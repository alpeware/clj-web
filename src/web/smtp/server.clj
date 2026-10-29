(ns web.smtp.server
  "Inbound SMTP server on TCP port 25 with STARTTLS socket upgrade,
   30-second read timeouts, max 10 concurrent sessions, per-IP rate limiting,
   atomic .eml persistence to <state-dir>/mail/, and cluster replication hooks."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [web.http.ratelimit :as rl]
            [web.smtp.session :as session])
  (:import [java.io BufferedReader BufferedWriter File InputStreamReader OutputStreamWriter]
           [java.net InetSocketAddress ServerSocket Socket SocketTimeoutException]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files StandardCopyOption]
           [java.security MessageDigest]
           [java.text SimpleDateFormat]
           [java.util Date Locale UUID]
           [java.util.concurrent Executors Semaphore]
           [java.util.concurrent.atomic AtomicBoolean]
           [javax.net.ssl SSLContext SSLSocket]))

;; ---------------------------------------------------------------------------
;; Storage & Persistence
;; ---------------------------------------------------------------------------

(defn- sha256-hex [^bytes bs]
  (let [md (MessageDigest/getInstance "SHA-256")
        digest (.digest md bs)]
    (apply str (map #(format "%02x" (bit-and % 0xFF)) digest))))

(defn save-eml!
  "Atomically persists an incoming email as an RFC 822/2822 .eml file in <state-dir>/mail/.
   Prepends standard Received: trace header if not already present.
   Returns a map with :id, :file, :raw-eml, :from, :to, :helo, :remote-ip, and :received-at."
  [state-dir mail-info]
  (let [id (or (:id mail-info) (str (UUID/randomUUID)))
        received-at (long (or (:received-at mail-info) (System/currentTimeMillis)))
        domain (or (:domain mail-info) "localhost")
        remote-ip (or (:remote-ip mail-info) "127.0.0.1")
        helo (or (:helo mail-info) "unknown")
        raw (or (:raw-eml mail-info) "")
        raw-bytes (.getBytes ^String raw StandardCharsets/UTF_8)
        sha-prefix (subs (sha256-hex raw-bytes) 0 8)
        mail-dir (io/file state-dir "mail")
        _ (.mkdirs mail-dir)
        filename (str received-at "-" sha-prefix ".eml")
        dest-file (io/file mail-dir filename)
        sdf (SimpleDateFormat. "EEE, d MMM yyyy HH:mm:ss Z" Locale/US)
        date-str (.format sdf (Date. received-at))
        received-hdr (str "Received: from " helo " ([" remote-ip "])\r\n"
                          "        by " domain " with ESMTP\r\n"
                          "        id " id "; " date-str "\r\n")
        full-eml (if (str/starts-with? (str/trim raw) "Received:")
                   raw
                   (str received-hdr raw))
        tmp-file (File/createTempFile "mail" ".tmp" mail-dir)]
    (spit tmp-file full-eml)
    (try
      (Files/move (.toPath tmp-file) (.toPath dest-file)
                  (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                        StandardCopyOption/REPLACE_EXISTING]))
      (catch Exception _
        (Files/move (.toPath tmp-file) (.toPath dest-file)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
    {:id id
     :file dest-file
     :raw-eml full-eml
     :from (:from mail-info)
     :to (:to mail-info)
     :helo helo
     :remote-ip remote-ip
     :received-at received-at}))

(defn list-emails
  "Lists saved .eml files in <state-dir>/mail/ sorted by filename (chronological order).
   Returns a vector of maps with :file, :name, :size, and :modified."
  [state-dir]
  (let [mail-dir (io/file state-dir "mail")]
    (if-not (.exists mail-dir)
      []
      (->> (.listFiles mail-dir)
           (filter (fn [^File f] (and (.isFile f) (str/ends-with? (.getName f) ".eml"))))
           (sort-by (fn [^File f] (.getName f)))
           (map (fn [^File f]
                  {:file f
                   :name (.getName f)
                   :size (.length f)
                   :modified (.lastModified f)}))
           vec))))

;; ---------------------------------------------------------------------------
;; Connection Handling
;; ---------------------------------------------------------------------------

(defn read-bounded-line
  "Reads a single line terminated by \n or \r\n up to max-line-chars characters.
   Returns the line string without trailing \r or \n, or nil on EOF if no characters read.
   Throws ex-info if line exceeds max-line-chars without encountering a newline."
  ([^BufferedReader reader]
   (read-bounded-line reader 4096))
  ([^BufferedReader reader max-line-chars]
   (let [sb (StringBuilder.)
         limit (long (or max-line-chars 4096))]
     (loop []
       (let [ch (.read reader)]
         (cond
           (= ch -1)
           (if (pos? (.length sb))
             (.toString sb)
             nil)

           (= ch (int \newline))
           (let [s (.toString sb)]
             (if (str/ends-with? s "\r")
               (subs s 0 (dec (count s)))
               s))

           (>= (.length sb) limit)
           (throw (ex-info (str "SMTP line length limit exceeded (max " limit " chars)")
                           {:type :smtp/line-too-long :limit limit}))

           :else
           (do
             (.append sb (char ch))
             (recur))))))))

(defn- run-session-loop!
  [^Socket initial-socket config tls-manager opts sock-timeout]
  (let [domain (get config :domain "localhost")
        state-dir (get config :state-dir "/var/lib/clj-web")
        smtp-cfg (get config :smtp {})
        max-bytes (long (get smtp-cfg :max-message-bytes 131072))
        allowed (get smtp-cfg :allowed-recipients #{})
        remote-addr (.getInetAddress initial-socket)
        remote-ip (if remote-addr (.getHostAddress remote-addr) "127.0.0.1")
        init-in (BufferedReader. (InputStreamReader. (.getInputStream initial-socket) StandardCharsets/UTF_8))
        init-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream initial-socket) StandardCharsets/UTF_8))
        init-st (let [s (session/init-session {:domain domain
                                               :max-message-bytes max-bytes
                                               :allowed-recipients allowed
                                               :tls-active? (instance? SSLSocket initial-socket)})
                      greet (session/greeting s)]
                  (doseq [resp (:responses greet)]
                    (.write init-out (str resp "\r\n")))
                  (.flush init-out)
                  (:state greet))]
    (loop [current-socket initial-socket
           in init-in
           out init-out
           session-st init-st]
      (let [line (try
                   (read-bounded-line in 4096)
                   (catch SocketTimeoutException _ nil)
                   (catch Exception _ nil))]
        (if (nil? line)
          ;; EOF or read timeout: close connection
          nil
          (let [result (session/handle-smtp-line session-st line)
                new-state (:state result)
                responses (:responses result)
                effects (:effects result)]
            ;; Send responses
            (doseq [resp responses]
              (.write out (str resp "\r\n")))
            (.flush out)

            ;; Handle effects
            (let [starttls-effect (first (filter #(= (:type %) :starttls) effects))
                  close-effect (first (filter #(= (:type %) :close) effects))
                  deliver-effect (first (filter #(= (:type %) :deliver-mail) effects))]

              ;; Deliver mail effect
              (when deliver-effect
                (let [mail-info {:id (str (UUID/randomUUID))
                                 :from (:from deliver-effect)
                                 :to (:to deliver-effect)
                                 :helo (:helo deliver-effect)
                                 :remote-ip remote-ip
                                 :raw-eml (:data-str deliver-effect)
                                 :received-at (System/currentTimeMillis)
                                 :domain domain}
                      saved (save-eml! state-dir mail-info)]
                  (when-let [on-recv (:on-mail-received opts)]
                    (try (on-recv saved) (catch Exception _ nil)))))

              (cond
                ;; QUIT / Close
                close-effect
                nil

                ;; STARTTLS socket upgrade
                starttls-effect
                (let [ssl-ctx @(:ssl-context-atom tls-manager)
                      factory (.getSocketFactory ^SSLContext ssl-ctx)
                      ssl-socket (.createSocket factory
                                                current-socket
                                                remote-ip
                                                (.getPort current-socket)
                                                true)]
                  (.setUseClientMode ssl-socket false)
                  (.setEnabledProtocols ssl-socket (into-array String ["TLSv1.3" "TLSv1.2"]))
                  (.setSoTimeout ssl-socket sock-timeout)
                  (.startHandshake ssl-socket)
                  (let [new-in (BufferedReader. (InputStreamReader. (.getInputStream ssl-socket) StandardCharsets/UTF_8))
                        new-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream ssl-socket) StandardCharsets/UTF_8))]
                    (recur ssl-socket new-in new-out new-state)))

                ;; Normal command or data line: continue loop
                :else
                (recur current-socket in out new-state)))))))))

(defn- handle-client-connection!
  ([^Socket client-socket config tls-manager opts semaphore limiter-atom sock-timeout]
   (handle-client-connection! client-socket config tls-manager opts semaphore limiter-atom sock-timeout nil))
  ([^Socket client-socket config tls-manager opts semaphore limiter-atom sock-timeout running?]
   (try
     (.setSoTimeout client-socket sock-timeout)
     (if-not (.tryAcquire ^Semaphore semaphore)
       ;; Max concurrent sessions exceeded
       (with-open [w (BufferedWriter. (OutputStreamWriter. (.getOutputStream client-socket) StandardCharsets/UTF_8))]
         (.write w "421 4.3.2 Server too busy, try again later\r\n")
         (.flush w))
       (try
         (let [remote-addr (.getInetAddress client-socket)
               remote-ip (if remote-addr (.getHostAddress remote-addr) "127.0.0.1")
               subnet-key (rl/ip->subnet-key remote-ip)
               now-ms (System/currentTimeMillis)
               swapped-st (swap! limiter-atom
                                 (fn [st]
                                   (let [res (rl/check-and-consume st subnet-key 1.0 now-ms)]
                                     (with-meta (:state res) (dissoc res :state)))))
               allowed? (:allowed? (meta swapped-st))]
           (if-not allowed?
             (with-open [w (BufferedWriter. (OutputStreamWriter. (.getOutputStream client-socket) StandardCharsets/UTF_8))]
               (.write w "421 4.7.0 Too many connections from your IP\r\n")
               (.flush w))
             (run-session-loop! client-socket config tls-manager opts sock-timeout)))
         (finally
           (.release ^Semaphore semaphore))))
     (catch Exception e
       (when (or (nil? running?) (.get ^AtomicBoolean running?))
         (binding [*out* *err*]
           (println (str "Unexpected error in SMTP client connection: " (.getMessage e))))))
     (finally
       (try (.close client-socket) (catch Exception _ nil))))))

;; ---------------------------------------------------------------------------
;; Server Lifecycle
;; ---------------------------------------------------------------------------

(defn start-smtp-server!
  "Starts a Virtual-Thread TCP SMTP server on configured bind-ip and port.
   Supports STARTTLS upgrades using tls-manager, 30s socket timeouts,
   atomic .eml persistence, and cluster replication via (:on-mail-received opts).
   Returns a server map with :server-socket, :port, :running?, and :stop-fn."
  ([config tls-manager]
   (start-smtp-server! config tls-manager {}))
  ([config tls-manager opts]
   (let [smtp-cfg (get config :smtp {})
         bind-ip (get smtp-cfg :bind-ip "0.0.0.0")
         port (int (get smtp-cfg :port 25))
         sock-timeout (int (get smtp-cfg :socket-timeout-ms 30000))
         vthread-executor (Executors/newVirtualThreadPerTaskExecutor)
         semaphore (Semaphore. 10)
         limiter-atom (atom (rl/init-limiter {:capacity 20.0 :refill-per-sec 5.0}))
         server-socket (ServerSocket.)
         _ (.bind server-socket (InetSocketAddress. ^String bind-ip port))
         bound-port (.getLocalPort server-socket)
         running? (AtomicBoolean. true)
         stop-fn (fn []
                   (.set running? false)
                   (try (.close server-socket) (catch Exception _ nil))
                   (try (.shutdownNow vthread-executor) (catch Exception _ nil)))]
     ;; Background accept loop on virtual thread
     (.submit vthread-executor
              ^Runnable
              (fn []
                (while (.get running?)
                  (try
                    (let [client (.accept server-socket)]
                      (.submit vthread-executor
                               ^Runnable
                               (fn []
                                 (handle-client-connection! client config tls-manager opts semaphore limiter-atom sock-timeout running?))))
                    (catch Exception e
                      (when (.get running?)
                        (binding [*out* *err*]
                          (println (str "Unexpected error in SMTP accept loop: " (.getMessage e))))))))))
     {:server-socket server-socket
      :port bound-port
      :running? running?
      :stop-fn stop-fn})))

(defn stop-smtp-server!
  "Stops the SMTP server and virtual-thread executor cleanly."
  [server]
  (when-let [stop-fn (:stop-fn server)]
    (stop-fn))
  server)
