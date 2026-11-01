(ns web.http.server
  "Enhanced JDK 25 HttpServer (port 80) and HttpsServer (port 443) wrapper.
   Uses Virtual Threads, provides polymorphic response bodies (nil, byte[], String, File, slice),
   handles ACME challenges + 308 redirects on port 80, and per-IP rate limiting,
   static content, and zero-downtime hot-reloadable TLS on port 443."
  (:require [clojure.string :as str]
            [web.http.content :as content]
            [web.http.ratelimit :as rl]
            [web.tls.context :as tls])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer HttpsExchange HttpsServer]
           [java.io File InputStream OutputStream RandomAccessFile]
           [java.net InetSocketAddress ServerSocket Socket SocketException]
           [java.nio ByteBuffer]
           [java.nio.charset StandardCharsets]
           [java.text SimpleDateFormat]
           [java.util Date]
           [java.util.concurrent Executors]
           [java.util.concurrent.atomic AtomicInteger]))

;; ---------------------------------------------------------------------------
;; Request & Response Conversion
;; ---------------------------------------------------------------------------

(defn exchange->request
  "Converts a com.sun.net.httpserver.HttpExchange into a Ring-like request map."
  ([^HttpExchange exchange]
   (exchange->request exchange nil))
  ([^HttpExchange exchange forwarded-ips-atom]
   (let [uri (.getRequestURI exchange)
         path (.getPath uri)
         query (.getRawQuery uri)
         scheme (if (instance? HttpsExchange exchange) "https" "http")
         method (keyword (str/upper-case (.getRequestMethod exchange)))
         remote-addr (.getRemoteAddress exchange)
         forwarded-ip (when (and remote-addr forwarded-ips-atom)
                        (get @forwarded-ips-atom (.getPort remote-addr)))
         remote-ip (or forwarded-ip
                       (if remote-addr
                         (.getHostAddress (.getAddress remote-addr))
                         "127.0.0.1"))
         headers-raw (.getRequestHeaders exchange)
         headers (into {}
                       (map (fn [[k v]]
                              [(keyword "header" (str/lower-case k)) (vec v)]))
                       headers-raw)
         host-hdr (first (get headers :header/host))
         host (if host-hdr (first (str/split host-hdr #":")) "localhost")
         params (when (and query (not (str/blank? query)))
                  (into {}
                        (keep (fn [pair]
                                (let [[k v] (str/split pair #"=" 2)]
                                  (when (and k (not (str/blank? k)))
                                    [(java.net.URLDecoder/decode k StandardCharsets/UTF_8)
                                     (if v (java.net.URLDecoder/decode v StandardCharsets/UTF_8) "")]))))
                        (str/split query #"&")))]
     {:request/method method
      :request/uri {:scheme scheme
                    :host host
                    :path path
                    :query query}
      :request/params (or params {})
      :request/headers headers
      :request/remote-ip remote-ip
      :request/exchange exchange})))

(defn send-response
  "Sends response through HttpExchange with support for polymorphic body types:
   nil (empty body / HEAD / 304 / 308), byte[], String, File, or {:file f :offset off :length len}."
  [^HttpExchange exchange response]
  (let [status (int (or (:response/status response)
                        (get-in response [:response/headers :status])
                        200))
        headers (or (:response/headers response) {})
        resp-headers (.getResponseHeaders exchange)]
    ;; Set response headers
    (doseq [[k v] headers]
      (when (and k (not= k :status) v)
        (.set resp-headers (name k) (str v))))
    (let [body (:response/body response)]
      (cond
        ;; Empty body or 304 / 204
        (or (nil? body) (= status 304) (= status 204))
        (do
          (.sendResponseHeaders exchange status -1)
          (.close exchange))

        ;; Byte array
        (bytes? body)
        (let [len (alength ^bytes body)]
          (.sendResponseHeaders exchange status len)
          (with-open [os (.getResponseBody exchange)]
            (.write os ^bytes body 0 len)
            (.flush os)))

        ;; String
        (string? body)
        (let [bs (.getBytes ^String body StandardCharsets/UTF_8)
              len (alength bs)]
          (.sendResponseHeaders exchange status len)
          (with-open [os (.getResponseBody exchange)]
            (.write os bs 0 len)
            (.flush os)))

        ;; File (full)
        (instance? File body)
        (let [len (.length ^File body)]
          (.sendResponseHeaders exchange status len)
          (with-open [raf (RandomAccessFile. ^File body "r")
                      os (.getResponseBody exchange)]
            (let [fc (.getChannel raf)
                  buf (ByteBuffer/allocate 65536)]
              (loop []
                (let [n (.read fc buf)]
                  (when (pos? n)
                    (.flip buf)
                    (.write os (.array buf) 0 n)
                    (.clear buf)
                    (recur))))
              (.flush os))))

        ;; File slice map: {:file ^File f :offset start :length len}
        (and (map? body) (:file body))
        (let [^File file (:file body)
              offset (long (or (:offset body) 0))
              len (long (or (:length body) (- (.length file) offset)))]
          (.sendResponseHeaders exchange status len)
          (with-open [raf (RandomAccessFile. file "r")
                      os (.getResponseBody exchange)]
            (.seek raf offset)
            (let [fc (.getChannel raf)
                  buf (ByteBuffer/allocate 65536)]
              (loop [remaining len]
                (when (pos? remaining)
                  (let [to-read (int (min remaining 65536))]
                    (.limit buf to-read)
                    (let [n (.read fc buf)]
                      (when (pos? n)
                        (.flip buf)
                        (.write os (.array buf) 0 n)
                        (.clear buf)
                        (recur (- remaining n)))))))
              (.flush os))))

        :else
        (do
          (.sendResponseHeaders exchange status -1)
          (.close exchange))))))

;; ---------------------------------------------------------------------------
;; Handlers: Port 80 (HTTP) & Port 443 (HTTPS)
;; ---------------------------------------------------------------------------

(defn- render-statusz
  [limiter-atom cluster-state-atom now-ms]
  (let [sdf (SimpleDateFormat. "yyyy-MM")
        month-key (.format sdf (Date. (long now-ms)))
        egress-bytes (long (if (and limiter-atom (instance? clojure.lang.IDeref limiter-atom))
                             (get-in @limiter-atom [:egress-by-month month-key] 0)
                             0))
        st (when (and cluster-state-atom (instance? clojure.lang.IDeref cluster-state-atom))
             @cluster-state-atom)
        role (:role st)
        leader-id (:leader-id st)
        healthy-count (if st (count (:healthy-nodes st)) 1)
        total-count (if st (count (:all-nodes st)) 1)
        peers (when st (filter :last-seen-ms (vals (:peers st))))
        max-hb-age-ms (if (seq peers)
                        (reduce max 0 (map (fn [p] (max 0 (- (long now-ms) (long (:last-seen-ms p))))) peers))
                        0)]
    (format "role=%s leader=%s quorum=%d/%d hb_ms=%d egress_bytes=%d\n"
            (name (or role :standalone))
            (name (or leader-id :none))
            healthy-count
            total-count
            max-hb-age-ms
            egress-bytes)))

(defn- make-http-port-80-handler
  [_config acme-challenges-atom https-port limiter-atom cluster-state-atom]
  (reify HttpHandler
    (handle [_ exchange]
      (let [req (exchange->request exchange)
            path (get-in req [:request/uri :path])
            method (:request/method req)]
        (cond
          ;; 1. ACME challenge validation
          (and (or (= method :GET) (= method :HEAD))
               (str/starts-with? path "/.well-known/acme-challenge/"))
          (let [token (subs path (count "/.well-known/acme-challenge/"))
                challenges (if (instance? clojure.lang.IDeref acme-challenges-atom)
                             @acme-challenges-atom
                             acme-challenges-atom)
                key-auth (get challenges token)]
            (println (str "[HTTP] ACME challenge " (name method) " " path " -> " (if key-auth 200 404) " [" (:request/remote-ip req) "]"))
            (if key-auth
              (send-response exchange
                             {:response/status 200
                              :response/headers {"Content-Type" "application/octet-stream"}
                              :response/body (if (= method :HEAD) nil key-auth)})
              (send-response exchange
                             {:response/status 404
                              :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                              :response/body "Not Found\n"})))

          ;; 2. Health check
          (and (or (= method :GET) (= method :HEAD))
               (= path "/healthz"))
          (send-response exchange
                         {:response/status 200
                          :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                          :response/body (if (= method :HEAD) nil "ok\n")})

          ;; 3. Status check
          (and (or (= method :GET) (= method :HEAD))
               (= path "/statusz")
               (#{"127.0.0.1" "::1" "0:0:0:0:0:0:0:1"} (:request/remote-ip req)))
          (let [body (render-statusz limiter-atom cluster-state-atom (System/currentTimeMillis))]
            (send-response exchange
                           {:response/status 200
                            :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                            :response/body (if (= method :HEAD) nil body)}))

          ;; 4. 308 Permanent Redirect to HTTPS
          :else
          (let [host (get-in req [:request/uri :host] "localhost")
                port-suffix (if (and https-port (not= https-port 443)) (str ":" https-port) "")
                query (get-in req [:request/uri :query])
                query-suffix (if (seq query) (str "?" query) "")
                location (str "https://" host port-suffix path query-suffix)]
            (send-response exchange
                           {:response/status 308
                            :response/headers {"Location" location
                                               "Connection" "close"}
                            :response/body nil})))))))

(defn- make-https-port-443-handler
  ([config cache-atom limiter-atom]
   (make-https-port-443-handler config cache-atom limiter-atom nil))
  ([config cache-atom limiter-atom forwarded-ips-atom]
   (reify HttpHandler
     (handle [_ exchange]
       (let [req (exchange->request exchange forwarded-ips-atom)
             path (get-in req [:request/uri :path])
             method (:request/method req)
             remote-ip (:request/remote-ip req)
             subnet-key (rl/ip->subnet-key remote-ip)
             now-ms (System/currentTimeMillis)]
         (cond
          ;; Health check (bypasses rate limit)
           (and (or (= method :GET) (= method :HEAD))
                (= path "/healthz"))
           (send-response exchange
                          {:response/status 200
                           :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                           :response/body (if (= method :HEAD) nil "ok\n")})

           :else
          ;; Rate limit check
           (let [swapped-state (swap! limiter-atom
                                      (fn [st]
                                        (let [res (rl/check-and-consume st subnet-key 1.0 now-ms)]
                                          (with-meta (:state res) (dissoc res :state)))))
                 meta-res (meta swapped-state)
                 allowed? (:allowed? meta-res)
                 retry-after-ms (:retry-after-ms meta-res)]
             (if-not allowed?
               (let [retry-secs (max 1 (long (Math/ceil (/ (long (or retry-after-ms 0)) 1000.0))))]
                 (send-response exchange
                                {:response/status 429
                                 :response/headers {"Retry-After" (str retry-secs)
                                                    "Content-Type" "text/plain; charset=utf-8"}
                                 :response/body "Too Many Requests\n"}))

              ;; Egress budget and static content serving
               (let [resp (content/serve-static-request config cache-atom req)
                     hsts-resp (update resp :response/headers assoc
                                       "Strict-Transport-Security" "max-age=31536000; includeSubDomains")
                     body (:response/body hsts-resp)
                     body-len (cond
                                (bytes? body) (alength ^bytes body)
                                (string? body) (alength (.getBytes ^String body StandardCharsets/UTF_8))
                                (map? body) (or (:length body) 0)
                                (instance? File body) (.length ^File body)
                                :else 0)]
                 (println (str "[HTTPS] " (name method) " " path " -> " (:response/status hsts-resp) " (" body-len "B) [" remote-ip "]"))
                ;; Record egress bytes and check monthly egress limit
                 (if (pos? body-len)
                   (let [sdf (SimpleDateFormat. "yyyy-MM")
                         month-key (.format sdf (Date. now-ms))
                         swapped-egress (swap! limiter-atom
                                               (fn [st]
                                                 (let [res (rl/record-egress st body-len month-key)]
                                                   (with-meta (:state res) (dissoc res :state)))))
                         egress-allowed? (:allowed? (meta swapped-egress))]
                     (if-not egress-allowed?
                       (send-response exchange
                                      {:response/status 429
                                       :response/headers {"Content-Type" "text/plain; charset=utf-8"
                                                          "Retry-After" "3600"}
                                       :response/body "Monthly egress limit exceeded\n"})
                       (send-response exchange hsts-resp)))
                   (send-response exchange hsts-resp)))))))))))

;; ---------------------------------------------------------------------------
;; TLS SNI Extraction & Ingress Stream Classification (Pure Sans-IO)
;; ---------------------------------------------------------------------------

(defn- u8
  "Reads unsigned byte at idx from byte array."
  [^bytes buf ^long idx]
  (bit-and (long (aget buf idx)) 0xFF))

(defn- u16
  "Reads unsigned 16-bit big-endian integer at idx from byte array."
  [^bytes buf ^long idx]
  (bit-or (bit-shift-left (u8 buf idx) 8)
          (u8 buf (inc idx))))

(defn extract-tls-sni
  "Pure function. Safely extracts the Server Name Indication (SNI) host_name
   from a TLS ClientHello byte buffer if present. Returns lowercase hostname
   string or nil if not present, malformed, or truncated."
  [^bytes buf ^long len]
  (try
    (when (and buf (>= len 44)
               (= (u8 buf 0) 0x16)     ;; Handshake record
               (= (u8 buf 1) 0x03)     ;; TLS major version 3
               (= (u8 buf 5) 0x01))    ;; ClientHello
      (let [sid-len (u8 buf 43)
            cs-offset (+ 44 sid-len)]
        (when (<= (+ cs-offset 2) len)
          (let [cs-len (u16 buf cs-offset)
                comp-offset (+ cs-offset 2 cs-len)]
            (when (<= (+ comp-offset 1) len)
              (let [comp-len (u8 buf comp-offset)
                    exts-offset (+ comp-offset 1 comp-len)]
                (when (<= (+ exts-offset 2) len)
                  (let [exts-len (u16 buf exts-offset)
                        exts-end (min len (+ exts-offset 2 exts-len))]
                    (loop [curr (+ exts-offset 2)]
                      (when (<= (+ curr 4) exts-end)
                        (let [ext-type (u16 buf curr)
                              ext-len (u16 buf (+ curr 2))
                              ext-data-start (+ curr 4)
                              ext-data-end (+ ext-data-start ext-len)]
                          (if (zero? ext-type) ;; SNI extension (0x0000)
                            (when (<= (+ ext-data-start 5) (min len ext-data-end))
                              (let [name-type (u8 buf (+ ext-data-start 2))]
                                (when (zero? name-type) ;; host_name
                                  (let [name-len (u16 buf (+ ext-data-start 3))
                                        name-start (+ ext-data-start 5)]
                                    (when (<= (+ name-start name-len) (min len ext-data-end))
                                      (str/lower-case (String. buf (int name-start) (int name-len) StandardCharsets/UTF_8)))))))
                            (recur ext-data-end)))))))))))))
    (catch Exception _ nil)))

(defn ingress-stream?
  "Pure function. Determines if an incoming byte buffer at port 443
   is an ingress stream (WebRTC RFC 4571 DTLS, RFC 4571 STUN, or TLS SNI
   matching ingress.<domain> / *.ingress.<domain>).
   Returns boolean."
  [^bytes buf ^long len domain]
  (try
    (cond
      (or (nil? buf) (< len 4))
      false

      ;; RFC 4571 DTLS: 2-byte frame length, ContentType 0x16 (22), DTLS major version 0xFE (254)
      (and (>= len 4)
           (= (u8 buf 2) 0x16)
           (= (u8 buf 3) 0xFE))
      true

      ;; RFC 4571 STUN: 2-byte frame length, STUN Binding Request 0x00 0x01, Magic Cookie 0x2112A442
      (and (>= len 10)
           (= (u8 buf 2) 0x00)
           (= (u8 buf 3) 0x01)
           (= (u8 buf 6) 0x21)
           (= (u8 buf 7) 0x12)
           (= (u8 buf 8) 0xA4)
           (= (u8 buf 9) 0x42))
      true

      ;; TLS ClientHello with SNI matching ingress
      (and (>= len 5)
           (= (u8 buf 0) 0x16)
           (= (u8 buf 1) 0x03)
           (<= 0 (u8 buf 2) 4))
      (if-let [sni (extract-tls-sni buf len)]
        (let [clean-domain (when domain (str/lower-case (str/trim domain)))]
          (boolean
           (or (= sni "ingress")
               (str/ends-with? sni ".ingress")
               (when (seq clean-domain)
                 (or (= sni (str "ingress." clean-domain))
                     (str/ends-with? sni (str ".ingress." clean-domain)))))))
        false)

      :else
      false)
    (catch Exception _ false)))

;; ---------------------------------------------------------------------------
;; Live Passthrough Multiplexing Boundary
;; ---------------------------------------------------------------------------

(defn- pipe-stream!
  "Pipes bytes from InputStream to OutputStream on current virtual thread.
   Half-closes destination output on EOF and closes both sockets once both directions finish."
  [^InputStream in ^OutputStream out ^Socket dst-sock ^Socket other-sock cleanup-fn]
  (try
    (.transferTo in out)
    (.flush out)
    (try (.shutdownOutput dst-sock) (catch Exception _ nil))
    (catch Exception _
      (try (.close dst-sock) (catch Exception _ nil))
      (try (.close other-sock) (catch Exception _ nil)))
    (finally
      (cleanup-fn))))

(defn- peek-initial-bytes
  "Reads initial bytes from client socket up to 1024 bytes.
   If TLS record header is detected, attempts to read full ClientHello up to 1024 bytes.
   Returns [buf n]."
  [^Socket client-sock]
  (.setSoTimeout client-sock 5000)
  (let [in (.getInputStream client-sock)
        buf (byte-array 1024)
        n0 (.read in buf 0 1024)]
    (if (pos? n0)
      (let [needed (if (and (>= n0 5) (= (u8 buf 0) 0x16) (= (u8 buf 1) 0x03))
                     (min 1024 (+ 5 (u16 buf 3)))
                     n0)]
        (loop [curr n0]
          (if (and (< curr needed) (.isConnected client-sock) (not (.isClosed client-sock)))
            (let [r (.read in buf curr (- needed curr))]
              (if (pos? r)
                (recur (+ curr r))
                [buf curr]))
            [buf curr])))
      [buf 0])))

(defn- handle-passthrough-connection!
  "Inspects incoming client socket at port 443 and splices to either
   ingress-target or internal HttpsServer based on ingress-stream? classification."
  [^Socket client-sock passthrough-ctx]
  (let [{:keys [domain internal-https-port ingress-target forwarded-ips-atom ^java.util.concurrent.ExecutorService vthread-executor]} passthrough-ctx]
    (try
      (let [[buf n] (peek-initial-bytes client-sock)]
        (.setSoTimeout client-sock 0)
        (if (pos? n)
          (let [ingress? (ingress-stream? buf n domain)
                use-ingress? (and ingress? (some? ingress-target))
                target (if use-ingress?
                         ingress-target
                         {:host "127.0.0.1" :port internal-https-port})
                backend-sock (Socket. ^String (:host target) (int (:port target)))
                local-backend-port (.getLocalPort backend-sock)
                client-ip (when-let [addr (.getInetAddress client-sock)]
                            (.getHostAddress addr))]
            (.setTcpNoDelay client-sock true)
            (.setTcpNoDelay backend-sock true)
            (when (and (not use-ingress?) forwarded-ips-atom client-ip)
              (swap! forwarded-ips-atom assoc local-backend-port client-ip))
            (let [backend-out (.getOutputStream backend-sock)]
              (.write backend-out buf 0 n)
              (.flush backend-out))
            (let [client-in (.getInputStream client-sock)
                  client-out (.getOutputStream client-sock)
                  backend-in (.getInputStream backend-sock)
                  backend-out (.getOutputStream backend-sock)
                  rem-dirs (AtomicInteger. 2)
                  cleanup-fn (fn []
                               (when (zero? (.decrementAndGet rem-dirs))
                                 (when (and (not use-ingress?) forwarded-ips-atom)
                                   (swap! forwarded-ips-atom dissoc local-backend-port))
                                 (try (.close client-sock) (catch Exception _ nil))
                                 (try (.close backend-sock) (catch Exception _ nil))))]
              (.submit vthread-executor ^Runnable (fn [] (pipe-stream! client-in backend-out backend-sock client-sock cleanup-fn)))
              (.submit vthread-executor ^Runnable (fn [] (pipe-stream! backend-in client-out client-sock backend-sock cleanup-fn)))))
          (try (.close client-sock) (catch Exception _ nil))))
      (catch Exception _
        (try (.close client-sock) (catch Exception _ nil))))))

;; ---------------------------------------------------------------------------
;; Server Lifecycle
;; ---------------------------------------------------------------------------

(defn start-http-servers!
  "Starts JDK 25 virtual-thread HttpServer (port 80), internal HttpsServer, and
   port 443 TCP passthrough multiplexer.
   Returns a map with :http-server, :https-server, :front-door-sock, :http-port,
   :https-port, :cache-atom, :limiter-atom, and :stop-fn."
  ([config tls-manager acme-challenges-atom]
   (start-http-servers! config tls-manager acme-challenges-atom nil))
  ([config tls-manager acme-challenges-atom cluster-state-atom]
   (let [bind-ip (get-in config [:http :bind-ip] "0.0.0.0")
         http-port (int (get-in config [:http :http-port] 80))
         https-port (int (get-in config [:http :https-port] 443))
         domain (:domain config)
         ingress-target (get-in config [:http :ingress-target])
         vthread-executor (Executors/newVirtualThreadPerTaskExecutor)
         forwarded-ips-atom (atom {})
         cache-atom (atom (content/init-content-cache
                           {:max-bytes (get-in config [:http :cache-max-bytes] 134217728)
                            :max-file-bytes (get-in config [:http :cache-max-file-bytes] 2097152)}))
         limiter-atom (atom (rl/init-limiter
                             {:capacity 100.0
                              :refill-per-sec 20.0
                              :monthly-egress-limit-bytes (get-in config [:http :monthly-egress-limit-bytes] 900000000)}))

         ;; 1. Start internal HTTPS server on 127.0.0.1 (ephemeral port 0)
         https-server (HttpsServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
         _ (.setHttpsConfigurator https-server (tls/make-https-configurator (:ssl-context-atom tls-manager)))
         _ (.setExecutor https-server vthread-executor)
         _ (.createContext https-server "/" (make-https-port-443-handler config cache-atom limiter-atom forwarded-ips-atom))
         _ (.start https-server)
         internal-https-port (.getPort (.getAddress https-server))
         passthrough-ctx {:domain domain
                          :internal-https-port internal-https-port
                          :ingress-target ingress-target
                          :forwarded-ips-atom forwarded-ips-atom
                          :vthread-executor vthread-executor}

         ;; 2. Start front-door port 443 ServerSocket
         front-door-sock (doto (ServerSocket.)
                           (.setReuseAddress true)
                           (.bind (InetSocketAddress. ^String bind-ip https-port)))
         bound-https-port (.getLocalPort front-door-sock)

         ;; 3. Run front-door accept loop on virtual thread
         _ (.submit vthread-executor
                    ^Runnable
                    (fn []
                      (try
                        (while (not (.isClosed front-door-sock))
                          (let [client (.accept front-door-sock)]
                            (.submit vthread-executor
                                     ^Runnable
                                     (fn []
                                       (handle-passthrough-connection! client passthrough-ctx)))))
                        (catch SocketException _ nil)
                        (catch Exception _ nil))))

         ;; 4. Start HTTP server (port 80 / ephemeral)
         http-server (HttpServer/create (InetSocketAddress. ^String bind-ip http-port) 0)
         _ (.setExecutor http-server vthread-executor)
         _ (.createContext http-server "/" (make-http-port-80-handler config acme-challenges-atom bound-https-port limiter-atom cluster-state-atom))
         _ (.start http-server)
         bound-http-port (.getPort (.getAddress http-server))

         stop-fn (fn []
                   (try (.close front-door-sock) (catch Exception _ nil))
                   (try (.stop http-server 0) (catch Exception _ nil))
                   (try (.stop https-server 0) (catch Exception _ nil))
                   (try (.shutdownNow vthread-executor) (catch Exception _ nil)))]
     {:http-server http-server
      :https-server https-server
      :front-door-sock front-door-sock
      :http-port bound-http-port
      :https-port bound-https-port
      :cache-atom cache-atom
      :limiter-atom limiter-atom
      :stop-fn stop-fn})))

(defn stop-http-servers!
  "Stops HTTP and HTTPS servers cleanly."
  [servers]
  (when-let [stop-fn (:stop-fn servers)]
    (stop-fn))
  servers)
