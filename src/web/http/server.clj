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
           [java.io File RandomAccessFile]
           [java.net InetSocketAddress]
           [java.nio ByteBuffer]
           [java.nio.charset StandardCharsets]
           [java.text SimpleDateFormat]
           [java.util Date]
           [java.util.concurrent Executors]))

;; ---------------------------------------------------------------------------
;; Request & Response Conversion
;; ---------------------------------------------------------------------------

(defn exchange->request
  "Converts a com.sun.net.httpserver.HttpExchange into a Ring-like request map."
  [^HttpExchange exchange]
  (let [uri (.getRequestURI exchange)
        path (.getPath uri)
        query (.getRawQuery uri)
        scheme (if (instance? HttpsExchange exchange) "https" "http")
        method (keyword (str/upper-case (.getRequestMethod exchange)))
        remote-addr (.getRemoteAddress exchange)
        remote-ip (if remote-addr
                    (.getHostAddress (.getAddress remote-addr))
                    "127.0.0.1")
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
     :request/exchange exchange}))

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
  [config cache-atom limiter-atom]
  (reify HttpHandler
    (handle [_ exchange]
      (let [req (exchange->request exchange)
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
                  (send-response exchange hsts-resp))))))))))

;; ---------------------------------------------------------------------------
;; Server Lifecycle
;; ---------------------------------------------------------------------------

(defn start-http-servers!
  "Starts JDK 25 virtual-thread HttpServer (port 80) and HttpsServer (port 443).
   Returns a map with :http-server, :https-server, :http-port, :https-port,
   :cache-atom, :limiter-atom, and :stop-fn."
  ([config tls-manager acme-challenges-atom]
   (start-http-servers! config tls-manager acme-challenges-atom nil))
  ([config tls-manager acme-challenges-atom cluster-state-atom]
   (let [bind-ip (get-in config [:http :bind-ip] "0.0.0.0")
         http-port (int (get-in config [:http :http-port] 80))
         https-port (int (get-in config [:http :https-port] 443))
         vthread-executor (Executors/newVirtualThreadPerTaskExecutor)
         cache-atom (atom (content/init-content-cache
                           {:max-bytes (get-in config [:http :cache-max-bytes] 134217728)
                            :max-file-bytes (get-in config [:http :cache-max-file-bytes] 2097152)}))
         limiter-atom (atom (rl/init-limiter
                             {:capacity 100.0
                              :refill-per-sec 20.0
                              :monthly-egress-limit-bytes (get-in config [:http :monthly-egress-limit-bytes] 900000000)}))

         ;; 1. Start HTTPS server first so port 80 can redirect to HTTPS port if ephemeral
         https-server (HttpsServer/create (InetSocketAddress. ^String bind-ip https-port) 0)
         _ (.setHttpsConfigurator https-server (tls/make-https-configurator (:ssl-context-atom tls-manager)))
         _ (.setExecutor https-server vthread-executor)
         _ (.createContext https-server "/" (make-https-port-443-handler config cache-atom limiter-atom))
         _ (.start https-server)
         bound-https-port (.getPort (.getAddress https-server))

         ;; 2. Start HTTP server (port 80 / ephemeral)
         http-server (HttpServer/create (InetSocketAddress. ^String bind-ip http-port) 0)
         _ (.setExecutor http-server vthread-executor)
         _ (.createContext http-server "/" (make-http-port-80-handler config acme-challenges-atom bound-https-port limiter-atom cluster-state-atom))
         _ (.start http-server)
         bound-http-port (.getPort (.getAddress http-server))

         stop-fn (fn []
                   (try (.stop http-server 0) (catch Exception _ nil))
                   (try (.stop https-server 0) (catch Exception _ nil))
                   (try (.shutdownNow vthread-executor) (catch Exception _ nil)))]
     {:http-server http-server
      :https-server https-server
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
