(ns web.http.server-test
  "Live integration tests for JDK 25 virtual-thread HttpServer (port 80) and
   HttpsServer (port 443), covering ACME challenges, 308 redirect, /healthz,
   static content delivery over HTTPS, rate limiting, and zero-downtime TLS hot-swap."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.http.server :as server]
            [web.tls.context :as tls])
  (:import [java.io File]
           [java.net ServerSocket Socket URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.nio ByteBuffer]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.security SecureRandom]
           [java.security.cert X509Certificate]
           [javax.net.ssl SSLContext SSLSocket TrustManager X509TrustManager]))

(defn- find-free-port []
  (with-open [s (ServerSocket. 0)]
    (.getLocalPort s)))

(defn- delete-dir-recursively! [^File f]
  (when (.isDirectory f)
    (doseq [child (.listFiles f)]
      (delete-dir-recursively! child)))
  (.delete f))

(defn- with-temp-env [f]
  (let [state-dir (.toFile (Files/createTempDirectory "clj-web-server-state" (into-array java.nio.file.attribute.FileAttribute [])))
        content-dir (.toFile (Files/createTempDirectory "clj-web-server-content" (into-array java.nio.file.attribute.FileAttribute [])))]
    (try
      (f state-dir content-dir)
      (finally
        (delete-dir-recursively! state-dir)
        (delete-dir-recursively! content-dir)))))

(def ^:private trust-all-managers
  (into-array TrustManager
              [(reify X509TrustManager
                 (getAcceptedIssuers [_] (into-array X509Certificate []))
                 (checkClientTrusted [_ _ _])
                 (checkServerTrusted [_ _ _]))]))

(defn- make-trusting-ssl-context []
  (doto (SSLContext/getInstance "TLS")
    (.init nil trust-all-managers (SecureRandom.))))

(defn- make-http-client []
  (-> (HttpClient/newBuilder)
      (.sslContext (make-trusting-ssl-context))
      (.version java.net.http.HttpClient$Version/HTTP_1_1)
      (.build)))

(defn- get-peer-cert [host port]
  (let [ctx (make-trusting-ssl-context)
        factory (.getSocketFactory ctx)]
    (with-open [^SSLSocket socket (.createSocket factory ^String host (int port))]
      (.startHandshake socket)
      (first (.getPeerCertificates (.getSession socket))))))

(deftest test-http-port-80-acme-and-redirect
  (with-temp-env
    (fn [^File state-dir ^File content-dir]
      (let [http-port (find-free-port)
            https-port (find-free-port)
            cfg {:state-dir (.getAbsolutePath state-dir)
                 :domain "server-test.domain.org"
                 :http {:bind-ip "127.0.0.1"
                        :http-port http-port
                        :https-port https-port
                        :content-root (.getAbsolutePath content-dir)}}
            tls-mgr (tls/init-tls-manager! cfg)
            acme-atom (atom {"test-token-123" "test-key-auth-xyz"})
            servers (server/start-http-servers! cfg tls-mgr acme-atom)
            client (make-http-client)]
        (try
          (testing "ACME challenge returns 200 OK with key-auth when token is present"
            (let [uri (URI/create (str "http://127.0.0.1:" http-port "/.well-known/acme-challenge/test-token-123"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (= "test-key-auth-xyz" (.body resp)))))

          (testing "ACME challenge returns 404 Not Found when token is missing"
            (let [uri (URI/create (str "http://127.0.0.1:" http-port "/.well-known/acme-challenge/unknown-token"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 404 (.statusCode resp)))))

          (testing "Health check /healthz returns 200 OK on HTTP port"
            (let [uri (URI/create (str "http://127.0.0.1:" http-port "/healthz"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (= "ok\n" (.body resp)))))

          (testing "Status check /statusz returns 200 OK on HTTP port for loopback"
            (let [uri (URI/create (str "http://127.0.0.1:" http-port "/statusz"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (.contains (.body resp) "role="))))

          (testing "General request returns 308 Permanent Redirect to HTTPS"
            (let [uri (URI/create (str "http://127.0.0.1:" http-port "/docs/api.html?sort=asc"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/discarding))
                  loc (first (.allValues (.headers resp) "Location"))]
              (is (= 308 (.statusCode resp)))
              (is (= (str "https://127.0.0.1:" https-port "/docs/api.html?sort=asc") loc))))

          (finally
            (server/stop-http-servers! servers)))))))

(deftest test-https-port-443-static-serving-and-hsts
  (with-temp-env
    (fn [^File state-dir ^File content-dir]
      (let [http-port (find-free-port)
            https-port (find-free-port)
            cfg {:state-dir (.getAbsolutePath state-dir)
                 :domain "https-test.domain.org"
                 :http {:bind-ip "127.0.0.1"
                        :http-port http-port
                        :https-port https-port
                        :content-root (.getAbsolutePath content-dir)}}
            tls-mgr (tls/init-tls-manager! cfg)
            acme-atom (atom {})
            servers (server/start-http-servers! cfg tls-mgr acme-atom)
            client (make-http-client)
            doc-file (io/file content-dir "asset.txt")
            content "HTTPS Static Asset Content Delivery with HSTS"]
        (spit doc-file content)
        (try
          (testing "Serves file over HTTPS with 200 OK and HSTS header"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/asset.txt"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))
                  hsts (first (.allValues (.headers resp) "Strict-Transport-Security"))]
              (is (= 200 (.statusCode resp)))
              (is (= content (.body resp)))
              (is (some? hsts))
              (is (.contains hsts "max-age=31536000"))))

          (testing "Health check /healthz on HTTPS returns 200 OK"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/healthz"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (= "ok\n" (.body resp)))))

          (testing "/statusz on HTTPS returns 404 Not Found"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/statusz"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 404 (.statusCode resp)))))

          (testing "Conditional request with matching ETag returns 304"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/asset.txt"))
                  req1 (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp1 (.send client req1 (HttpResponse$BodyHandlers/discarding))
                  etag (first (.allValues (.headers resp1) "ETag"))
                  req2 (-> (HttpRequest/newBuilder uri)
                           (.header "If-None-Match" etag)
                           (.GET)
                           (.build))
                  resp2 (.send client req2 (HttpResponse$BodyHandlers/discarding))]
              (is (some? etag))
              (is (= 304 (.statusCode resp2)))))

          (testing "Range request returns 206 Partial Content"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/asset.txt"))
                  req (-> (HttpRequest/newBuilder uri)
                          (.header "Range" "bytes=0-4")
                          (.GET)
                          (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 206 (.statusCode resp)))
              (is (= "HTTPS" (.body resp)))
              (is (.contains (first (.allValues (.headers resp) "Content-Range")) "bytes 0-4/"))))

          (finally
            (server/stop-http-servers! servers)))))))

(deftest test-https-rate-limiting
  (with-temp-env
    (fn [^File state-dir ^File content-dir]
      (let [http-port (find-free-port)
            https-port (find-free-port)
            cfg {:state-dir (.getAbsolutePath state-dir)
                 :domain "ratelimit-test.domain.org"
                 :http {:bind-ip "127.0.0.1"
                        :http-port http-port
                        :https-port https-port
                        :content-root (.getAbsolutePath content-dir)}}
            tls-mgr (tls/init-tls-manager! cfg)
            acme-atom (atom {})
            servers (server/start-http-servers! cfg tls-mgr acme-atom)
            client (make-http-client)
            doc-file (io/file content-dir "test.txt")]
        (spit doc-file "rate limit payload")
        ;; Artificially set capacity low on limiter-atom to trigger rate limiting
        (reset! (:limiter-atom servers)
                {:capacity 2.0
                 :refill-per-sec 0.1
                 :monthly-egress-limit-bytes 10000000
                 :buckets {"127.0.0.0/24" {:tokens 0.0 :last-refill-ms (System/currentTimeMillis)}}})
        (try
          (testing "Returns 429 Too Many Requests when bucket is depleted"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/test.txt"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 429 (.statusCode resp)))
              (is (some? (first (.allValues (.headers resp) "Retry-After"))))))

          (finally
            (server/stop-http-servers! servers)))))))

(deftest test-live-tls-hot-swap
  (with-temp-env
    (fn [^File state-dir ^File content-dir]
      (let [http-port (find-free-port)
            https-port (find-free-port)
            cfg {:state-dir (.getAbsolutePath state-dir)
                 :domain "initial.domain.org"
                 :http {:bind-ip "127.0.0.1"
                        :http-port http-port
                        :https-port https-port
                        :content-root (.getAbsolutePath content-dir)}}
            tls-mgr (tls/init-tls-manager! cfg)
            acme-atom (atom {})
            servers (server/start-http-servers! cfg tls-mgr acme-atom)]
        (try
          (let [^X509Certificate initial-cert (get-peer-cert "127.0.0.1" https-port)]
            (testing "Initial connection presents initial certificate"
              (let [subject (.getName (.getSubjectX500Principal initial-cert))]
                (is (.contains subject "CN=initial.domain.org"))))

            (testing "Hot-reloading TLS bundle updates presented certificate immediately without restarting server"
              (let [new-bundle (tls/generate-self-signed-cert "initial.domain.org" 60)
                    cert-pem (tls/encode-cert-chain-pem (:certificates new-bundle))
                    key-pem (tls/encode-private-key-pem (:private-key new-bundle))]
                (tls/update-tls-bundle! tls-mgr cert-pem key-pem)

                (let [^X509Certificate reloaded-cert (get-peer-cert "127.0.0.1" https-port)
                      reloaded-subject (.getName (.getSubjectX500Principal reloaded-cert))]
                  (is (.contains reloaded-subject "CN=initial.domain.org"))
                  (is (not= (.getSerialNumber initial-cert) (.getSerialNumber reloaded-cert)))))))

          (finally
            (server/stop-http-servers! servers)))))))

(deftest test-https-monthly-egress-limiting
  (with-temp-env
    (fn [^File state-dir ^File content-dir]
      (let [http-port (find-free-port)
            https-port (find-free-port)
            cfg {:state-dir (.getAbsolutePath state-dir)
                 :domain "egress-test.domain.org"
                 :http {:bind-ip "127.0.0.1"
                        :http-port http-port
                        :https-port https-port
                        :content-root (.getAbsolutePath content-dir)}}
            tls-mgr (tls/init-tls-manager! cfg)
            acme-atom (atom {})
            servers (server/start-http-servers! cfg tls-mgr acme-atom)
            client (make-http-client)
            doc-file (io/file content-dir "test.txt")]
        (spit doc-file "monthly egress limit test payload")
        ;; Set monthly egress limit artificially to 10 bytes so the first request exhausts/exceeds it
        (reset! (:limiter-atom servers)
                {:capacity 100.0
                 :refill-per-sec 10.0
                 :monthly-egress-limit-bytes 10
                 :buckets {}
                 :egress-by-month {}})
        (try
          (testing "Returns 429 when monthly egress limit is exceeded"
            (let [uri (URI/create (str "https://127.0.0.1:" https-port "/test.txt"))
                  req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 429 (.statusCode resp)))
              (is (= "Monthly egress limit exceeded\n" (.body resp)))))

          (finally
            (server/stop-http-servers! servers)))))))

;; ---------------------------------------------------------------------------
;; TCP Passthrough Multiplexer & Ingress Classification Tests
;; ---------------------------------------------------------------------------

(defn- make-mock-client-hello
  "Builds a valid raw TLS 1.2 ClientHello byte array with the given SNI hostname."
  [^String sni-string]
  (let [sni-bytes (when sni-string (.getBytes sni-string StandardCharsets/UTF_8))
        sni-len (if sni-bytes (alength sni-bytes) 0)
        ext-data-len (+ 5 sni-len)
        ext-len (+ 4 ext-data-len)
        exts-block (if sni-string
                     (let [bb (ByteBuffer/allocate (+ 2 ext-len))]
                       (.putShort bb (short ext-len))
                       (.putShort bb (short 0)) ;; SNI ext type 0x0000
                       (.putShort bb (short ext-data-len))
                       (.putShort bb (short (+ 3 sni-len)))
                       (.put bb (byte 0)) ;; host_name type 0
                       (.putShort bb (short sni-len))
                       (.put bb sni-bytes)
                       (.array bb))
                     (byte-array [(byte 0) (byte 0)]))
        handshake-body-len (+ 2 32 1 0 2 2 1 1 (alength exts-block))
        handshake-len (+ 4 handshake-body-len)
        bb (ByteBuffer/allocate (+ 5 handshake-len))]
    (.put bb (byte 0x16))          ;; ContentType: Handshake
    (.putShort bb (short 0x0303))  ;; Version: TLS 1.2
    (.putShort bb (short handshake-len))
    (.put bb (byte 0x01))          ;; HandshakeType: ClientHello
    (.put bb (byte 0x00))          ;; Handshake length 24-bit
    (.putShort bb (short handshake-body-len))
    (.putShort bb (short 0x0303))  ;; Client Version
    (.put bb (byte-array 32))      ;; Random
    (.put bb (byte 0))             ;; Session ID length
    (.putShort bb (short 2))       ;; Cipher suites length
    (.putShort bb (short 0x1301))  ;; Cipher suite: TLS_AES_128_GCM_SHA256
    (.put bb (byte 1))             ;; Compression methods length
    (.put bb (byte 0))             ;; null compression
    (.put bb exts-block)
    (.array bb)))

(deftest test-extract-tls-sni-unit
  (testing "extracts SNI hostname from ClientHello"
    (let [pkt (make-mock-client-hello "node1.ingress.bitecho.org")]
      (is (= "node1.ingress.bitecho.org" (server/extract-tls-sni pkt (alength pkt))))))

  (testing "returns nil for non-TLS or malformed packets"
    (is (nil? (server/extract-tls-sni (byte-array 10) 10)))
    (is (nil? (server/extract-tls-sni (byte-array [(byte 0x16) (byte 0x03) (byte 0x01)]) 3)))
    (is (nil? (server/extract-tls-sni nil 0)))))

(deftest test-ingress-stream-classification-unit
  (let [domain "bitecho.org"]
    (testing "RFC 4571 DTLS is classified as ingress"
      (let [pkt (byte-array [(byte 0) (byte 12) (byte 0x16) (unchecked-byte 0xFE) (unchecked-byte 0xFD) 0 0 0 0 0 0 0])]
        (is (true? (server/ingress-stream? pkt (alength pkt) domain)))))

    (testing "RFC 4571 STUN is classified as ingress"
      (let [pkt (byte-array [(byte 0) (byte 20) (byte 0x00) (byte 0x01) 0 0 (byte 0x21) (byte 0x12) (unchecked-byte 0xA4) (byte 0x42)])]
        (is (true? (server/ingress-stream? pkt (alength pkt) domain)))))

    (testing "SNI node1.ingress.bitecho.org is ingress"
      (let [pkt (make-mock-client-hello "node1.ingress.bitecho.org")]
        (is (true? (server/ingress-stream? pkt (alength pkt) domain)))))

    (testing "SNI ingress.bitecho.org is ingress"
      (let [pkt (make-mock-client-hello "ingress.bitecho.org")]
        (is (true? (server/ingress-stream? pkt (alength pkt) domain)))))

    (testing "SNI bitecho.org or www.bitecho.org is NOT ingress"
      (let [pkt1 (make-mock-client-hello "bitecho.org")
            pkt2 (make-mock-client-hello "www.bitecho.org")]
        (is (false? (server/ingress-stream? pkt1 (alength pkt1) domain)))
        (is (false? (server/ingress-stream? pkt2 (alength pkt2) domain)))))

    (testing "Plain HTTP request is NOT ingress"
      (let [pkt (.getBytes "GET /healthz HTTP/1.1\r\n\r\n" StandardCharsets/UTF_8)]
        (is (false? (server/ingress-stream? pkt (alength pkt) domain)))))))

(defspec prop-extract-tls-sni-roundtrip
  100
  (prop/for-all [sub (gen/not-empty (gen/fmap #(apply str %) (gen/vector (gen/elements "abcdefghijklmnopqrstuvwxyz0123456789-") 3 20)))
                 domain (gen/elements ["example.com" "bitecho.org" "test.net"])]
                (let [host (str sub "." domain)
                      buf (make-mock-client-hello host)
                      extracted (server/extract-tls-sni buf (alength buf))]
                  (= host extracted))))

(defspec prop-extract-tls-sni-fuzz
  100
  (prop/for-all [bs (gen/fmap byte-array (gen/vector (gen/choose -128 127) 0 300))]
                (let [res (server/extract-tls-sni bs (alength ^bytes bs))]
                  (or (nil? res) (string? res)))))

(defspec prop-ingress-stream-classification
  100
  (prop/for-all [node-id (gen/choose 1 9)
                 domain (gen/elements ["bitecho.org" "example.com"])
                 other-sub (gen/elements ["www" "docs" "mvn" "api" "blog"])]
                (let [dtls-pkt (byte-array [(byte 0) (byte 10) (byte 0x16) (unchecked-byte 0xFE) (unchecked-byte 0xFD) 0 0 0 0 0])
                      stun-pkt (byte-array [(byte 0) (byte 20) (byte 0x00) (byte 0x01) 0 0 (byte 0x21) (byte 0x12) (unchecked-byte 0xA4) (byte 0x42)])
                      ingress-sni (str "node" node-id ".ingress." domain)
                      ingress-tls (make-mock-client-hello ingress-sni)
                      bare-ingress-tls (make-mock-client-hello (str "ingress." domain))
                      other-tls (make-mock-client-hello (str other-sub "." domain))
                      plain-http (.getBytes "GET / HTTP/1.1\r\nHost: test\r\n\r\n" StandardCharsets/UTF_8)]
                  (and (true? (server/ingress-stream? dtls-pkt (alength dtls-pkt) domain))
                       (true? (server/ingress-stream? stun-pkt (alength stun-pkt) domain))
                       (true? (server/ingress-stream? ingress-tls (alength ingress-tls) domain))
                       (true? (server/ingress-stream? bare-ingress-tls (alength bare-ingress-tls) domain))
                       (false? (server/ingress-stream? other-tls (alength other-tls) domain))
                       (false? (server/ingress-stream? plain-http (alength plain-http) domain))))))

(deftest test-port-443-tcp-passthrough-multiplexer
  (with-temp-env
    (fn [^File state-dir ^File content-dir]
      (let [http-port (find-free-port)
            https-port (find-free-port)
            mock-ingress-port (find-free-port)
            received-payload-promise (promise)
            mock-backend-server (ServerSocket. mock-ingress-port)]
        (try
          ;; Mock ingress backend thread
          (.start (Thread/ofVirtual)
                  (reify Runnable
                    (run [_]
                      (try
                        (with-open [client (.accept mock-backend-server)]
                          (let [in (.getInputStream client)
                                out (.getOutputStream client)
                                buf (byte-array 1024)
                                n (.read in buf 0 1024)]
                            (deliver received-payload-promise (when (pos? n) (java.util.Arrays/copyOf buf (int n))))
                            (.write out (.getBytes "MOCK-ACK\n" StandardCharsets/UTF_8))
                            (.flush out)))
                        (catch Exception _ nil)))))

          (let [cfg {:state-dir (.getAbsolutePath state-dir)
                     :domain "passthrough.bitecho.org"
                     :http {:bind-ip "127.0.0.1"
                            :http-port http-port
                            :https-port https-port
                            :content-root (.getAbsolutePath content-dir)
                            :ingress-target {:host "127.0.0.1" :port mock-ingress-port}}}
                tls-mgr (tls/init-tls-manager! cfg)
                acme-atom (atom {})
                servers (server/start-http-servers! cfg tls-mgr acme-atom)
                client (make-http-client)]
            (try
              (testing "RFC 4571 DTLS packet is routed to ingress-target backend"
                (with-open [s (Socket. "127.0.0.1" (int (:https-port servers)))]
                  (let [out (.getOutputStream s)
                        in (.getInputStream s)
                        dtls-pkt (byte-array [(byte 0) (byte 12) (byte 0x16) (unchecked-byte 0xFE) (unchecked-byte 0xFD) 1 2 3 4 5 6 7])]
                    (.write out dtls-pkt)
                    (.flush out)
                    (let [received (deref received-payload-promise 5000 :timeout)]
                      (is (not= :timeout received))
                      (is (java.util.Arrays/equals ^bytes dtls-pkt ^bytes received)))
                    (let [resp-buf (byte-array 1024)
                          rn (.read in resp-buf 0 1024)]
                      (is (= "MOCK-ACK\n" (String. resp-buf 0 rn StandardCharsets/UTF_8)))))))

              (testing "Standard HTTPS request to same port 443 is routed to internal HttpsServer"
                (let [uri (URI/create (str "https://127.0.0.1:" (:https-port servers) "/healthz"))
                      req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
                      resp (.send client req (HttpResponse$BodyHandlers/ofString))]
                  (is (= 200 (.statusCode resp)))
                  (is (= "ok\n" (.body resp)))))

              (finally
                (server/stop-http-servers! servers))))
          (finally
            (try (.close mock-backend-server) (catch Exception _ nil))))))))
