(ns web.http.server-test
  "Live integration tests for JDK 25 virtual-thread HttpServer (port 80) and
   HttpsServer (port 443), covering ACME challenges, 308 redirect, /healthz,
   static content delivery over HTTPS, rate limiting, and zero-downtime TLS hot-swap."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [web.http.server :as server]
            [web.tls.context :as tls])
  (:import [java.io File]
           [java.net ServerSocket URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
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
