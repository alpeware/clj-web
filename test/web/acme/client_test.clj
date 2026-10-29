(ns web.acme.client-test
  "Unit and integration tests for ACME v2 client and certificate renewal workflow.
   Includes a full mock Let's Encrypt ACME v2 server implementing directory,
   replay nonce, newAccount, newOrder, HTTP-01 challenge fulfillment, order finalization,
   and certificate issuance."
  (:require [clojure.data.json :as json]
            [clojure.test :refer [deftest is testing]]
            [web.acme.client :as client]
            [web.acme.jws :as jws]
            [web.cluster.mesh :as mesh]
            [web.tls.context :as tls])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- create-temp-dir []
  (.toFile (Files/createTempDirectory "acme-test" (into-array FileAttribute []))))

(defn- delete-dir-recursively [f]
  (when (.exists f)
    (doseq [child (.listFiles f)]
      (if (.isDirectory child)
        (delete-dir-recursively child)
        (.delete child)))
    (.delete f)))

;; ---------------------------------------------------------------------------
;; Unit Tests: Renewal Decision Logic
;; ---------------------------------------------------------------------------

(deftest test-needs-renewal
  (let [now (System/currentTimeMillis)
        base-cfg {:acme {:enabled? true :renew-before-days 30}}]

    (testing "disabled ACME never requests renewal"
      (let [cfg (assoc-in base-cfg [:acme :enabled?] false)]
        (is (false? (client/needs-renewal? cfg nil now)))))

    (testing "nil tls-manager triggers renewal"
      (is (true? (client/needs-renewal? base-cfg nil now))))

    (testing "self-signed bootstrap certificate triggers renewal"
      (let [mgr {:bundle-atom (atom {:self-signed? true :expires-at (+ now 10000000)})}]
        (is (true? (client/needs-renewal? base-cfg mgr now)))))

    (testing "expired certificate triggers renewal"
      (let [mgr {:bundle-atom (atom {:self-signed? false :expires-at (- now 10000)})}]
        (is (true? (client/needs-renewal? base-cfg mgr now)))))

    (testing "certificate expiring within 30 days triggers renewal"
      (let [twenty-days-ms (* 20 86400000)
            mgr {:bundle-atom (atom {:self-signed? false :expires-at (+ now twenty-days-ms)})}]
        (is (true? (client/needs-renewal? base-cfg mgr now)))))

    (testing "certificate with 60 days validity does not trigger renewal"
      (let [sixty-days-ms (* 60 86400000)
            mgr {:bundle-atom (atom {:self-signed? false :expires-at (+ now sixty-days-ms)})}]
        (is (false? (client/needs-renewal? base-cfg mgr now)))))))

;; ---------------------------------------------------------------------------
;; Integration Test: Mock ACME v2 Server & Certificate Issuance
;; ---------------------------------------------------------------------------

(defn- send-http-response!
  [^HttpExchange exchange status ^String content-type ^String replay-nonce headers ^bytes body-bytes]
  (let [resp-hdrs (.getResponseHeaders exchange)]
    (when content-type
      (.add resp-hdrs "Content-Type" content-type))
    (when replay-nonce
      (.add resp-hdrs "Replay-Nonce" replay-nonce))
    (doseq [[k v] headers]
      (.add resp-hdrs k v))
    (if (or (nil? body-bytes) (zero? (count body-bytes)))
      (.sendResponseHeaders exchange status -1)
      (do
        (.sendResponseHeaders exchange status (count body-bytes))
        (with-open [os (.getResponseBody exchange)]
          (.write os body-bytes))))))

(defn- create-mock-acme-server
  "Spins up an in-memory mock ACME v2 server implementing RFC 8555 directory,
   account registration, order creation, HTTP-01 challenge, finalization, and cert download."
  []
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
        port (.getPort (.getAddress server))
        base-url (str "http://127.0.0.1:" port)
        nonce-counter (atom 0)
        authz-status-atom (atom "pending")
        order-status-atom (atom "pending")
        issued-cert-pem (atom nil)

        next-nonce (fn []
                     (str "mock-nonce-" (swap! nonce-counter inc)))

        handler
        (proxy [HttpHandler] []
          (handle [^HttpExchange exchange]
            (let [method (.getRequestMethod exchange)
                  path (.getPath (.getRequestURI exchange))
                  nonce (next-nonce)]
              (cond
                ;; GET /directory
                (and (= method "GET") (= path "/directory"))
                (let [dir-json (json/write-str {"newNonce" (str base-url "/acme/new-nonce")
                                                "newAccount" (str base-url "/acme/new-acct")
                                                "newOrder" (str base-url "/acme/new-order")})
                      bytes (.getBytes dir-json StandardCharsets/UTF_8)]
                  (send-http-response! exchange 200 "application/json" nonce {} bytes))

                ;; HEAD or GET /acme/new-nonce
                (and (#{"HEAD" "GET"} method) (= path "/acme/new-nonce"))
                (send-http-response! exchange 200 nil nonce {} nil)

                ;; POST /acme/new-acct
                (and (= method "POST") (= path "/acme/new-acct"))
                (let [resp-json (json/write-str {"status" "valid"})
                      bytes (.getBytes resp-json StandardCharsets/UTF_8)]
                  (send-http-response! exchange 201 "application/json" nonce
                                       {"Location" (str base-url "/acme/acct/1")}
                                       bytes))

                ;; POST /acme/new-order
                (and (= method "POST") (= path "/acme/new-order"))
                (let [order-json (json/write-str {"status" "pending"
                                                  "identifiers" [{"type" "dns" "value" "example.com"}]
                                                  "authorizations" [(str base-url "/acme/authz/1")]
                                                  "finalize" (str base-url "/acme/order/1/finalize")})
                      bytes (.getBytes order-json StandardCharsets/UTF_8)]
                  (send-http-response! exchange 201 "application/json" nonce
                                       {"Location" (str base-url "/acme/order/1")}
                                       bytes))

                ;; POST /acme/authz/1 (POST-as-GET)
                (and (= method "POST") (= path "/acme/authz/1"))
                (let [st @authz-status-atom
                      authz-json (json/write-str {"status" st
                                                  "challenges" [{"type" "http-01"
                                                                 "url" (str base-url "/acme/chall/1")
                                                                 "token" "mock-token-xyz-987"
                                                                 "status" st}]})
                      bytes (.getBytes authz-json StandardCharsets/UTF_8)]
                  (send-http-response! exchange 200 "application/json" nonce {} bytes))

                ;; POST /acme/chall/1 (trigger validation)
                (and (= method "POST") (= path "/acme/chall/1"))
                (do
                  ;; Mark authorization as valid
                  (reset! authz-status-atom "valid")
                  (let [resp-json (json/write-str {"status" "valid"})
                        bytes (.getBytes resp-json StandardCharsets/UTF_8)]
                    (send-http-response! exchange 200 "application/json" nonce {} bytes)))

                ;; POST /acme/order/1/finalize
                (and (= method "POST") (= path "/acme/order/1/finalize"))
                (let [raw-req (slurp (.getRequestBody exchange))
                      jws-payload (when-let [p (get (json/read-str raw-req) "payload")]
                                    (json/read-str (jws/base64url-decode-str p)))
                      _csr-b64 (get jws-payload "csr")
                      cert-data (tls/generate-self-signed-cert "example.com" 90)
                      cert-pem (tls/encode-cert-pem (:certificate cert-data))]
                  (reset! issued-cert-pem cert-pem)
                  (reset! order-status-atom "valid")
                  (let [order-json (json/write-str {"status" "valid"
                                                    "certificate" (str base-url "/acme/order/1/cert")})
                        bytes (.getBytes order-json StandardCharsets/UTF_8)]
                    (send-http-response! exchange 200 "application/json" nonce {} bytes)))

                ;; POST /acme/order/1 (poll order status)
                (and (= method "POST") (= path "/acme/order/1"))
                (let [st @order-status-atom
                      order-json (json/write-str (cond-> {"status" st}
                                                   (= st "valid") (assoc "certificate" (str base-url "/acme/order/1/cert"))))
                      bytes (.getBytes order-json StandardCharsets/UTF_8)]
                  (send-http-response! exchange 200 "application/json" nonce {} bytes))

                ;; POST /acme/order/1/cert (download certificate)
                (and (= method "POST") (= path "/acme/order/1/cert"))
                (let [cert-str @issued-cert-pem
                      bytes (.getBytes (or cert-str "") StandardCharsets/UTF_8)]
                  (send-http-response! exchange 200 "application/pem-certificate-chain" nonce {} bytes))

                :else
                (send-http-response! exchange 404 "text/plain" nonce {} (.getBytes "Not Found"))))))]
    (.createContext server "/" handler)
    (.start server)
    {:server server
     :base-url base-url
     :port port
     :stop-fn (fn [] (try (.stop server 0) (catch Exception _ nil)))}))

(deftest test-e2e-acme-provisioning-flow
  (let [mock-server (create-mock-acme-server)
        base-url (:base-url mock-server)
        temp-dir (create-temp-dir)
        config {:domain "example.com"
                :state-dir (str temp-dir)
                :node/id :ns1
                :cluster {:nodes {:ns1 {:ip "127.0.0.1" :port 5001}}}
                :acme {:enabled? true
                       :domains ["example.com"]
                       :contact-email "mailto:admin@example.com"
                       :directory-url (str base-url "/directory")
                       :renew-before-days 30}}
        tls-mgr (tls/init-tls-manager! {:state-dir (str temp-dir) :domain "example.com"})
        challenges-atom (atom {})
        cluster-mgr (mesh/start-cluster! config tls-mgr challenges-atom {:transport :in-memory})]
    (try
      (testing "initial TLS manager is self-signed"
        (is (true? (:self-signed? @(:bundle-atom tls-mgr)))))

      (testing "provision-certificate! completes full RFC 8555 flow against mock ACME server"
        (let [result (client/provision-certificate! config cluster-mgr tls-mgr
                                                    {:directory-url (str base-url "/directory")
                                                     :poll-interval-ms 20
                                                     :poll-timeout-ms 5000})]
          (is (some? result))
          (is (string? (:cert-pem result)))
          (is (string? (:key-pem result)))
          (is (> (:expires-at result) (System/currentTimeMillis)))
          (is (seq (:certificates result)))

          (testing "tls-manager was hot-reloaded with the issued ACME certificate"
            (let [current-bundle @(:bundle-atom tls-mgr)]
              (is (false? (:self-signed? current-bundle)))
              (is (some? (:private-key current-bundle)))
              (is (= (:cert-pem result) (:cert-pem current-bundle)))))))

      (testing "start-acme-loop! and stop-acme-loop! lifecycle"
        (let [acme-loop (client/start-acme-loop! config cluster-mgr tls-mgr {:check-interval-ms 50})]
          (is (some? acme-loop))
          (is (true? (.get ^java.util.concurrent.atomic.AtomicBoolean (:running? acme-loop))))
          (client/stop-acme-loop! acme-loop)
          (is (false? (.get ^java.util.concurrent.atomic.AtomicBoolean (:running? acme-loop))))))

      (finally
        ((:stop-fn mock-server))
        (mesh/stop-cluster! cluster-mgr)
        (delete-dir-recursively temp-dir)))))
