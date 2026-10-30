(ns web.main-test
  "Comprehensive integration and unit test suite for web.main and the full 3-node cluster.
   Validates CLI subcommands, single-node lifecycle, and executes an end-to-end 3-node
   cluster integration verification covering:
     1. Cluster formation and quorum leader election (:ns1 leader, :ns2/:ns3 followers).
     2. Automated ACME cert issuance, HTTP-01 challenge cluster sync, and follower TLS hot-swap.
     3. HTTPS static asset serving across nodes (HTTP 200, ETag, 304 Not Modified, HSTS).
     4. Inbound STARTTLS SMTP on :ns2 and cross-node inbox replication to :ns1, :ns2, and :ns3.
     5. Health-aware multi-A DNS resolution, node failover simulation, leader re-election,
        and health-filtered DNS resolution."
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [web.acme.client :as acme]
            [web.acme.jws :as jws]
            [web.dns.codec :as codec]
            [web.main :as main]
            [web.smtp.server :as smtp]
            [web.tls.context :as tls])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.io BufferedReader BufferedWriter File InputStreamReader OutputStreamWriter]
           [java.math BigInteger]
           [java.net DatagramPacket DatagramSocket InetAddress InetSocketAddress ServerSocket Socket URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.security KeyPair SecureRandom]
           [java.security.cert X509Certificate]
           [java.util Date]
           [javax.net.ssl SSLContext TrustManager X509TrustManager]
           [sun.security.x509 AlgorithmId CertificateAlgorithmId CertificateExtensions
            CertificateSerialNumber CertificateValidity CertificateVersion
            CertificateX509Key DNSName GeneralName GeneralNames IPAddressName
            SubjectAlternativeNameExtension X500Name X509CertImpl X509CertInfo]))

;; ---------------------------------------------------------------------------
;; Test Utilities & Helpers
;; ---------------------------------------------------------------------------

(defn- create-temp-dir []
  (.toFile (Files/createTempDirectory "main-test" (into-array FileAttribute []))))

(defn- delete-dir-recursively [^File f]
  (when (.exists f)
    (doseq [child (.listFiles f)]
      (if (.isDirectory child)
        (delete-dir-recursively child)
        (.delete child)))
    (.delete f)))

(defn- find-free-port []
  (with-open [s (ServerSocket. 0)]
    (.getLocalPort s)))

(defn- wait-for-mail [dir-path timeout-ms]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop []
      (let [emails (smtp/list-emails dir-path)]
        (if (seq emails)
          emails
          (if (< (System/currentTimeMillis) deadline)
            (do (Thread/sleep 50) (recur))
            []))))))

(defn- read-smtp-line [^BufferedReader reader]
  (.readLine reader))

(defn- write-smtp-line [^BufferedWriter writer line]
  (.write writer (str line "\r\n"))
  (.flush writer))

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

(defn- send-udp-dns-query [^String host ^long port query-pkt]
  (let [wire (codec/encode-packet query-pkt {:max-bytes 512})
        socket (DatagramSocket.)]
    (.setSoTimeout socket 3000)
    (try
      (let [addr (InetAddress/getByName host)
            packet (DatagramPacket. wire (alength wire) addr (int port))]
        (.send socket packet)
        (let [recv-buf (byte-array 1500)
              recv-packet (DatagramPacket. recv-buf (alength recv-buf))]
          (.receive socket recv-packet)
          (let [resp-bytes (byte-array (.getLength recv-packet))]
            (System/arraycopy recv-buf 0 resp-bytes 0 (.getLength recv-packet))
            (codec/decode-packet resp-bytes))))
      (finally
        (.close socket)))))

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

(defn- generate-cert-for-keypair
  [^KeyPair kp ^String domain ^long validity-days]
  (let [pub (.getPublic kp)
        priv (.getPrivate kp)
        info (X509CertInfo.)
        now (Date.)
        until (Date. (+ (.getTime now) (* validity-days 86400000)))
        validity (CertificateValidity. now until)
        sn (CertificateSerialNumber. (BigInteger. 64 (SecureRandom.)))
        owner (X500Name. (str "CN=" domain))
        alg-id (AlgorithmId/get "SHA256withECDSA")]
    (.setVersion info (CertificateVersion. CertificateVersion/V3))
    (.setSerialNumber info sn)
    (.setSubject info owner)
    (.setIssuer info owner)
    (.setValidity info validity)
    (.setKey info (CertificateX509Key. pub))
    (.setAlgorithmId info (CertificateAlgorithmId. alg-id))
    (let [exts (CertificateExtensions.)
          gn (GeneralNames.)]
      (.add gn (GeneralName. (DNSName. (or domain "localhost"))))
      (.add gn (GeneralName. (DNSName. "localhost")))
      (.add gn (GeneralName. (IPAddressName. "127.0.0.1")))
      (.setExtension exts SubjectAlternativeNameExtension/NAME (SubjectAlternativeNameExtension. gn))
      (.setExtensions info exts))
    (X509CertImpl/newSigned info priv "SHA256withECDSA")))

(defn- create-mock-acme-server
  "Creates an in-memory mock ACME v2 server implementing RFC 8555 directory,
   newNonce, newAccount, newOrder, authz, HTTP-01 challenge, order finalize, and cert download."
  ([]
   (create-mock-acme-server (jws/generate-ec-keypair)))
  ([^KeyPair kp]
   (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
         port (.getPort (.getAddress server))
         base-url (str "http://127.0.0.1:" port)
         nonce-counter (atom 0)
         authz-status-atom (atom "pending")
         order-status-atom (atom "pending")
         issued-cert-pem (atom nil)
         next-nonce (fn [] (str "mock-nonce-" (swap! nonce-counter inc)))
         handler
         (proxy [HttpHandler] []
           (handle [^HttpExchange exchange]
             (let [method (.getRequestMethod exchange)
                   path (.getPath (.getRequestURI exchange))
                   nonce (next-nonce)]
               (cond
                 (and (= method "GET") (= path "/directory"))
                 (let [dir-json (json/write-str {"newNonce" (str base-url "/acme/new-nonce")
                                                 "newAccount" (str base-url "/acme/new-acct")
                                                 "newOrder" (str base-url "/acme/new-order")})
                       bytes (.getBytes dir-json StandardCharsets/UTF_8)]
                   (send-http-response! exchange 200 "application/json" nonce {} bytes))

                 (and (#{"HEAD" "GET"} method) (= path "/acme/new-nonce"))
                 (send-http-response! exchange 200 nil nonce {} nil)

                 (and (= method "POST") (= path "/acme/new-acct"))
                 (let [resp-json (json/write-str {"status" "valid"})
                       bytes (.getBytes resp-json StandardCharsets/UTF_8)]
                   (send-http-response! exchange 201 "application/json" nonce
                                        {"Location" (str base-url "/acme/acct/1")}
                                        bytes))

                 (and (= method "POST") (= path "/acme/new-order"))
                 (let [order-json (json/write-str {"status" "pending"
                                                   "identifiers" [{"type" "dns" "value" "example.com"}]
                                                   "authorizations" [(str base-url "/acme/authz/1")]
                                                   "finalize" (str base-url "/acme/order/1/finalize")})
                       bytes (.getBytes order-json StandardCharsets/UTF_8)]
                   (send-http-response! exchange 201 "application/json" nonce
                                        {"Location" (str base-url "/acme/order/1")}
                                        bytes))

                 (and (= method "POST") (= path "/acme/authz/1"))
                 (let [st @authz-status-atom
                       authz-json (json/write-str {"status" st
                                                   "challenges" [{"type" "http-01"
                                                                  "url" (str base-url "/acme/chall/1")
                                                                  "token" "mock-token-xyz-987"
                                                                  "status" st}]})
                       bytes (.getBytes authz-json StandardCharsets/UTF_8)]
                   (send-http-response! exchange 200 "application/json" nonce {} bytes))

                 (and (= method "POST") (= path "/acme/chall/1"))
                 (do
                   (reset! authz-status-atom "valid")
                   (let [resp-json (json/write-str {"status" "valid"})
                         bytes (.getBytes resp-json StandardCharsets/UTF_8)]
                     (send-http-response! exchange 200 "application/json" nonce {} bytes)))

                 (and (= method "POST") (= path "/acme/order/1/finalize"))
                 (let [cert (generate-cert-for-keypair kp "example.com" 90)
                       cert-pem (tls/encode-cert-pem cert)]
                   (reset! issued-cert-pem cert-pem)
                   (reset! order-status-atom "valid")
                   (let [order-json (json/write-str {"status" "valid"
                                                     "certificate" (str base-url "/acme/order/1/cert")})
                         bytes (.getBytes order-json StandardCharsets/UTF_8)]
                     (send-http-response! exchange 200 "application/json" nonce {} bytes)))

                 (and (= method "POST") (= path "/acme/order/1"))
                 (let [st @order-status-atom
                       order-json (json/write-str (cond-> {"status" st}
                                                    (= st "valid") (assoc "certificate" (str base-url "/acme/order/1/cert"))))
                       bytes (.getBytes order-json StandardCharsets/UTF_8)]
                   (send-http-response! exchange 200 "application/json" nonce {} bytes))

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
      :stop-fn (fn [] (try (.stop server 0) (catch Exception _ nil)))})))

;; ---------------------------------------------------------------------------
;; Unit Tests: CLI Subcommands & Node Lifecycle
;; ---------------------------------------------------------------------------

(deftest test-cli-subcommands
  (let [dir (create-temp-dir)
        cfg-file (io/file dir "node.edn")]
    (try
      (spit cfg-file (pr-str {:domain "example.com"
                              :node/id :ns1
                              :state-dir (.getAbsolutePath dir)}))

      (testing "print-fingerprint subcommand outputs SHA-256 DTLS fingerprint"
        (let [out (with-out-str (main/-main "print-fingerprint" (.getAbsolutePath cfg-file)))]
          (is (.contains out "Node: :ns1"))
          (is (.contains out "State directory:"))
          (is (.contains out "SHA-256 Fingerprint:"))
          (is (re-find #"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){31}" out))))

      (testing "list-mail subcommand displays saved emails"
        (let [mail-info {:from "alice@sender.org"
                         :to ["admin@example.com"]
                         :helo "mail.sender.org"
                         :remote-ip "192.168.1.1"
                         :domain "example.com"
                         :subject "CLI Subcommand Test Email"
                         :raw-eml "From: alice@sender.org\r\nTo: admin@example.com\r\nSubject: CLI Subcommand Test Email\r\n\r\nBody text"}]
          (smtp/save-eml! (.getAbsolutePath dir) mail-info)
          (let [out (with-out-str (main/-main "list-mail" (.getAbsolutePath cfg-file)))]
            (is (.contains out "Found 1 emails"))
            (is (.contains out "alice@sender.org"))
            (is (.contains out "CLI Subcommand Test Email")))))

      (testing "read-mail subcommand displays email headers and plain body"
        (let [saved (smtp/save-eml! (.getAbsolutePath dir)
                                    {:from "bob@sender.org"
                                     :to ["admin@example.com"]
                                     :helo "mail.sender.org"
                                     :remote-ip "192.168.1.1"
                                     :domain "example.com"
                                     :subject "Read Mail Test Subject"
                                     :raw-eml "From: bob@sender.org\r\nTo: admin@example.com\r\nSubject: Read Mail Test Subject\r\n\r\nHello from the plain body!"})
              email-file (:file saved)
              email-id (str/replace (.getName ^File email-file) #"\.eml$" "")
              out-latest (with-out-str (main/-main "read-mail" (.getAbsolutePath cfg-file)))
              out-id (with-out-str (main/-main "read-mail" (.getAbsolutePath cfg-file) email-id))]
          (is (.contains out-latest "ID:"))
          (is (.contains out-latest "From:    bob@sender.org"))
          (is (.contains out-latest "To:      admin@example.com"))
          (is (.contains out-latest "Subject: Read Mail Test Subject"))
          (is (.contains out-latest "Hello from the plain body!"))
          (is (.contains out-id "ID:"))
          (is (.contains out-id email-id))
          (is (.contains out-id "From:    bob@sender.org"))
          (is (.contains out-id "Hello from the plain body!"))))

      (testing "delete-mail subcommand deletes specific, latest, and all emails"
        (let [s1 (smtp/save-eml! (.getAbsolutePath dir)
                                 {:from "del1@sender.org"
                                  :to ["admin@example.com"]
                                  :helo "mail.sender.org"
                                  :remote-ip "192.168.1.1"
                                  :domain "example.com"
                                  :subject "Delete 1"
                                  :raw-eml "From: del1@sender.org\r\nSubject: Delete 1\r\n\r\n1"})
              s2 (smtp/save-eml! (.getAbsolutePath dir)
                                 {:from "del2@sender.org"
                                  :to ["admin@example.com"]
                                  :helo "mail.sender.org"
                                  :remote-ip "192.168.1.1"
                                  :domain "example.com"
                                  :subject "Delete 2"
                                  :raw-eml "From: del2@sender.org\r\nSubject: Delete 2\r\n\r\n2"})
              _s3 (smtp/save-eml! (.getAbsolutePath dir)
                                  {:from "del3@sender.org"
                                   :to ["admin@example.com"]
                                   :helo "mail.sender.org"
                                   :remote-ip "192.168.1.1"
                                   :domain "example.com"
                                   :subject "Delete 3"
                                   :raw-eml "From: del3@sender.org\r\nSubject: Delete 3\r\n\r\n3"})
              id1 (str/replace (.getName ^File (:file s1)) #"\.eml$" "")
              fname2 (.getName ^File (:file s2))
              ;; Delete specific ID
              out-id (with-out-str (main/-main "delete-mail" (.getAbsolutePath cfg-file) id1))
              _ (is (.contains out-id "Deleted 1 email(s)"))
              _ (is (.contains out-id id1))
              ;; Delete latest (which is s3)
              out-latest (with-out-str (main/-main "delete-mail" (.getAbsolutePath cfg-file) "latest"))
              _ (is (.contains out-latest "Deleted 1 email(s)"))
              ;; Only s2 remains; delete all
              out-all (with-out-str (main/-main "delete-mail" (.getAbsolutePath cfg-file) "all"))
              _ (is (re-find #"Deleted \d+ email\(s\)" out-all))
              _ (is (.contains out-all fname2))
              ;; Now empty; deleting again prints no matching emails found
              out-empty (with-out-str (main/-main "delete-mail" (.getAbsolutePath cfg-file) "latest"))
              _ (is (.contains out-empty "No matching emails found to delete"))
              remaining (smtp/list-emails (.getAbsolutePath dir))]
          (is (empty? remaining))))

      (testing "single-node start-node! and stop-node! lifecycle"
        (let [node (main/start-node! {:domain "example.com"
                                      :node/id :ns1
                                      :state-dir (.getAbsolutePath dir)
                                      :dns {:bind-ip "127.0.0.1" :port (find-free-port)}
                                      :http {:bind-ip "127.0.0.1" :http-port (find-free-port) :https-port (find-free-port)}
                                      :smtp {:bind-ip "127.0.0.1" :port (find-free-port)}
                                      :cluster {:nodes {:ns1 {:ip "127.0.0.1" :port (find-free-port)}}}}
                                     {:cluster-opts {:transport :in-memory}})]
          (is (some? (:dns-server node)))
          (is (some? (:smtp-server node)))
          (is (some? (:http-servers node)))
          (is (some? (:tls-manager node)))
          (is (some? (:cluster-mgr node)))
          (is (fn? (:stop-fn node)))
          ((:stop-fn node))))
      (finally
        (delete-dir-recursively dir)))))

;; ---------------------------------------------------------------------------
;; Integration Test: 3-Node End-to-End Cluster Verification
;; ---------------------------------------------------------------------------

(deftest three-node-e2e-integration-test
  (let [test-keypair (jws/generate-ec-keypair)
        mock-server (create-mock-acme-server test-keypair)
        content-dir (create-temp-dir)
        dir1 (create-temp-dir)
        dir2 (create-temp-dir)
        dir3 (create-temp-dir)
        index-file (io/file content-dir "index.html")
        _ (spit index-file "<h1>Hello from clj-web 3-node cluster!</h1>")
        dns-port-1 (find-free-port)
        dns-port-2 (find-free-port)
        dns-port-3 (find-free-port)
        http-port-1 (find-free-port)
        http-port-2 (find-free-port)
        http-port-3 (find-free-port)
        https-port-1 (find-free-port)
        https-port-2 (find-free-port)
        https-port-3 (find-free-port)
        smtp-port-1 (find-free-port)
        smtp-port-2 (find-free-port)
        smtp-port-3 (find-free-port)
        cluster-port-1 (find-free-port)
        cluster-port-2 (find-free-port)
        cluster-port-3 (find-free-port)
        base-cfg {:domain "example.com"
                  :cluster {:nodes {:ns1 {:ip4 "10.0.0.1" :ip "127.0.0.1" :port cluster-port-1}
                                    :ns2 {:ip4 "10.0.0.2" :ip "127.0.0.1" :port cluster-port-2}
                                    :ns3 {:ip4 "10.0.0.3" :ip "127.0.0.1" :port cluster-port-3}}
                            :heartbeat-interval-ms 100
                            :heartbeat-timeout-ms 350}
                  :acme {:enabled? true
                         :domains ["example.com"]
                         :contact-email "mailto:admin@example.com"
                         :directory-url (str (:base-url mock-server) "/directory")
                         :renew-before-days 30}}
        cfg1 (assoc base-cfg
                    :node/id :ns1
                    :state-dir (.getAbsolutePath dir1)
                    :dns {:bind-ip "127.0.0.1" :port dns-port-1 :subdomains #{"@" "www" "ns1" "ns2" "ns3"}}
                    :http {:bind-ip "127.0.0.1" :http-port http-port-1 :https-port https-port-1 :content-root (.getAbsolutePath content-dir)}
                    :smtp {:bind-ip "127.0.0.1" :port smtp-port-1 :allowed-recipients #{"admin@example.com"}})
        cfg2 (assoc base-cfg
                    :node/id :ns2
                    :state-dir (.getAbsolutePath dir2)
                    :dns {:bind-ip "127.0.0.1" :port dns-port-2 :subdomains #{"@" "www" "ns1" "ns2" "ns3"}}
                    :http {:bind-ip "127.0.0.1" :http-port http-port-2 :https-port https-port-2 :content-root (.getAbsolutePath content-dir)}
                    :smtp {:bind-ip "127.0.0.1" :port smtp-port-2 :allowed-recipients #{"admin@example.com"}})
        cfg3 (assoc base-cfg
                    :node/id :ns3
                    :state-dir (.getAbsolutePath dir3)
                    :dns {:bind-ip "127.0.0.1" :port dns-port-3 :subdomains #{"@" "www" "ns1" "ns2" "ns3"}}
                    :http {:bind-ip "127.0.0.1" :http-port http-port-3 :https-port https-port-3 :content-root (.getAbsolutePath content-dir)}
                    :smtp {:bind-ip "127.0.0.1" :port smtp-port-3 :allowed-recipients #{"admin@example.com"}})
        elected-leader (promise)
        n1 (main/start-node! cfg1 {:cluster-opts {:transport :in-memory
                                                  :on-leader-elected (fn [leader term]
                                                                       (deliver elected-leader [leader term]))}})
        n2 (main/start-node! cfg2 {:cluster-opts {:transport :in-memory}})
        n3 (main/start-node! cfg3 {:cluster-opts {:transport :in-memory}})]
    (try
      ;; Cross-wire in-memory cluster transport between ns1, ns2, ns3
      (let [mgrs {:ns1 (:cluster-mgr n1) :ns2 (:cluster-mgr n2) :ns3 (:cluster-mgr n3)}]
        (doseq [[from-id from-mgr] mgrs
                [to-id to-mgr] mgrs
                :when (not= from-id to-id)]
          (swap! (:peer-conns-atom from-mgr) assoc-in [to-id :send-fn]
                 (fn [msg]
                   ((:dispatch-event! to-mgr)
                    {:type :cluster/receive :from from-id :message msg}
                    (System/currentTimeMillis))))))

      ;; Connect peers
      (let [now (System/currentTimeMillis)]
        ((:dispatch-event! (:cluster-mgr n1)) {:type :cluster/peer-connected :peer-id :ns2} now)
        ((:dispatch-event! (:cluster-mgr n1)) {:type :cluster/peer-connected :peer-id :ns3} now)
        ((:dispatch-event! (:cluster-mgr n2)) {:type :cluster/peer-connected :peer-id :ns1} now)
        ((:dispatch-event! (:cluster-mgr n2)) {:type :cluster/peer-connected :peer-id :ns3} now)
        ((:dispatch-event! (:cluster-mgr n3)) {:type :cluster/peer-connected :peer-id :ns1} now)
        ((:dispatch-event! (:cluster-mgr n3)) {:type :cluster/peer-connected :peer-id :ns2} now))

      ;; -----------------------------------------------------------------------
      ;; 1. Cluster Formation and Quorum Leader Election
      ;; -----------------------------------------------------------------------
      (testing "Requirement 1: Cluster formation and quorum leader election"
        (let [[leader term] (deref elected-leader 5000 nil)]
          (is (= :ns1 leader))
          (is (pos? term)))
        (is (= :leader (:role @(:state-atom (:cluster-mgr n1)))))
        (is (= :ns1 (:leader-id @(:state-atom (:cluster-mgr n1)))))
        (is (= :follower (:role @(:state-atom (:cluster-mgr n2)))))
        (is (= :ns1 (:leader-id @(:state-atom (:cluster-mgr n2)))))
        (is (= :follower (:role @(:state-atom (:cluster-mgr n3)))))
        (is (= :ns1 (:leader-id @(:state-atom (:cluster-mgr n3))))))

      ;; -----------------------------------------------------------------------
      ;; 2. Automated ACME Cert Issuance, Challenge Sync & Follower Hot-Swap
      ;; -----------------------------------------------------------------------
      (testing "Requirement 2: Automated ACME certificate issuance, cluster HTTP-01 challenge sync, and follower TLS bundle hot-swap"
        ;; Verify initially all 3 nodes have self-signed bootstrap certificates
        (is (true? (:self-signed? @(:bundle-atom (:tls-manager n1)))))
        (is (true? (:self-signed? @(:bundle-atom (:tls-manager n2)))))
        (is (true? (:self-signed? @(:bundle-atom (:tls-manager n3)))))

        ;; Leader ns1 provisions certificate via mock ACME v2 server
        (let [acme-res (acme/provision-certificate! (:config n1)
                                                    (:cluster-mgr n1)
                                                    (:tls-manager n1)
                                                    {:directory-url (str (:base-url mock-server) "/directory")
                                                     :domain-keypair test-keypair
                                                     :poll-interval-ms 20
                                                     :poll-timeout-ms 5000})]
          (is (some? acme-res))
          (is (string? (:cert-pem acme-res)))
          ;; Leader updated locally
          (is (false? (:self-signed? @(:bundle-atom (:tls-manager n1)))))
          ;; Followers ns2 and ns3 hot-swapped their TLS bundle via cluster replication
          (is (false? (:self-signed? @(:bundle-atom (:tls-manager n2)))))
          (is (false? (:self-signed? @(:bundle-atom (:tls-manager n3)))))
          (is (= (:cert-pem acme-res) (:cert-pem @(:bundle-atom (:tls-manager n2)))))
          (is (= (:cert-pem acme-res) (:cert-pem @(:bundle-atom (:tls-manager n3)))))))

      ;; -----------------------------------------------------------------------
      ;; 3. HTTPS Static Asset Serving Across Nodes
      ;; -----------------------------------------------------------------------
      (testing "Requirement 3: HTTPS static asset serving across nodes (HTTP 200, ETag, 304 Not Modified, HSTS)"
        (let [client (make-http-client)
              https-port-2 (get-in n2 [:http-servers :https-port])
              uri (URI/create (str "https://127.0.0.1:" https-port-2 "/index.html"))
              req (-> (HttpRequest/newBuilder uri) (.GET) (.build))
              resp (.send client req (HttpResponse$BodyHandlers/ofString))
              etag (first (.allValues (.headers resp) "ETag"))
              hsts (first (.allValues (.headers resp) "Strict-Transport-Security"))]
          (is (= 200 (.statusCode resp)))
          (is (.contains (.body resp) "Hello from clj-web 3-node cluster!"))
          (is (some? etag))
          (is (some? hsts))
          (is (.contains hsts "max-age=31536000"))

          ;; Conditional GET with matching ETag returns 304 Not Modified
          (let [cond-req (-> (HttpRequest/newBuilder uri)
                             (.header "If-None-Match" etag)
                             (.GET)
                             (.build))
                cond-resp (.send client cond-req (HttpResponse$BodyHandlers/discarding))]
            (is (= 304 (.statusCode cond-resp))))))

      ;; -----------------------------------------------------------------------
      ;; 4. Inbound STARTTLS SMTP on ns2 + Cross-Node Inbox Replication
      ;; -----------------------------------------------------------------------
      (testing "Requirement 4: Inbound STARTTLS SMTP on ns2 and cross-node inbox replication"
        (let [smtp-port-2 (get-in n2 [:smtp-server :port])]
          (with-open [raw-sock (Socket. "127.0.0.1" (int smtp-port-2))]
            (.setSoTimeout raw-sock 5000)
            (let [raw-in (BufferedReader. (InputStreamReader. (.getInputStream raw-sock) StandardCharsets/UTF_8))
                  raw-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream raw-sock) StandardCharsets/UTF_8))]
              ;; 1. Banner
              (is (.startsWith (read-smtp-line raw-in) "220 example.com ESMTP clj-web ready"))
              ;; 2. EHLO
              (write-smtp-line raw-out "EHLO test.client.org")
              (loop []
                (let [line (read-smtp-line raw-in)]
                  (when (.startsWith line "250-")
                    (recur))))
              ;; 3. STARTTLS
              (write-smtp-line raw-out "STARTTLS")
              (is (= "220 2.0.0 Ready to start TLS" (read-smtp-line raw-in)))

              ;; 4. Upgrade to SSLSocket
              (let [ssl-ctx (make-trusting-ssl-context)
                    factory (.getSocketFactory ssl-ctx)
                    ssl-sock (.createSocket factory raw-sock "127.0.0.1" (int smtp-port-2) true)]
                (.setUseClientMode ssl-sock true)
                (.setEnabledProtocols ssl-sock (into-array String ["TLSv1.3" "TLSv1.2"]))
                (.setSoTimeout ssl-sock 5000)
                (.startHandshake ssl-sock)

                (let [tls-in (BufferedReader. (InputStreamReader. (.getInputStream ssl-sock) StandardCharsets/UTF_8))
                      tls-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream ssl-sock) StandardCharsets/UTF_8))]
                  ;; 5. Post-TLS EHLO
                  (write-smtp-line tls-out "EHLO test.client.org")
                  (loop []
                    (let [line (read-smtp-line tls-in)]
                      (when (.startsWith line "250-")
                        (recur))))
                  ;; 6. MAIL FROM
                  (write-smtp-line tls-out "MAIL FROM:<alice@sender.org>")
                  (is (= "250 2.1.0 OK" (read-smtp-line tls-in)))
                  ;; 7. RCPT TO
                  (write-smtp-line tls-out "RCPT TO:<admin@example.com>")
                  (is (= "250 2.1.5 OK" (read-smtp-line tls-in)))
                  ;; 8. DATA
                  (write-smtp-line tls-out "DATA")
                  (is (.startsWith (read-smtp-line tls-in) "354"))
                  (write-smtp-line tls-out "From: alice@sender.org")
                  (write-smtp-line tls-out "To: admin@example.com")
                  (write-smtp-line tls-out "Subject: E2E Integration Cluster Test")
                  (write-smtp-line tls-out "")
                  (write-smtp-line tls-out "Cluster replicated email content.")
                  (write-smtp-line tls-out ".")
                  (is (.startsWith (read-smtp-line tls-in) "250"))
                  ;; 9. QUIT
                  (write-smtp-line tls-out "QUIT")
                  (is (.startsWith (read-smtp-line tls-in) "221"))))))

          ;; Verify saved on receiver node ns2
          (let [mail-2 (wait-for-mail (.getAbsolutePath dir2) 3000)]
            (is (= 1 (count mail-2)))
            (let [content (slurp (:file (first mail-2)))]
              (is (.contains content "Subject: E2E Integration Cluster Test"))))

          ;; Verify replicated across cluster to ns1 and ns3
          (let [mail-1 (wait-for-mail (.getAbsolutePath dir1) 3000)
                mail-3 (wait-for-mail (.getAbsolutePath dir3) 3000)]
            (is (= 1 (count mail-1)) "Email replicated to ns1")
            (is (= 1 (count mail-3)) "Email replicated to ns3")
            (let [content-1 (slurp (:file (first mail-1)))
                  content-3 (slurp (:file (first mail-3)))]
              (is (.contains content-1 "Subject: E2E Integration Cluster Test"))
              (is (.contains content-3 "Subject: E2E Integration Cluster Test"))))))

      ;; -----------------------------------------------------------------------
      ;; 5. Health-Aware Multi-A DNS Resolution & Failover Simulation
      ;; -----------------------------------------------------------------------
      (testing "Requirement 5: Health-aware multi-A DNS resolution and failover simulation"
        (let [dns-port-2 (get-in n2 [:dns-server :udp-port])
              query-pkt {:id 2001
                         :qr? false
                         :opcode 0
                         :aa? false
                         :tc? false
                         :rd? true
                         :ra? false
                         :rcode :noerror
                         :questions [{:qname "example.com" :qtype :A :qclass :IN}]
                         :answers []
                         :authority []
                         :additional []}
              resp1 (send-udp-dns-query "127.0.0.1" dns-port-2 query-pkt)]
          (is (= 2001 (:id resp1)))
          (is (= :noerror (:rcode resp1)))
          ;; All 3 healthy nodes (ns1, ns2, ns3) returned in A records
          (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3"} (set (map :rdata (:answers resp1)))))

          ;; Failover simulation: Stop ns1
          (main/stop-node! n1)

          ;; Wait for heartbeat timeout (350ms) so ns2 and ns3 detect ns1 as down and ns2 re-elects itself
          (let [deadline (+ (System/currentTimeMillis) 3000)]
            (loop []
              (when-not (= :ns2 (:leader-id @(:state-atom (:cluster-mgr n2))))
                (when (< (System/currentTimeMillis) deadline)
                  (Thread/sleep 50)
                  (recur)))))

          ;; Verify ns2 re-elected leader under 2-of-3 quorum
          (is (= :leader (:role @(:state-atom (:cluster-mgr n2)))))
          (is (= :ns2 (:leader-id @(:state-atom (:cluster-mgr n2)))))
          (is (= #{:ns2 :ns3} (:healthy-nodes @(:state-atom (:cluster-mgr n2)))))

          ;; Query DNS on ns2 again: should only resolve healthy nodes (10.0.0.2, 10.0.0.3)
          (let [resp2 (send-udp-dns-query "127.0.0.1" dns-port-2 (assoc query-pkt :id 2002))]
            (is (= 2002 (:id resp2)))
            (is (= :noerror (:rcode resp2)))
            (is (= #{"10.0.0.2" "10.0.0.3"} (set (map :rdata (:answers resp2))))))))
      (finally
        ((:stop-fn mock-server))
        (main/stop-node! n1)
        (main/stop-node! n2)
        (main/stop-node! n3)
        (delete-dir-recursively content-dir)
        (delete-dir-recursively dir1)
        (delete-dir-recursively dir2)
        (delete-dir-recursively dir3)))))
