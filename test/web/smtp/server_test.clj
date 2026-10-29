(ns web.smtp.server-test
  "Live integration tests for Inbound SMTP server on TCP port 25 with STARTTLS socket upgrade,
   open-relay prevention, atomic .eml persistence, and cluster replication callback."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [web.smtp.server :as smtp]
            [web.tls.context :as tls])
  (:import [java.io BufferedReader BufferedWriter File InputStreamReader OutputStreamWriter]
           [java.net ServerSocket Socket]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.security SecureRandom]
           [java.security.cert X509Certificate]
           [javax.net.ssl SSLContext TrustManager X509TrustManager]))

(defn- find-free-port []
  (with-open [s (ServerSocket. 0)]
    (.getLocalPort s)))

(defn- delete-dir-recursively! [^File f]
  (when (.isDirectory f)
    (doseq [child (.listFiles f)]
      (delete-dir-recursively! child)))
  (.delete f))

(defn- with-temp-state-dir [f]
  (let [dir (.toFile (Files/createTempDirectory "clj-web-smtp-test" (into-array java.nio.file.attribute.FileAttribute [])))]
    (try
      (f dir)
      (finally
        (delete-dir-recursively! dir)))))

(def ^:private trust-all-managers
  (into-array TrustManager
              [(reify X509TrustManager
                 (getAcceptedIssuers [_] (into-array X509Certificate []))
                 (checkClientTrusted [_ _ _])
                 (checkServerTrusted [_ _ _]))]))

(defn- make-trusting-ssl-context []
  (doto (SSLContext/getInstance "TLS")
    (.init nil trust-all-managers (SecureRandom.))))

(deftest test-save-and-list-eml
  (with-temp-state-dir
    (fn [^File state-dir]
      (let [state-dir-str (.getAbsolutePath state-dir)
            mail-info {:from "alice@sender.org"
                       :to ["admin@example.com"]
                       :helo "client.sender.org"
                       :remote-ip "192.168.1.10"
                       :domain "example.com"
                       :raw-eml "Subject: Test\r\n\r\nHello World\r\n"}
            saved (smtp/save-eml! state-dir-str mail-info)]
        (testing "Saves .eml file atomically with Received: header"
          (is (some? (:id saved)))
          (is (.exists ^File (:file saved)))
          (let [content (slurp (:file saved))]
            (is (str/starts-with? content "Received: from client.sender.org ([192.168.1.10])"))
            (is (.contains content "by example.com with ESMTP"))
            (is (.contains content "Subject: Test"))
            (is (.contains content "Hello World"))))

        (testing "list-emails returns saved file"
          (let [emails (smtp/list-emails state-dir-str)]
            (is (= 1 (count emails)))
            (is (= (.getName ^File (:file saved)) (:name (first emails))))))))))

(defn- read-smtp-line [^BufferedReader reader]
  (.readLine reader))

(defn- write-smtp-line [^BufferedWriter writer line]
  (.write writer (str line "\r\n"))
  (.flush writer))

(deftest test-live-smtp-server-with-starttls
  (with-temp-state-dir
    (fn [^File state-dir]
      (let [port (find-free-port)
            state-dir-str (.getAbsolutePath state-dir)
            domain "example.com"
            allowed #{"admin@example.com" "security@example.com"}
            cfg {:domain domain
                 :state-dir state-dir-str
                 :smtp {:bind-ip "127.0.0.1"
                        :port port
                        :socket-timeout-ms 10000
                        :max-message-bytes 65536
                        :allowed-recipients allowed}}
            tls-mgr (tls/init-tls-manager! cfg)
            received-atom (atom nil)
            server (smtp/start-smtp-server! cfg tls-mgr {:on-mail-received (fn [m] (reset! received-atom m))})]
        (try
          (with-open [raw-sock (Socket. "127.0.0.1" port)]
            (.setSoTimeout raw-sock 5000)
            (let [raw-in (BufferedReader. (InputStreamReader. (.getInputStream raw-sock) StandardCharsets/UTF_8))
                  raw-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream raw-sock) StandardCharsets/UTF_8))]

              ;; 1. Greeting banner
              (let [banner (read-smtp-line raw-in)]
                (is (.startsWith banner "220 example.com ESMTP clj-web ready")))

              ;; 2. Plaintext EHLO
              (write-smtp-line raw-out "EHLO client.sender.org")
              (let [l1 (read-smtp-line raw-in)
                    l2 (read-smtp-line raw-in)
                    l3 (read-smtp-line raw-in)
                    l4 (read-smtp-line raw-in)]
                (is (= "250-example.com" l1))
                (is (= "250-STARTTLS" l2))
                (is (= "250-SIZE 65536" l3))
                (is (= "250 8BITMIME" l4)))

              ;; 3. STARTTLS request
              (write-smtp-line raw-out "STARTTLS")
              (let [tls-resp (read-smtp-line raw-in)]
                (is (= "220 2.0.0 Ready to start TLS" tls-resp)))

              ;; 4. Upgrade client socket to SSLSocket
              (let [ssl-ctx (make-trusting-ssl-context)
                    factory (.getSocketFactory ssl-ctx)
                    ssl-sock (.createSocket factory raw-sock "127.0.0.1" port true)]
                (.setUseClientMode ssl-sock true)
                (.setEnabledProtocols ssl-sock (into-array String ["TLSv1.3" "TLSv1.2"]))
                (.setSoTimeout ssl-sock 5000)
                (.startHandshake ssl-sock)

                (let [tls-in (BufferedReader. (InputStreamReader. (.getInputStream ssl-sock) StandardCharsets/UTF_8))
                      tls-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream ssl-sock) StandardCharsets/UTF_8))]

                  ;; 5. Post-TLS EHLO (STARTTLS should now be omitted)
                  (write-smtp-line tls-out "EHLO client.sender.org")
                  (let [l1 (read-smtp-line tls-in)
                        l2 (read-smtp-line tls-in)
                        l3 (read-smtp-line tls-in)]
                    (is (= "250-example.com" l1))
                    (is (= "250-SIZE 65536" l2))
                    (is (= "250 8BITMIME" l3)))

                  ;; 6. MAIL FROM
                  (write-smtp-line tls-out "MAIL FROM:<alice@sender.org>")
                  (is (= "250 2.1.0 OK" (read-smtp-line tls-in)))

                  ;; 7. Open-relay check: disallowed recipient rejected
                  (write-smtp-line tls-out "RCPT TO:<victim@disallowed.com>")
                  (is (= "550 5.7.1 Relay access denied" (read-smtp-line tls-in)))

                  ;; 8. Allowed recipient accepted
                  (write-smtp-line tls-out "RCPT TO:<admin@example.com>")
                  (is (= "250 2.1.5 OK" (read-smtp-line tls-in)))

                  ;; 9. DATA transmission
                  (write-smtp-line tls-out "DATA")
                  (is (.startsWith (read-smtp-line tls-in) "354 Start mail input"))

                  (write-smtp-line tls-out "From: alice@sender.org")
                  (write-smtp-line tls-out "To: admin@example.com")
                  (write-smtp-line tls-out "Subject: Test Inbound Email with STARTTLS")
                  (write-smtp-line tls-out "")
                  (write-smtp-line tls-out "Hello from encrypted SMTP!")
                  (write-smtp-line tls-out "..Leading dot line")
                  (write-smtp-line tls-out ".")

                  (is (= "250 2.0.0 OK: queued" (read-smtp-line tls-in)))

                  ;; 10. QUIT
                  (write-smtp-line tls-out "QUIT")
                  (is (= "221 2.0.0 Bye" (read-smtp-line tls-in)))

                  ;; Verify disk persistence and replication callback
                  (let [emails (smtp/list-emails state-dir-str)]
                    (is (= 1 (count emails)))
                    (let [content (slurp (:file (first emails)))]
                      (is (.contains content "Subject: Test Inbound Email with STARTTLS"))
                      (is (.contains content ".Leading dot line"))
                      (is (.contains content "Hello from encrypted SMTP!"))))

                  (is (some? @received-atom))
                  (is (= "alice@sender.org" (:from @received-atom)))
                  (is (= ["admin@example.com"] (:to @received-atom)))))))
          (finally
            (smtp/stop-smtp-server! server)))))))
