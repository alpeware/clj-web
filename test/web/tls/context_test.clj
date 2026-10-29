(ns web.tls.context-test
  "Unit tests for TLS certificate generation, PEM encoding/parsing,
   atomic persistence, and hot-swappable SSLContext management."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [web.tls.context :as tls])
  (:import [com.sun.net.httpserver HttpsConfigurator]
           [java.io File]
           [java.nio.file Files]
           [java.security PrivateKey]
           [java.security.cert X509Certificate]
           [javax.net.ssl SSLContext]))

(defn- delete-dir-recursively! [^File f]
  (when (.isDirectory f)
    (doseq [child (.listFiles f)]
      (delete-dir-recursively! child)))
  (.delete f))

(defn- with-temp-state-dir [f]
  (let [dir (.toFile (Files/createTempDirectory "clj-web-tls-test" (into-array java.nio.file.attribute.FileAttribute [])))]
    (try
      (f dir)
      (finally
        (delete-dir-recursively! dir)))))

(deftest test-generate-self-signed-cert
  (testing "Generates valid unexpired ECDSA P-256 certificate"
    (let [bundle (tls/generate-self-signed-cert "example.com" 30)
          cert ^X509Certificate (:certificate bundle)
          key ^PrivateKey (:private-key bundle)
          now (System/currentTimeMillis)]
      (is (instance? X509Certificate cert))
      (is (instance? PrivateKey key))
      (is (= "EC" (.getAlgorithm key)))
      (is (true? (:self-signed? bundle)))
      (is (= 1 (count (:certificates bundle))))
      (is (identical? cert (first (:certificates bundle))))
      (is (<= now (:expires-at bundle)))
      (is (.contains (.getName (.getSubjectX500Principal cert)) "CN=example.com"))
      ;; Verify cert is currently valid (checkValidity throws if invalid)
      (is (nil? (.checkValidity cert))))))

(deftest test-pem-encode-and-parse-roundtrip
  (testing "Certificate PEM encode/decode round-trip"
    (let [bundle (tls/generate-self-signed-cert "test.domain.org" 10)
          cert (first (:certificates bundle))
          pem (tls/encode-cert-pem cert)
          parsed-chain (tls/parse-cert-chain-pem pem)]
      (is (.startsWith pem "-----BEGIN CERTIFICATE-----"))
      (is (.contains pem "-----END CERTIFICATE-----"))
      (is (= 1 (count parsed-chain)))
      (is (= (seq (.getEncoded cert))
             (seq (.getEncoded ^X509Certificate (first parsed-chain)))))))

  (testing "Multiple certificates chain PEM encode/decode"
    (let [bundle1 (tls/generate-self-signed-cert "node1.domain.org" 10)
          bundle2 (tls/generate-self-signed-cert "node2.domain.org" 10)
          certs [(:certificate bundle1) (:certificate bundle2)]
          chain-pem (tls/encode-cert-chain-pem certs)
          parsed (tls/parse-cert-chain-pem chain-pem)]
      (is (= 2 (count parsed)))
      (is (= (seq (.getEncoded ^X509Certificate (first certs)))
             (seq (.getEncoded ^X509Certificate (first parsed)))))
      (is (= (seq (.getEncoded ^X509Certificate (second certs)))
             (seq (.getEncoded ^X509Certificate (second parsed)))))))

  (testing "Private key PEM encode/decode round-trip"
    (let [bundle (tls/generate-self-signed-cert "key.domain.org" 10)
          key (:private-key bundle)
          pem (tls/encode-private-key-pem key)
          parsed-key (tls/parse-private-key-pem pem)]
      (is (.startsWith pem "-----BEGIN PRIVATE KEY-----"))
      (is (.contains pem "-----END PRIVATE KEY-----"))
      (is (instance? PrivateKey parsed-key))
      (is (= "EC" (.getAlgorithm parsed-key)))
      (is (= (seq (.getEncoded key))
             (seq (.getEncoded parsed-key)))))))

(deftest test-build-ssl-context
  (testing "Builds functioning SSLContext from certs and private key"
    (let [bundle (tls/generate-self-signed-cert "ssl.domain.org" 15)
          ssl-ctx (tls/build-ssl-context (:certificates bundle) (:private-key bundle))]
      (is (instance? SSLContext ssl-ctx))
      (is (some? (.getServerSocketFactory ssl-ctx)))
      (is (some? (.getSocketFactory ssl-ctx))))))

(deftest test-save-and-load-tls-bundle
  (with-temp-state-dir
    (fn [^File state-dir]
      (let [state-dir-str (.getAbsolutePath state-dir)]
        (testing "Missing files return nil"
          (is (nil? (tls/load-tls-bundle state-dir-str))))

        (testing "Saves and loads bundle atomically"
          (let [bundle (tls/generate-self-signed-cert "save.domain.org" 20)
                cert-pem (tls/encode-cert-chain-pem (:certificates bundle))
                key-pem (tls/encode-private-key-pem (:private-key bundle))]
            (tls/save-tls-bundle! state-dir-str cert-pem key-pem)
            (let [fullchain (io/file state-dir "certs" "fullchain.pem")
                  privkey (io/file state-dir "certs" "privkey.pem")]
              (is (.exists fullchain))
              (is (.exists privkey)))

            (let [loaded (tls/load-tls-bundle state-dir-str)]
              (is (some? loaded))
              (is (false? (:self-signed? loaded)))
              (is (= 1 (count (:certificates loaded))))
              (is (instance? PrivateKey (:private-key loaded)))
              (is (= cert-pem (:cert-pem loaded)))
              (is (= key-pem (:key-pem loaded)))
              (is (<= (abs (- (:expires-at bundle) (:expires-at loaded))) 1000)))))))))

(deftest test-init-and-update-tls-manager
  (with-temp-state-dir
    (fn [^File state-dir]
      (let [state-dir-str (.getAbsolutePath state-dir)
            cfg {:domain "cold.domain.org" :state-dir state-dir-str}
            mgr (tls/init-tls-manager! cfg)
            bundle @(:bundle-atom mgr)
            ssl-ctx @(:ssl-context-atom mgr)]
        (testing "Cold bootstrap creates self-signed cert"
          (is (true? (:self-signed? bundle)))
          (is (instance? SSLContext ssl-ctx))
          (is (= "cold.domain.org" (:domain mgr)))
          (is (= state-dir-str (:state-dir mgr))))

        (testing "Update bundle swaps SSLContext and persists to disk"
          (let [new-gen (tls/generate-self-signed-cert "renewed.domain.org" 60)
                new-cert-pem (tls/encode-cert-chain-pem (:certificates new-gen))
                new-key-pem (tls/encode-private-key-pem (:private-key new-gen))]
            (tls/update-tls-bundle! mgr new-cert-pem new-key-pem)

            (let [updated-bundle @(:bundle-atom mgr)
                  updated-ctx @(:ssl-context-atom mgr)]
              (is (false? (:self-signed? updated-bundle)))
              (is (not (identical? ssl-ctx updated-ctx)))
              (is (= new-cert-pem (:cert-pem updated-bundle)))
              (is (= new-key-pem (:key-pem updated-bundle)))

              ;; Verify disk bundle matches update
              (let [disk-bundle (tls/load-tls-bundle state-dir-str)]
                (is (some? disk-bundle))
                (is (= new-cert-pem (:cert-pem disk-bundle)))))))

        (testing "Warm boot loads persisted bundle without generating self-signed cert"
          (let [warm-mgr (tls/init-tls-manager! cfg)
                warm-bundle @(:bundle-atom warm-mgr)]
            (is (false? (:self-signed? warm-bundle)))
            (is (some? (:cert-pem warm-bundle)))))))))

(deftest test-make-https-configurator
  (let [bundle1 (tls/generate-self-signed-cert "cfg1.domain.org" 10)
        bundle2 (tls/generate-self-signed-cert "cfg2.domain.org" 10)
        ctx1 (tls/build-ssl-context (:certificates bundle1) (:private-key bundle1))
        ctx2 (tls/build-ssl-context (:certificates bundle2) (:private-key bundle2))
        ctx-atom (atom ctx1)
        configurator (tls/make-https-configurator ctx-atom)]
    (is (instance? HttpsConfigurator configurator))
    (is (identical? ctx1 (.getSSLContext configurator)))
    (reset! ctx-atom ctx2)
    (is (identical? ctx2 (.getSSLContext configurator)))))
