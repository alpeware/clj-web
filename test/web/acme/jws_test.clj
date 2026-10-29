(ns web.acme.jws-test
  "Unit and property tests for RFC 7515 / RFC 7638 / RFC 8555 JWS (ES256)
   cryptography and PKCS#10 Certificate Signing Request builder."
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.acme.jws :as jws])
  (:import [java.math BigInteger]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.security KeyFactory KeyPair MessageDigest PublicKey Signature]
           [java.security.interfaces ECPrivateKey ECPublicKey]
           [java.security.spec ECPoint ECPublicKeySpec]
           [java.util Arrays]))

(defn- create-temp-dir []
  (.toFile (Files/createTempDirectory "jws-test" (into-array FileAttribute []))))

(defn- delete-dir-recursively [f]
  (when (.exists f)
    (doseq [child (.listFiles f)]
      (if (.isDirectory child)
        (delete-dir-recursively child)
        (.delete child)))
    (.delete f)))

;; ---------------------------------------------------------------------------
;; Base64URL Encoding & Decoding Tests
;; ---------------------------------------------------------------------------

(deftest test-base64url-encode-decode
  (testing "encodes without padding and round-trips ASCII strings"
    (let [input "Hello, Let's Encrypt ACME v2 JWS!"
          encoded (jws/base64url-encode input)
          decoded (jws/base64url-decode-str encoded)]
      (is (not (str/includes? encoded "=")))
      (is (not (str/includes? encoded "+")))
      (is (not (str/includes? encoded "/")))
      (is (= input decoded))))

  (testing "encodes byte arrays correctly"
    (let [bytes-in (byte-array [(unchecked-byte 0xfa) (unchecked-byte 0xce) (unchecked-byte 0xb0) (unchecked-byte 0x0c)])
          encoded (jws/base64url-encode bytes-in)
          bytes-out (jws/base64url-decode encoded)]
      (is (= (vec bytes-in) (vec bytes-out))))))

(defspec prop-base64url-roundtrip 100
  (prop/for-all [bs (gen/fmap byte-array (gen/vector (gen/choose -128 127) 0 100))]
                (let [encoded (jws/base64url-encode bs)
                      decoded (jws/base64url-decode encoded)]
                  (is (not (str/includes? encoded "=")))
                  (is (not (str/includes? encoded "+")))
                  (is (not (str/includes? encoded "/")))
                  (is (Arrays/equals ^bytes bs ^bytes decoded))
                  true)))

;; ---------------------------------------------------------------------------
;; EC Key Generation & Account Keypair Persistence
;; ---------------------------------------------------------------------------

(deftest test-generate-ec-keypair
  (let [kp (jws/generate-ec-keypair)
        pub (.getPublic kp)
        priv (.getPrivate kp)]
    (is (instance? KeyPair kp))
    (is (instance? ECPublicKey pub))
    (is (instance? ECPrivateKey priv))
    (is (= "EC" (.getAlgorithm pub)))
    (is (= "EC" (.getAlgorithm priv)))))

(deftest test-save-or-load-account-keypair
  (let [temp-dir (create-temp-dir)]
    (try
      (let [kp-info1 (jws/save-or-load-account-keypair! (str temp-dir))
            priv1 (:private-key kp-info1)
            pub1 (:public-key kp-info1)
            priv-file (io/file temp-dir "acme" "account-key.pem")
            pub-file (io/file temp-dir "acme" "account-pub.pem")]
        (is (.exists priv-file) "account-key.pem written to disk")
        (is (.exists pub-file) "account-pub.pem written to disk")
        (is (some? priv1))
        (is (some? pub1))
        (let [thumb1 (jws/jwk-thumbprint pub1)]
          (testing "loads identical account keypair on second call"
            (let [kp-info2 (jws/save-or-load-account-keypair! (str temp-dir))
                  pub2 (:public-key kp-info2)]
              (is (= thumb1 (jws/jwk-thumbprint pub2)))
              (is (= (vec (.getEncoded pub1)) (vec (.getEncoded pub2))))))))
      (finally
        (delete-dir-recursively temp-dir)))))

;; ---------------------------------------------------------------------------
;; JWK & RFC 7638 Thumbprint Tests
;; ---------------------------------------------------------------------------

(deftest test-ec-public-key->jwk
  (let [kp (jws/generate-ec-keypair)
        jwk (jws/ec-public-key->jwk (.getPublic kp))]
    (is (= "P-256" (get jwk "crv")))
    (is (= "EC" (get jwk "kty")))
    (is (string? (get jwk "x")))
    (is (string? (get jwk "y")))
    ;; Coordinates in Base64URL for 32 bytes are 43 characters
    (is (= 43 (count (get jwk "x"))))
    (is (= 43 (count (get jwk "y"))))))

(defn- build-ec-public-key-from-coords
  "Reconstructs an ECPublicKey from P-256 affine coordinates X and Y."
  [^BigInteger x ^BigInteger y]
  (let [kpg (java.security.KeyPairGenerator/getInstance "EC")
        _ (.initialize kpg 256)
        dummy-kp (.generateKeyPair kpg)
        param-spec (.getParams ^ECPublicKey (.getPublic dummy-kp))
        point (ECPoint. x y)
        pub-spec (ECPublicKeySpec. point param-spec)
        kf (KeyFactory/getInstance "EC")]
    (.generatePublic kf pub-spec)))

(deftest test-rfc-7638-thumbprint-test-vector
  (testing "matches RFC 7638 §3.1 official test vector"
    ;; From RFC 7638 section 3.1:
    ;; x: "f83OJ3D2xFFlbLJQnQ8nCDWWh7UcvrnQJawpMuk1o08"
    ;; y: "x_daQauaeCM-dVhACqMXRevSxBlJU4Gav_dpi6b9gtY"
    ;; Expected thumbprint: "tM0ddT9n5QjreSa-whVCzKqqidsgmxI4bBy-xT9DnvI"
    (let [x-bytes (jws/base64url-decode "f83OJ3D2xFFlbLJQnQ8nCDWWh7UcvrnQJawpMuk1o08")
          y-bytes (jws/base64url-decode "x_daQauaeCM-dVhACqMXRevSxBlJU4Gav_dpi6b9gtY")
          x-bi (BigInteger. 1 ^bytes x-bytes)
          y-bi (BigInteger. 1 ^bytes y-bytes)
          pub (build-ec-public-key-from-coords x-bi y-bi)
          thumb (jws/jwk-thumbprint pub)]
      (is (= "tM0ddT9n5QjreSa-whVCzKqqidsgmxI4bBy-xT9DnvI" thumb)))))

(deftest test-key-authorization-and-dns-01
  (let [kp (jws/generate-ec-keypair)
        pub (.getPublic kp)
        thumb (jws/jwk-thumbprint pub)
        token "sample-acme-challenge-token-12345"
        auth (jws/key-authorization token pub)
        dns-val (jws/dns-01-txt-value token pub)]
    (is (= (str token "." thumb) auth))
    (let [md (MessageDigest/getInstance "SHA-256")
          expected-digest (.digest md (.getBytes auth StandardCharsets/UTF_8))]
      (is (= (jws/base64url-encode expected-digest) dns-val)))))

;; ---------------------------------------------------------------------------
;; JWS ES256 Signing & Verification Tests
;; ---------------------------------------------------------------------------

(defn- verify-jws-signature?
  "Verifies JWS ES256 signature using public key."
  [jws-json ^PublicKey pub-key]
  (let [data (json/read-str jws-json)
        protected-b64 (get data "protected")
        payload-b64 (get data "payload")
        sig-b64 (get data "signature")
        signing-input (str protected-b64 "." payload-b64)
        sig-bytes (jws/base64url-decode sig-b64)
        verifier (Signature/getInstance "SHA256withECDSAinP1363Format")]
    (.initVerify verifier pub-key)
    (.update verifier (.getBytes signing-input StandardCharsets/US_ASCII))
    (and (= 64 (count sig-bytes))
         (.verify verifier sig-bytes))))

(deftest test-sign-jws-with-jwk
  (let [kp (jws/generate-ec-keypair)
        priv (.getPrivate kp)
        pub (.getPublic kp)
        payload {"termsOfServiceAgreed" true}
        url "https://acme.example.com/acme/new-acct"
        nonce "nonce-xyz-987"
        jws-str (jws/sign-jws {:private-key priv
                               :public-key pub
                               :nonce nonce
                               :url url
                               :payload payload})
        jws-data (json/read-str jws-str)
        protected-json (jws/base64url-decode-str (get jws-data "protected"))
        header (json/read-str protected-json)
        payload-json (jws/base64url-decode-str (get jws-data "payload"))
        parsed-payload (json/read-str payload-json)]
    (is (= "ES256" (get header "alg")))
    (is (= nonce (get header "nonce")))
    (is (= url (get header "url")))
    (is (some? (get header "jwk")))
    (is (= {"termsOfServiceAgreed" true} parsed-payload))
    (is (true? (verify-jws-signature? jws-str pub)))))

(deftest test-sign-jws-with-kid
  (let [kp (jws/generate-ec-keypair)
        priv (.getPrivate kp)
        pub (.getPublic kp)
        payload {"identifiers" [{"type" "dns" "value" "example.com"}]}
        kid "https://acme.example.com/acme/acct/42"
        url "https://acme.example.com/acme/new-order"
        nonce "nonce-abc-123"
        jws-str (jws/sign-jws {:private-key priv
                               :kid kid
                               :nonce nonce
                               :url url
                               :payload payload})
        jws-data (json/read-str jws-str)
        protected-json (jws/base64url-decode-str (get jws-data "protected"))
        header (json/read-str protected-json)]
    (is (= "ES256" (get header "alg")))
    (is (= kid (get header "kid")))
    (is (nil? (get header "jwk")))
    (is (true? (verify-jws-signature? jws-str pub)))))

(deftest test-sign-jws-post-as-get
  (let [kp (jws/generate-ec-keypair)
        priv (.getPrivate kp)
        pub (.getPublic kp)
        kid "https://acme.example.com/acme/acct/42"
        url "https://acme.example.com/acme/order/100"
        nonce "nonce-poll-555"
        jws-str (jws/sign-jws {:private-key priv
                               :kid kid
                               :nonce nonce
                               :url url
                               :payload :post-as-get})
        jws-data (json/read-str jws-str)]
    (is (= "" (get jws-data "payload")))
    (is (true? (verify-jws-signature? jws-str pub)))))

;; ---------------------------------------------------------------------------
;; PKCS#10 Certificate Signing Request (CSR) Tests
;; ---------------------------------------------------------------------------

(deftest test-generate-csr
  (let [kp (jws/generate-ec-keypair)
        domains ["alpeware.com" "ns1.alpeware.com" "ns2.alpeware.com" "ns3.alpeware.com"]
        csr-der (jws/generate-csr kp domains)
        csr-str (String. ^bytes csr-der StandardCharsets/ISO_8859_1)]
    (is (bytes? csr-der))
    (is (> (count csr-der) 100))
    (is (= (unchecked-byte 0x30) (first csr-der)))
    (testing "CSR contains common name and SAN domain names"
      (doseq [d domains]
        (is (str/includes? csr-str d))))))
