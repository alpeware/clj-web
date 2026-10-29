(ns web.tls.context
  "TLS certificate generation, PEM encode/decode, atomic disk storage,
   in-memory SSLContext management, and zero-downtime hot reload."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [com.sun.net.httpserver HttpsConfigurator HttpsParameters]
           [java.io ByteArrayInputStream File]
           [java.net Socket]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.security KeyFactory KeyStore PrivateKey SecureRandom Signature]
           [java.security.cert CertificateFactory X509Certificate]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.util Base64 Date]
           [javax.net.ssl KeyManager SSLEngine SSLContext TrustManagerFactory X509ExtendedKeyManager]))

(def ^:private mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII)))

(defn generate-self-signed-cert
  "Generates a self-signed ECDSA (P-256) X.509 certificate and private key
   using sun.security.tools.keytool.CertAndKeyGen with Subject Alternative Names."
  ([domain] (generate-self-signed-cert domain 30))
  ([domain validity-days]
   (let [c (sun.security.tools.keytool.CertAndKeyGen. "EC" "SHA256withECDSA")
         validity-secs (* (long (or validity-days 30)) 86400)]
     (.generate c 256)
     (let [x500 (sun.security.x509.X500Name. (str "CN=" domain))
           exts (sun.security.x509.CertificateExtensions.)
           gn (sun.security.x509.GeneralNames.)
           _ (when (and domain (not (str/starts-with? domain "*")))
               (try
                 (.add gn (sun.security.x509.GeneralName. (sun.security.x509.DNSName. domain)))
                 (catch Exception _ nil)))
           _ (.add gn (sun.security.x509.GeneralName. (sun.security.x509.DNSName. "localhost")))
           _ (.add gn (sun.security.x509.GeneralName. (sun.security.x509.IPAddressName. "127.0.0.1")))
           san-ext (sun.security.x509.SubjectAlternativeNameExtension. gn)
           _ (.setExtension exts (sun.security.x509.SubjectAlternativeNameExtension/NAME) san-ext)
           now (Date.)
           cert (.getSelfCertificate c x500 now validity-secs exts)
           priv-key (.getPrivateKey c)]
       {:certificate cert
        :certificates [cert]
        :private-key priv-key
        :expires-at (.getTime (.getNotAfter cert))
        :self-signed? true}))))

(defn encode-cert-pem
  "Serializes an X509Certificate to standard PEM format string."
  [^X509Certificate cert]
  (str "-----BEGIN CERTIFICATE-----\n"
       (.encodeToString mime-encoder (.getEncoded cert))
       "\n-----END CERTIFICATE-----\n"))

(defn encode-cert-chain-pem
  "Serializes a sequence of X509Certificates to standard PEM chain string."
  [certs]
  (str/join "\n" (map encode-cert-pem certs)))

(defn encode-private-key-pem
  "Serializes a PKCS#8 PrivateKey to standard PEM format string."
  [^PrivateKey k]
  (str "-----BEGIN PRIVATE KEY-----\n"
       (.encodeToString mime-encoder (.getEncoded k))
       "\n-----END PRIVATE KEY-----\n"))

(defn parse-cert-chain-pem
  "Parses one or more X.509 certificates from a PEM string into a vector of X509Certificate."
  [pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cf (CertificateFactory/getInstance "X.509")
          in (ByteArrayInputStream. (.getBytes ^String pem-str StandardCharsets/US_ASCII))]
      (vec (.generateCertificates cf in)))))

(defn parse-private-key-pem
  "Parses a PKCS#8 PrivateKey from a PEM string (EC with fallback to RSA)."
  [pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cleaned (-> pem-str
                      (str/replace #"-----BEGIN [A-Z ]+-----" "")
                      (str/replace #"-----END [A-Z ]+-----" "")
                      (str/replace #"\s+" ""))
          decoder (Base64/getDecoder)
          key-bytes (.decode decoder ^String cleaned)
          spec (PKCS8EncodedKeySpec. key-bytes)]
      (try
        (let [kf (KeyFactory/getInstance "EC")]
          (.generatePrivate kf spec))
        (catch Exception _
          (let [kf (KeyFactory/getInstance "RSA")]
            (.generatePrivate kf spec)))))))

(defn make-dynamic-key-manager
  "Creates an X509ExtendedKeyManager proxy that delegates to bundle-atom on every handshake."
  [bundle-atom]
  (proxy [X509ExtendedKeyManager] []
    (chooseEngineServerAlias [_key-type _issuers ^SSLEngine _engine]
      "node-key")
    (chooseServerAlias [_key-type _issuers ^Socket _socket]
      "node-key")
    (getCertificateChain [alias]
      (when (= alias "node-key")
        (let [b (if (instance? clojure.lang.IDeref bundle-atom) @bundle-atom bundle-atom)]
          (into-array X509Certificate (:certificates b)))))
    (getPrivateKey [alias]
      (when (= alias "node-key")
        (let [b (if (instance? clojure.lang.IDeref bundle-atom) @bundle-atom bundle-atom)]
          ^PrivateKey (:private-key b))))
    (getServerAliases [_key-type _issuers]
      (into-array String ["node-key"]))
    (getClientAliases [_key-type _issuers]
      (into-array String []))
    (chooseClientAlias [_key-types _issuers ^Socket _socket]
      nil)
    (chooseEngineClientAlias [_key-types _issuers ^SSLEngine _engine]
      nil)))

(defn build-ssl-context
  "Builds an initialized SSLContext for TLS using dynamic or static key bundle."
  ([certs ^PrivateKey private-key]
   (build-ssl-context (atom {:certificates certs :private-key private-key})))
  ([bundle-atom]
   (let [kmf-key-mgr (make-dynamic-key-manager bundle-atom)
         tmf (TrustManagerFactory/getInstance (TrustManagerFactory/getDefaultAlgorithm))]
     (try
       (.init tmf (KeyStore/getInstance (KeyStore/getDefaultType)))
       (catch Exception _
         (let [ks (KeyStore/getInstance "PKCS12")]
           (.load ks nil (char-array "pass"))
           (.init tmf ks))))
     (let [ssl-ctx (SSLContext/getInstance "TLS")]
       (.init ssl-ctx (into-array KeyManager [kmf-key-mgr]) (.getTrustManagers tmf) (SecureRandom.))
       ssl-ctx))))

(defn- cert-covers-domain?
  [^X509Certificate cert ^String expected-domain]
  (let [expected (str/lower-case (str/trim expected-domain))
        sans (try
               (when-let [alt-names (.getSubjectAlternativeNames cert)]
                 (keep (fn [entry]
                         (when (= (first entry) 2)
                           (str/lower-case (str (second entry)))))
                       alt-names))
               (catch Exception _ nil))
        cn (try
             (let [dn (.getName (.getSubjectX500Principal cert))]
               (when-let [[_ cn-val] (re-find #"(?i)CN=([^,]+)" dn)]
                 (str/lower-case (str/trim cn-val))))
             (catch Exception _ nil))
        names (set (concat sans (when cn [cn])))]
    (boolean
     (or (contains? names expected)
         (some (fn [pattern]
                 (when (str/starts-with? pattern "*.")
                   (let [suffix (subs pattern 1)]
                     (and (> (count expected) (count suffix))
                          (str/ends-with? expected suffix)
                          (let [prefix (subs expected 0 (- (count expected) (count suffix)))]
                            (and (pos? (count prefix))
                                 (not (str/includes? prefix "."))))))))
               names)))))

(defn validate-tls-bundle!
  "Validates a TLS certificate chain and private key:
   - Verifies certs and priv-key are present.
   - Verifies leaf cert is not expired and within valid time window.
   - Verifies priv-key mathematically matches leaf certificate public key via signing.
   - Verifies cert covers expected-domain (if non-blank) adhering to RFC 6125 §6.4.3 single-level wildcard matching.
   - Verifies certificate chain signatures if multiple certs are provided (child signed by issuer).
   Trusts the authenticated DTLS cluster leader or configured ACME CA as the root trust anchor
   rather than pinning a static root CA store (allowing Let's Encrypt staging, custom ACME roots,
   and local self-signed certs).
   Throws ex-info on any validation failure."
  [certs ^PrivateKey priv-key expected-domain]
  (when (or (empty? certs) (nil? priv-key))
    (throw (ex-info "Missing TLS certificates or private key"
                    {:certs (count certs) :has-key? (some? priv-key)})))
  (let [^X509Certificate leaf (first certs)
        now (System/currentTimeMillis)
        not-after (.getTime (.getNotAfter leaf))
        not-before (.getTime (.getNotBefore leaf))]
    ;; Expiration check (with 5-minute clock skew margin on not-before)
    (when (or (<= not-after now)
              (>= not-before (+ now 300000)))
      (throw (ex-info "Leaf certificate is expired or not yet valid"
                      {:not-after not-after :not-before not-before :now now})))
    ;; Keypair match check
    (let [pub-key (.getPublicKey leaf)
          sig-alg (if (= (.getAlgorithm priv-key) "RSA") "SHA256withRSA" "SHA256withECDSA")
          challenge (.getBytes "clj-web-tls-verification-challenge" StandardCharsets/UTF_8)]
      (try
        (let [signer (Signature/getInstance sig-alg)
              verifier (Signature/getInstance sig-alg)]
          (.initSign signer priv-key)
          (.update signer challenge)
          (let [sig (.sign signer)]
            (.initVerify verifier pub-key)
            (.update verifier challenge)
            (when-not (.verify verifier sig)
              (throw (ex-info "Private key signature verification failed"
                              {:key-algo (.getAlgorithm priv-key)})))))
        (catch clojure.lang.ExceptionInfo e (throw e))
        (catch Exception e
          (throw (ex-info (str "Private key does not match certificate public key: " (.getMessage e))
                          {:key-algo (.getAlgorithm priv-key)
                           :cert-algo (.getAlgorithm pub-key)}
                          e)))))
    ;; Domain coverage check
    (when (and (string? expected-domain) (not (str/blank? expected-domain)))
      (when-not (cert-covers-domain? leaf expected-domain)
        (throw (ex-info (str "Certificate does not cover expected domain: " expected-domain)
                        {:expected-domain expected-domain
                         :subject (.getName (.getSubjectX500Principal leaf))}))))
    ;; Chain verification check
    (when (> (count certs) 1)
      (doseq [[^X509Certificate child ^X509Certificate issuer] (partition 2 1 certs)]
        (try
          (.verify child (.getPublicKey issuer))
          (catch Exception e
            (throw (ex-info (str "Certificate chain verification failed: " (.getMessage e))
                            {:child (.getName (.getSubjectX500Principal child))
                             :issuer (.getName (.getSubjectX500Principal issuer))}
                            e))))))
    true))

(defn save-tls-bundle!
  "Atomically saves cert-pem to <state-dir>/certs/fullchain.pem, key-pem
   to <state-dir>/certs/privkey.pem, and atomic pair to <state-dir>/certs/bundle.edn
   using atomic moves with temporary files."
  [state-dir cert-pem key-pem]
  (let [certs-dir (io/file state-dir "certs")]
    (.mkdirs certs-dir)
    (let [fullchain-file (io/file certs-dir "fullchain.pem")
          privkey-file (io/file certs-dir "privkey.pem")
          bundle-file (io/file certs-dir "bundle.edn")
          tmp-cert (File/createTempFile "fullchain" ".tmp" certs-dir)
          tmp-key (File/createTempFile "privkey" ".tmp" certs-dir)
          tmp-bundle (File/createTempFile "bundle" ".tmp" certs-dir)]
      (spit tmp-cert cert-pem)
      (spit tmp-key key-pem)
      (spit tmp-bundle (pr-str {:cert-pem cert-pem :key-pem key-pem}))
      (try
        (Files/setPosixFilePermissions (.toPath tmp-key) (PosixFilePermissions/fromString "rw-------"))
        (catch UnsupportedOperationException _ nil))
      (try
        (Files/setPosixFilePermissions (.toPath tmp-bundle) (PosixFilePermissions/fromString "rw-------"))
        (catch UnsupportedOperationException _ nil))
      (try
        (Files/move (.toPath tmp-cert) (.toPath fullchain-file)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                          StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move (.toPath tmp-cert) (.toPath fullchain-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
      (try
        (Files/move (.toPath tmp-key) (.toPath privkey-file)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                          StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move (.toPath tmp-key) (.toPath privkey-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
      (try
        (Files/move (.toPath tmp-bundle) (.toPath bundle-file)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                          StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move (.toPath tmp-bundle) (.toPath bundle-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING])))))))

(defn load-tls-bundle
  "Loads TLS bundle from <state-dir>/certs/ if valid, returning nil if missing or invalid.
   Optionally validates leaf certificate covers expected-domain."
  ([state-dir]
   (load-tls-bundle state-dir nil))
  ([state-dir expected-domain]
   (let [certs-dir (io/file state-dir "certs")
         fullchain-file (io/file certs-dir "fullchain.pem")
         privkey-file (io/file certs-dir "privkey.pem")
         bundle-file (io/file certs-dir "bundle.edn")
         load-pems (fn [cert-pem key-pem]
                     (when (and cert-pem key-pem)
                       (let [certs (parse-cert-chain-pem cert-pem)
                             priv-key (parse-private-key-pem key-pem)]
                         (when (and (seq certs) priv-key)
                           (validate-tls-bundle! certs priv-key expected-domain)
                           {:certificates certs
                            :private-key priv-key
                            :cert-pem cert-pem
                            :key-pem key-pem
                            :expires-at (.getTime (.getNotAfter ^X509Certificate (first certs)))
                            :self-signed? false}))))]
     (or
       ;; Primary: try fullchain.pem + privkey.pem
      (when (and (.exists fullchain-file) (.exists privkey-file))
        (try
          (load-pems (slurp fullchain-file) (slurp privkey-file))
          (catch Exception e
            (binding [*out* *err*]
              (println (str "Warning: Failed to load TLS bundle from pem files: " (.getMessage e))))
            nil)))
       ;; Fallback: try bundle.edn (e.g. if crash occurred between the two PEM moves)
      (when (.exists bundle-file)
        (try
          (let [data (edn/read-string (slurp bundle-file))]
            (load-pems (:cert-pem data) (:key-pem data)))
          (catch Exception e
            (binding [*out* *err*]
              (println (str "Warning: Failed to load TLS bundle from bundle.edn: " (.getMessage e))))
            nil)))))))

(defn init-tls-manager!
  "Initializes the TLS manager. Loads bundle from disk if available and unexpired;
   otherwise generates an ephemeral self-signed certificate for cold bootstrap.
   Returns map with :ssl-context-atom, :bundle-atom, :state-dir, and :domain."
  [config]
  (let [state-dir (:state-dir config)
        domain (:domain config)
        disk-bundle (load-tls-bundle state-dir domain)
        now (System/currentTimeMillis)
        bundle (if (and disk-bundle (> (:expires-at disk-bundle) now))
                 disk-bundle
                 (generate-self-signed-cert domain 30))
        bundle-atom (atom bundle)
        ssl-ctx (build-ssl-context bundle-atom)]
    {:ssl-context-atom (atom ssl-ctx)
     :bundle-atom bundle-atom
     :state-dir state-dir
     :domain domain}))

(defn update-tls-bundle!
  "Atomically updates and reloads the TLS bundle across memory and disk."
  [tls-manager cert-pem key-pem]
  (let [certs (parse-cert-chain-pem cert-pem)
        priv-key (parse-private-key-pem key-pem)]
    (when (or (empty? certs) (nil? priv-key))
      (throw (ex-info "Invalid TLS certificate or key PEM" {:certs (count certs) :key (some? priv-key)})))
    (validate-tls-bundle! certs priv-key (:domain tls-manager))
    (save-tls-bundle! (:state-dir tls-manager) cert-pem key-pem)
    (let [new-bundle {:certificates certs
                      :private-key priv-key
                      :cert-pem cert-pem
                      :key-pem key-pem
                      :expires-at (.getTime (.getNotAfter ^X509Certificate (first certs)))
                      :self-signed? false}]
      (reset! (:bundle-atom tls-manager) new-bundle)
      (reset! (:ssl-context-atom tls-manager) (build-ssl-context (:bundle-atom tls-manager)))
      tls-manager)))

(defn make-https-configurator
  "Creates an HttpsConfigurator proxy that queries @ssl-context-atom on every connection."
  [ssl-context-atom]
  (proxy [HttpsConfigurator] [@ssl-context-atom]
    (getSSLContext []
      @ssl-context-atom)
    (configure [^HttpsParameters params]
      (let [^SSLContext ctx @ssl-context-atom
            ssl-params (.getDefaultSSLParameters ctx)]
        (.setProtocols ssl-params (into-array String ["TLSv1.3" "TLSv1.2"]))
        (.setSSLParameters params ssl-params)))))
