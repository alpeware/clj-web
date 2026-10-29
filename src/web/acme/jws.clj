(ns web.acme.jws
  "Pure-JDK cryptography and RFC 7515 / RFC 7638 / RFC 8555 JWS (ES256)
   plus PKCS#10 Certificate Signing Request builder using java.security,
   org.clojure/data.json, and sun.security.x509."
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [web.tls.context :as tls])
  (:import [java.io File]
           [java.math BigInteger]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files StandardCopyOption]
           [java.security KeyFactory KeyPair KeyPairGenerator MessageDigest PrivateKey PublicKey Signature]
           [java.security.interfaces ECPublicKey]
           [java.security.spec X509EncodedKeySpec]
           [java.util Base64]
           [sun.security.x509 X500Name]))

;; ---------------------------------------------------------------------------
;; Base64URL Encoding & Decoding (RFC 4648 §5, without padding)
;; ---------------------------------------------------------------------------

(def ^:private base64url-encoder
  (.withoutPadding (Base64/getUrlEncoder)))

(def ^:private base64url-decoder
  (Base64/getUrlDecoder))

(defn base64url-encode
  "Encodes a byte array or String to RFC 4648 §5 Base64URL without padding."
  [data]
  (let [^bytes bs (cond
                    (bytes? data) data
                    (string? data) (.getBytes ^String data StandardCharsets/UTF_8)
                    :else (byte-array data))]
    (.encodeToString base64url-encoder bs)))

(defn base64url-decode
  "Decodes an RFC 4648 §5 Base64URL string to a byte array."
  [^String s]
  (.decode base64url-decoder s))

(defn base64url-decode-str
  "Decodes an RFC 4648 §5 Base64URL string to a UTF-8 String."
  [^String s]
  (String. (base64url-decode s) StandardCharsets/UTF_8))

;; ---------------------------------------------------------------------------
;; Key Generation & Public/Private PEM Persistence
;; ---------------------------------------------------------------------------

(defn generate-ec-keypair
  "Generates an ECDSA secp256r1 (P-256) KeyPair via KeyPairGenerator."
  []
  (let [kpg (KeyPairGenerator/getInstance "EC")]
    (.initialize kpg 256)
    (.generateKeyPair kpg)))

(defn encode-public-key-pem
  "Serializes a PublicKey (SubjectPublicKeyInfo) to standard PEM format string."
  [^PublicKey pub]
  (let [mime-encoder (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII))]
    (str "-----BEGIN PUBLIC KEY-----\n"
         (.encodeToString mime-encoder (.getEncoded pub))
         "\n-----END PUBLIC KEY-----\n")))

(defn parse-public-key-pem
  "Parses an X.509 SubjectPublicKeyInfo from a PEM string (EC)."
  [^String pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cleaned (-> pem-str
                      (str/replace #"-----BEGIN [A-Z ]+-----" "")
                      (str/replace #"-----END [A-Z ]+-----" "")
                      (str/replace #"\s+" ""))
          bytes (.decode (Base64/getDecoder) ^String cleaned)
          spec (X509EncodedKeySpec. bytes)
          kf (KeyFactory/getInstance "EC")]
      (.generatePublic kf spec))))

(defn save-or-load-account-keypair!
  "Loads or creates and atomically persists the ACME account EC keypair
   at <state-dir>/acme/account-key.pem and <state-dir>/acme/account-pub.pem.
   Returns {:private-key priv :public-key pub :keypair (KeyPair. pub priv)}."
  [state-dir]
  (let [acme-dir (io/file state-dir "acme")
        _ (.mkdirs acme-dir)
        priv-file (io/file acme-dir "account-key.pem")
        pub-file (io/file acme-dir "account-pub.pem")]
    (if (and (.exists priv-file) (.exists pub-file))
      (let [priv (tls/parse-private-key-pem (slurp priv-file))
            pub (parse-public-key-pem (slurp pub-file))]
        {:private-key priv
         :public-key pub
         :keypair (KeyPair. pub priv)})
      (let [kp (generate-ec-keypair)
            priv (.getPrivate kp)
            pub (.getPublic kp)
            priv-pem (tls/encode-private-key-pem priv)
            pub-pem (encode-public-key-pem pub)
            tmp-priv (File/createTempFile "acc-priv" ".tmp" acme-dir)
            tmp-pub (File/createTempFile "acc-pub" ".tmp" acme-dir)]
        (spit tmp-priv priv-pem)
        (spit tmp-pub pub-pem)
        (try
          (Files/move (.toPath tmp-priv) (.toPath priv-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                            StandardCopyOption/REPLACE_EXISTING]))
          (catch Exception _
            (Files/move (.toPath tmp-priv) (.toPath priv-file)
                        (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
        (try
          (Files/move (.toPath tmp-pub) (.toPath pub-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                            StandardCopyOption/REPLACE_EXISTING]))
          (catch Exception _
            (Files/move (.toPath tmp-pub) (.toPath pub-file)
                        (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
        {:private-key priv
         :public-key pub
         :keypair kp}))))

;; ---------------------------------------------------------------------------
;; JWK & Thumbprint (RFC 7638 & RFC 8555)
;; ---------------------------------------------------------------------------

(defn big-integer->32-bytes
  "Formats BigInteger affine coordinate into exact 32-byte unsigned big-endian byte array,
   stripping sign bit prefix byte if 33 bytes or zero-padding on left if < 32 bytes."
  [^BigInteger bi]
  (let [raw (.toByteArray bi)]
    (cond
      ;; 33 bytes with leading sign zero byte
      (and (= (count raw) 33) (zero? (first raw)))
      (byte-array (rest raw))
      ;; exact 32 bytes
      (= (count raw) 32)
      raw
      ;; < 32 bytes: pad on the left
      (< (count raw) 32)
      (let [pad (byte-array (- 32 (count raw)))]
        (byte-array (concat pad raw)))
      :else
      (throw (ex-info "Affine coordinate exceeds 32 bytes" {:count (count raw)})))))

(defn ec-public-key->jwk
  "Extracts ECPoint affine coordinates X and Y and returns canonical JWK map:
   {\"crv\" \"P-256\" \"kty\" \"EC\" \"x\" ... \"y\" ...}."
  [^ECPublicKey pub-key]
  (let [w (.getW pub-key)
        x (big-integer->32-bytes (.getAffineX w))
        y (big-integer->32-bytes (.getAffineY w))]
    {"crv" "P-256"
     "kty" "EC"
     "x" (base64url-encode x)
     "y" (base64url-encode y)}))

(defn jwk-thumbprint
  "Per RFC 7638, computes SHA-256 thumbprint over lexicographically ordered
   {\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"...\",\"y\":\"...\"} string.
   Returns Base64URL-encoded digest."
  [pub-key]
  (let [jwk (ec-public-key->jwk pub-key)
        canon-json (str "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
                        (get jwk "x")
                        "\",\"y\":\""
                        (get jwk "y")
                        "\"}")
        md (MessageDigest/getInstance "SHA-256")
        digest (.digest md (.getBytes canon-json StandardCharsets/UTF_8))]
    (base64url-encode digest)))

(defn key-authorization
  "Returns RFC 8555 key authorization string: <token>.<thumbprint> for HTTP-01."
  [token pub-key]
  (str token "." (jwk-thumbprint pub-key)))

(defn dns-01-txt-value
  "Returns RFC 8555 SHA-256 base64url digest of key-authorization for DNS-01."
  [token pub-key]
  (let [auth (key-authorization token pub-key)
        md (MessageDigest/getInstance "SHA-256")
        digest (.digest md (.getBytes auth StandardCharsets/UTF_8))]
    (base64url-encode digest)))

;; ---------------------------------------------------------------------------
;; JWS ES256 Signing (RFC 7515 & RFC 8555)
;; ---------------------------------------------------------------------------

(defn sign-jws
  "Builds and signs a Flattened JWS JSON string using ES256 (SHA256withECDSAinP1363Format).
   Options:
     :private-key (PrivateKey, required)
     :public-key  (ECPublicKey, required if kid is nil)
     :kid         (Account URL string, optional)
     :nonce       (Replay-Nonce string, required)
     :url         (Destination endpoint URL string, required)
     :payload     (Map, String, nil, or :post-as-get)
   Returns JSON string: {\"protected\": \"...\", \"payload\": \"...\", \"signature\": \"...\"}."
  [{:keys [private-key public-key kid nonce url payload]}]
  (let [header (cond-> {"alg" "ES256"
                        "nonce" nonce
                        "url" url}
                 kid (assoc "kid" kid)
                 (not kid) (assoc "jwk" (ec-public-key->jwk public-key)))
        header-json (json/write-str header)
        protected-b64 (base64url-encode (.getBytes header-json StandardCharsets/UTF_8))
        payload-b64 (if (or (nil? payload) (= payload :post-as-get))
                      ""
                      (base64url-encode (.getBytes (if (string? payload) payload (json/write-str payload)) StandardCharsets/UTF_8)))
        signing-input (str protected-b64 "." payload-b64)
        sig (Signature/getInstance "SHA256withECDSAinP1363Format")
        _ (.initSign sig ^PrivateKey private-key)
        _ (.update sig (.getBytes signing-input StandardCharsets/US_ASCII))
        sig-bytes (.sign sig)
        sig-b64 (base64url-encode sig-bytes)]
    (json/write-str {"protected" protected-b64
                     "payload" payload-b64
                     "signature" sig-b64})))

;; ---------------------------------------------------------------------------
;; Pure-Java PKCS#10 Certificate Signing Request (CSR) DER Builder
;; ---------------------------------------------------------------------------

(defn- ubyte [n] (unchecked-byte n))

(defn- der-length [^long len]
  (cond
    (< len 128) [(ubyte len)]
    (< len 256) [(ubyte 0x81) (ubyte len)]
    :else [(ubyte 0x82) (ubyte (bit-shift-right len 8)) (ubyte (bit-and len 0xff))]))

(defn- der-tlv [^long tag val-bytes]
  (let [bs (byte-array val-bytes)
        len (count bs)
        hdr (into [(ubyte tag)] (der-length len))]
    (byte-array (concat hdr bs))))

(defn- der-seq [items]
  (der-tlv 0x30 (byte-array (mapcat seq items))))

(defn- der-set [items]
  (der-tlv 0x31 (byte-array (mapcat seq items))))

(defn- der-tagged [tag items]
  (der-tlv tag (byte-array (mapcat seq items))))

(defn- der-dns-name [^String domain]
  (der-tlv 0x82 (.getBytes domain StandardCharsets/US_ASCII)))

(defn generate-csr
  "Generates a DER-encoded PKCS#10 Certificate Signing Request covering
   (first domains) as CN and all domains in a SubjectAlternativeName extension,
   signed with SHA256withECDSA. Returns byte array."
  [^KeyPair domain-keypair domains]
  (when (empty? domains)
    (throw (ex-info "At least one domain required for CSR" {:domains domains})))
  (let [common-name (first domains)
        san-names (mapv der-dns-name domains)
        san-seq (der-seq san-names)
        san-ext-val (der-tlv 0x04 san-seq)
        san-oid (byte-array [(ubyte 0x06) (ubyte 0x03) (ubyte 0x55) (ubyte 0x1d) (ubyte 0x11)])
        san-ext (der-seq [san-oid san-ext-val])
        exts-seq (der-seq [san-ext])
        ext-req-oid (byte-array [(ubyte 0x06) (ubyte 0x09) (ubyte 0x2a) (ubyte 0x86) (ubyte 0x48)
                                 (ubyte 0x86) (ubyte 0xf7) (ubyte 0x0d) (ubyte 0x01) (ubyte 0x09) (ubyte 0x0e)])
        attr-seq (der-seq [ext-req-oid (der-set [exts-seq])])
        attrs-tagged (der-tagged 0xa0 [attr-seq])
        x500 (X500Name. (str "CN=" common-name))
        subject-bytes (.getEncoded x500)
        spki-bytes (.getEncoded (.getPublic domain-keypair))
        version (byte-array [(ubyte 0x02) (ubyte 0x01) (ubyte 0x00)])
        req-info (der-seq [version subject-bytes spki-bytes attrs-tagged])
        sig (Signature/getInstance "SHA256withECDSA")
        _ (.initSign sig (.getPrivate domain-keypair))
        _ (.update sig req-info)
        sig-bytes (.sign sig)
        bit-string (der-tlv 0x03 (byte-array (cons (byte 0) sig-bytes)))
        sig-alg (byte-array [(ubyte 0x30) (ubyte 0x0a) (ubyte 0x06) (ubyte 0x08)
                             (ubyte 0x2a) (ubyte 0x86) (ubyte 0x48) (ubyte 0xce)
                             (ubyte 0x3d) (ubyte 0x04) (ubyte 0x03) (ubyte 0x02)])]
    (der-seq [req-info sig-alg bit-string])))
