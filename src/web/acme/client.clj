(ns web.acme.client
  "RFC 8555 ACME v2 client and zero-downtime certificate renewal orchestrator.
   Executes automated HTTP-01 challenge fulfillment, multi-node cluster challenge sync,
   ECDSA P-256 CSR generation, order finalization, certificate download,
   and dynamic TLS bundle broadcast."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [web.acme.jws :as jws]
            [web.cluster.mesh :as mesh]
            [web.tls.context :as tls])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.security.cert X509Certificate]
           [java.time Duration]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean]))

;; ---------------------------------------------------------------------------
;; HTTP Client & Directory / Nonce Helpers
;; ---------------------------------------------------------------------------

(defn create-http-client
  "Creates standard Java 25 HttpClient configured for HTTP/1.1 and redirects."
  ([] (create-http-client 15))
  ([^long timeout-seconds]
   (-> (HttpClient/newBuilder)
       (.version HttpClient$Version/HTTP_1_1)
       (.followRedirects HttpClient$Redirect/NORMAL)
       (.connectTimeout (Duration/ofSeconds timeout-seconds))
       (.build))))

(defn fetch-directory
  "Fetches ACME directory JSON from directory-url and returns parsed map."
  [^HttpClient client ^String directory-url]
  (let [req (-> (HttpRequest/newBuilder)
                (.uri (URI/create directory-url))
                (.timeout (Duration/ofSeconds 15))
                (.GET)
                (.build))
        resp (.send client req (HttpResponse$BodyHandlers/ofString))
        status (.statusCode resp)
        body (.body resp)]
    (if (<= 200 status 299)
      (json/read-str body)
      (throw (ex-info "Failed to fetch ACME directory" {:status status :body body :url directory-url})))))

(defn fetch-nonce
  "Fetches a fresh Replay-Nonce from new-nonce-url via HEAD request."
  [^HttpClient client ^String new-nonce-url]
  (let [req (-> (HttpRequest/newBuilder)
                (.uri (URI/create new-nonce-url))
                (.timeout (Duration/ofSeconds 15))
                (.method "HEAD" (HttpRequest$BodyPublishers/noBody))
                (.build))
        resp (.send client req (HttpResponse$BodyHandlers/discarding))
        nonce (.orElse (.firstValue (.headers resp) "Replay-Nonce") nil)]
    (or nonce
        (throw (ex-info "No Replay-Nonce header in response" {:status (.statusCode resp) :url new-nonce-url})))))

;; ---------------------------------------------------------------------------
;; Authenticated JWS POST Execution
;; ---------------------------------------------------------------------------

(defn acme-post!
  "Signs payload using JWS ES256 and current nonce, POSTs to url with Content-Type: application/jose+json,
   updates Replay-Nonce in client-state atom, and returns response map.
   Retries once automatically on badNonce error per RFC 8555 §6.5."
  ([client-state url payload]
   (acme-post! client-state url payload 0))
  ([client-state url payload retry-count]
   (let [st @client-state
         ^HttpClient client (:http-client st)
         directory (:directory st)
         nonce (or (:nonce st) (fetch-nonce client (get directory "newNonce")))
         jws-body (jws/sign-jws {:private-key (:account-priv st)
                                 :public-key (:account-pub st)
                                 :kid (:kid st)
                                 :nonce nonce
                                 :url url
                                 :payload payload})
         req (-> (HttpRequest/newBuilder)
                 (.uri (URI/create url))
                 (.timeout (Duration/ofSeconds 30))
                 (.header "Content-Type" "application/jose+json")
                 (.POST (HttpRequest$BodyPublishers/ofString jws-body))
                 (.build))
         resp (.send client req (HttpResponse$BodyHandlers/ofString))
         status (.statusCode resp)
         headers (.headers resp)
         new-nonce (.orElse (.firstValue headers "Replay-Nonce") nil)
         body (.body resp)
         json-data (try (when (and body (not (str/blank? body))) (json/read-str body)) (catch Exception _ nil))
         loc (.orElse (.firstValue headers "Location") nil)
         result {:status status
                 :location loc
                 :body body
                 :json json-data
                 :headers headers}]
     ;; Update replay nonce
     (when new-nonce
       (swap! client-state assoc :nonce new-nonce))
     ;; Check for badNonce retry
     (if (and (= status 400)
              (< retry-count 1)
              (= (get json-data "type") "urn:ietf:params:acme:error:badNonce"))
       (do
         (swap! client-state assoc :nonce (or new-nonce (fetch-nonce client (get directory "newNonce"))))
         (acme-post! client-state url payload (inc retry-count)))
       result))))

;; ---------------------------------------------------------------------------
;; ACME Issuance Workflow (Executed by Cluster Leader)
;; ---------------------------------------------------------------------------

(defn- poll-until-status!
  "Polls resource URL with POST-as-GET until target status reached or failure."
  [client-state url target-statuses failure-statuses timeout-ms interval-ms]
  (let [start-ms (System/currentTimeMillis)]
    (loop []
      (let [resp (acme-post! client-state url :post-as-get)
            current-status (get-in resp [:json "status"])]
        (cond
          (contains? target-statuses current-status)
          resp

          (contains? failure-statuses current-status)
          (throw (ex-info (str "ACME resource failed with status " current-status)
                          {:url url :response resp}))

          (> (- (System/currentTimeMillis) start-ms) timeout-ms)
          (throw (ex-info "Timed out polling ACME resource"
                          {:url url :last-status current-status :timeout-ms timeout-ms}))

          :else
          (do
            (Thread/sleep interval-ms)
            (recur)))))))

(defn provision-certificate!
  "Orchestrates full RFC 8555 certificate issuance workflow:
   1. Loads or creates ACME account keypair.
   2. Fetches directory & initial replay nonce.
   3. Registers/locates ACME account via newAccount.
   4. Creates order via newOrder for configured domains.
   5. Fulfills HTTP-01 challenges, replicating tokens to cluster peers.
   6. Generates fresh domain keypair and PKCS#10 CSR.
   7. Finalizes order and downloads PEM certificate chain.
   8. Updates local TLS manager and broadcasts bundle across cluster.
   Returns map with :cert-pem, :key-pem, :expires-at, :domain-keypair, :certificates."
  ([config cluster-mgr tls-manager]
   (provision-certificate! config cluster-mgr tls-manager {}))
  ([config cluster-mgr tls-manager opts]
   (let [domains (or (:domains (:acme config))
                     (when-let [d (:domain config)] [d])
                     ["localhost"])
         state-dir (:state-dir config)
         acme-cfg (get config :acme {})
         directory-url (or (:directory-url opts)
                           (:directory-url acme-cfg)
                           "https://acme-v02.api.letsencrypt.org/directory")
         poll-interval-ms (long (or (:poll-interval-ms opts) 500))
         poll-timeout-ms (long (or (:poll-timeout-ms opts) 60000))

         ;; Step 1: Account keypair
         acc-info (jws/save-or-load-account-keypair! state-dir)
         account-priv (:private-key acc-info)
         account-pub (:public-key acc-info)

         ;; Step 2: HTTP Client & Directory
         client (or (:http-client opts) (create-http-client))
         directory (fetch-directory client directory-url)
         initial-nonce (fetch-nonce client (get directory "newNonce"))
         client-state (atom {:http-client client
                             :account-priv account-priv
                             :account-pub account-pub
                             :kid nil
                             :nonce initial-nonce
                             :directory directory})

         ;; Step 3: newAccount
         acct-payload (cond-> {"termsOfServiceAgreed" true}
                        (:contact-email acme-cfg) (assoc "contact" [(:contact-email acme-cfg)]))
         acct-resp (acme-post! client-state (get directory "newAccount") acct-payload)
         account-url (or (:location acct-resp)
                         (throw (ex-info "newAccount did not return Location header" {:resp acct-resp})))
         _ (swap! client-state assoc :kid account-url)

         ;; Step 4: newOrder
         order-payload {"identifiers" (mapv (fn [d] {"type" "dns" "value" d}) domains)}
         order-resp (acme-post! client-state (get directory "newOrder") order-payload)
         order-url (or (:location order-resp)
                       (throw (ex-info "newOrder did not return Location header" {:resp order-resp})))
         order-data (:json order-resp)
         authz-urls (get order-data "authorizations")
         finalize-url (get order-data "finalize")]

     (when (empty? authz-urls)
       (throw (ex-info "newOrder returned no authorizations" {:order-resp order-resp})))

     ;; Step 5: Authorizations & Challenges
     (doseq [authz-url authz-urls]
       (let [authz-resp (acme-post! client-state authz-url :post-as-get)
             authz-data (:json authz-resp)
             authz-status (get authz-data "status")]
         (when-not (= authz-status "valid")
           (let [challenges (get authz-data "challenges")
                 http-chall (first (filter #(= (get % "type") "http-01") challenges))]
             (when-not http-chall
               (throw (ex-info "No http-01 challenge in authorization" {:authz-data authz-data})))
             (let [token (get http-chall "token")
                   chall-url (get http-chall "url")
                   key-auth (jws/key-authorization token account-pub)
                   dns-txt (jws/dns-01-txt-value token account-pub)]

               ;; Broadcast challenge across cluster
               (when cluster-mgr
                 (let [quorum-ok? (mesh/publish-acme-challenge! cluster-mgr token key-auth dns-txt 5000)]
                   (when-not quorum-ok?
                     (throw (ex-info "Cluster challenge replication quorum timeout" {:token token})))))

               ;; Trigger challenge verification
               (acme-post! client-state chall-url {})

               ;; Poll authorization until valid
               (try
                 (poll-until-status! client-state authz-url #{"valid"} #{"invalid"} poll-timeout-ms poll-interval-ms)
                 (finally
                   ;; Clear challenge from cluster
                   (when cluster-mgr
                     (mesh/clear-acme-challenge! cluster-mgr token)))))))))

     ;; Step 6: Finalize Order with CSR
     (let [domain-kp (or (:domain-keypair opts) (jws/generate-ec-keypair))
           csr-der (jws/generate-csr domain-kp domains)
           csr-b64 (jws/base64url-encode csr-der)
           _ (acme-post! client-state finalize-url {"csr" csr-b64})

           ;; Poll order until valid and certificate URL is available
           final-order-resp (poll-until-status! client-state order-url #{"valid"} #{"invalid"} poll-timeout-ms poll-interval-ms)
           cert-url (or (get-in final-order-resp [:json "certificate"])
                        (throw (ex-info "Order valid but certificate URL missing" {:order final-order-resp})))

           ;; Step 7: Download PEM certificate chain
           cert-resp (acme-post! client-state cert-url :post-as-get)
           cert-pem (:body cert-resp)
           key-pem (tls/encode-private-key-pem (.getPrivate domain-kp))
           certs (tls/parse-cert-chain-pem cert-pem)]

       (when (empty? certs)
         (throw (ex-info "Downloaded certificate chain is empty or invalid" {:body cert-pem})))

       (let [expires-at (.getTime (.getNotAfter ^X509Certificate (first certs)))]
         ;; Step 8: Update local TLS manager
         (when tls-manager
           (tls/update-tls-bundle! tls-manager cert-pem key-pem))

         ;; Step 9: Broadcast new bundle to cluster peers
         (when cluster-mgr
           (mesh/publish-tls-bundle! cluster-mgr cert-pem key-pem expires-at))

         {:cert-pem cert-pem
          :key-pem key-pem
          :expires-at expires-at
          :domain-keypair domain-kp
          :certificates certs})))))

;; ---------------------------------------------------------------------------
;; Renewal Check & Scheduled Loop
;; ---------------------------------------------------------------------------

(defn needs-renewal?
  "Returns true if ACME is enabled and the current certificate is self-signed
   or within renew-before-days (default 30) of expiration."
  [config tls-manager now-ms]
  (let [acme-cfg (get config :acme {})
        enabled? (get acme-cfg :enabled? true)]
    (and enabled?
         (if-not tls-manager
           true
           (let [bundle (when-let [a (:bundle-atom tls-manager)] @a)
                 renew-days (long (get acme-cfg :renew-before-days 30))
                 renew-window-ms (* renew-days 86400000)]
             (or (nil? bundle)
                 (:self-signed? bundle)
                 (let [exp (:expires-at bundle)]
                   (or (nil? exp)
                       (< (- exp now-ms) renew-window-ms)))))))))

(defn start-acme-loop!
  "Starts background renewal check ticker on scheduled executor.
   Automatically triggers certificate provisioning when this node is cluster leader
   and certificate needs renewal."
  ([config cluster-mgr tls-manager]
   (start-acme-loop! config cluster-mgr tls-manager {}))
  ([config cluster-mgr tls-manager opts]
   (let [running? (AtomicBoolean. true)
         executor (Executors/newSingleThreadScheduledExecutor)
         interval-ms (long (or (:check-interval-ms opts) 3600000))
         task (fn []
                (when (.get running?)
                  (try
                    (let [leader? (if cluster-mgr
                                    (= :leader (:role @(:state-atom cluster-mgr)))
                                    true)
                          now (System/currentTimeMillis)]
                      (when (and leader? (needs-renewal? config tls-manager now))
                        (provision-certificate! config cluster-mgr tls-manager opts)))
                    (catch Exception e
                      (binding [*out* *err*]
                        (println (str "Error in ACME renewal loop: " (.getMessage e))))))))]
     (.scheduleWithFixedDelay ^ScheduledExecutorService executor
                              ^Runnable task
                              0
                              interval-ms
                              TimeUnit/MILLISECONDS)
     {:config config
      :cluster-mgr cluster-mgr
      :tls-manager tls-manager
      :executor executor
      :running? running?
      :stop-fn (fn []
                 (.set running? false)
                 (try (.shutdownNow ^ScheduledExecutorService executor) (catch Exception _ nil)))})))

(defn stop-acme-loop!
  "Stops the background renewal ticker cleanly."
  [acme-mgr]
  (when-let [stop-fn (:stop-fn acme-mgr)]
    (stop-fn))
  acme-mgr)
