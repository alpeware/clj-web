(ns web.cluster.mesh
  "clj-datachannel transport and cluster lifecycle manager.
   Coordinates static signalingless WebRTC DataChannel full-mesh over UDP,
   mutual DTLS fingerprint authentication, periodic virtual-thread heartbeat ticker,
   and execution of cluster effects (ACME challenge sync, TLS hot-reload, email replication)."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api]
            [datachannel.dtls :as dtls]
            [web.cluster.protocol :as protocol]
            [web.config :as config]
            [web.smtp.server :as smtp]
            [web.tls.context :as tls])
  (:import [java.io File]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.security MessageDigest]
           [java.util.concurrent Executors TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean]))

;; ---------------------------------------------------------------------------
;; Node Identity & DTLS Fingerprints
;; ---------------------------------------------------------------------------

(defn- sha256-hex [^bytes bs]
  (let [md (MessageDigest/getInstance "SHA-256")
        digest (.digest md bs)]
    (apply str (map #(format "%02x" (bit-and % 0xFF)) digest))))

(defn deterministic-ice-creds
  "Derives deterministic ICE ufrag and pwd credentials from node-id and optional fingerprint.
   When fingerprint is provided, incorporates the normalized fingerprint for non-public credentials.
   Maintains 1-arg arity for backwards compatibility."
  ([node-id]
   (deterministic-ice-creds node-id nil))
  ([node-id fingerprint]
   (let [name-str (name (or node-id :node))
         seed-str (if (and (string? fingerprint) (not (str/blank? fingerprint)))
                    (str name-str "-" (config/normalize-fingerprint fingerprint))
                    name-str)
         ufrag (subs (sha256-hex (.getBytes (str "ufrag-" seed-str) StandardCharsets/UTF_8)) 0 8)
         pwd (subs (sha256-hex (.getBytes (str "pwd-" seed-str) StandardCharsets/UTF_8)) 0 24)]
     {:ufrag ufrag :pwd pwd})))

(defn load-or-create-node-identity!
  "Loads or creates node DTLS identity containing certificate, private key,
   deterministic ICE credentials, and SHA-256 fingerprint.
   Persists to <state-dir>/cluster/node-identity.edn."
  [state-dir node-id]
  (let [cluster-dir (io/file state-dir "cluster")
        _ (.mkdirs cluster-dir)
        identity-file (io/file cluster-dir "node-identity.edn")]
    (if (.exists identity-file)
      (try
        (let [edn-data (edn/read-string (slurp identity-file))]
          (when-not (and (map? edn-data)
                         (:cert-pem edn-data)
                         (:key-pem edn-data)
                         (:fingerprint edn-data)
                         (:ice-creds edn-data))
            (throw (ex-info "Corrupt cluster node-identity.edn file"
                            {:file (.getAbsolutePath identity-file)})))
          (let [certs (tls/parse-cert-chain-pem (:cert-pem edn-data))
                key (tls/parse-private-key-pem (:key-pem edn-data))]
            (when (or (empty? certs) (nil? key))
              (throw (ex-info "Corrupt cluster node-identity.edn file"
                              {:file (.getAbsolutePath identity-file)})))
            {:cert (first certs)
             :key key
             :fingerprint (:fingerprint edn-data)
             :ice-creds (:ice-creds edn-data)
             :cert-data {:cert (first certs) :key key :fingerprint (:fingerprint edn-data)}}))
        (catch clojure.lang.ExceptionInfo e
          (throw e))
        (catch Exception e
          (throw (ex-info "Corrupt cluster node-identity.edn file"
                          {:file (.getAbsolutePath identity-file)}
                          e))))
      (let [cert-data (dtls/generate-cert)
            cert (:cert cert-data)
            key (:key cert-data)
            fp (:fingerprint cert-data)
            cert-pem (tls/encode-cert-pem cert)
            key-pem (tls/encode-private-key-pem key)
            ice-creds (deterministic-ice-creds node-id fp)
            serialized (pr-str {:cert-pem cert-pem
                                :key-pem key-pem
                                :fingerprint fp
                                :ice-creds ice-creds})
            tmp-file (File/createTempFile "identity" ".tmp" cluster-dir)]
        (spit tmp-file serialized)
        (try
          (Files/setPosixFilePermissions (.toPath tmp-file) (PosixFilePermissions/fromString "rw-------"))
          (catch UnsupportedOperationException _ nil))
        (try
          (Files/move (.toPath tmp-file) (.toPath identity-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                            StandardCopyOption/REPLACE_EXISTING]))
          (catch Exception _
            (Files/move (.toPath tmp-file) (.toPath identity-file)
                        (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
        {:cert cert
         :key key
         :fingerprint fp
         :ice-creds ice-creds
         :cert-data cert-data}))))

(defn verify-peer-fingerprint?
  "Verifies actual DTLS peer fingerprint against configured fingerprint for peer-id.
   Strictly fail-closed: returns false if expected or actual-fingerprint is nil or blank."
  [config peer-id actual-fingerprint]
  (let [expected (get-in config [:cluster :nodes peer-id :fingerprint])]
    (if (or (nil? expected) (str/blank? (str expected))
            (nil? actual-fingerprint) (str/blank? (str actual-fingerprint)))
      false
      (try
        (let [norm-exp (config/normalize-fingerprint expected)
              norm-act (config/normalize-fingerprint actual-fingerprint)]
          (= norm-exp norm-act))
        (catch Exception _ false)))))

;; ---------------------------------------------------------------------------
;; Cluster Mesh Lifecycle
;; ---------------------------------------------------------------------------

(declare publish-acme-challenge! clear-acme-challenge! publish-tls-bundle! replicate-mail! stop-cluster!)

(defn start-cluster!
  "Starts the cluster node control plane, connecting to configured peers via clj-datachannel.
   Options:
     :on-leader-elected (fn [leader-id term])
     :on-challenge-quorum (fn [token])
     :transport (:datachannel (default) or :in-memory)"
  ([config tls-manager acme-challenges-atom]
   (start-cluster! config tls-manager acme-challenges-atom {}))
  ([config tls-manager acme-challenges-atom opts]
   (let [node-id (:node/id config)
         state-dir (:state-dir config)
         cluster-cfg (get config :cluster {})
         nodes-cfg (get cluster-cfg :nodes {})
         peer-ids (disj (set (keys nodes-cfg)) node-id)
         hb-interval (long (get cluster-cfg :heartbeat-interval-ms 5000))
         running? (AtomicBoolean. true)
         vthread-executor (Executors/newVirtualThreadPerTaskExecutor)
         scheduled-executor (Executors/newSingleThreadScheduledExecutor)
         cluster-state-atom (atom (protocol/init-cluster-state config))
         quorum-promises-atom (atom {})
         peer-conns-atom (atom {})
         identity (load-or-create-node-identity! state-dir node-id)
         transport (get opts :transport :datachannel)

         ;; Forward declarations for effect execution & outbound dispatch
         execute-effects!
         (fn [effects]
           (doseq [effect effects]
             (case (:type effect)
               :leader-elected
               (do
                 (println (str "Cluster leader elected: " (:leader-id effect) " (term " (:term effect) ")"))
                 (when-let [cb (:on-leader-elected opts)]
                   (try (cb (:leader-id effect) (:term effect))
                        (catch Exception e
                          (binding [*out* *err*]
                            (println "Error in on-leader-elected callback:" (.getMessage e)))))))

               :acme/challenge-updated
               (swap! acme-challenges-atom assoc (:token effect) (:key-auth effect))

               :acme/challenge-cleared
               (swap! acme-challenges-atom dissoc (:token effect))

               :acme/challenge-quorum-reached
               (do
                 (when-let [p (get @quorum-promises-atom (:token effect))]
                   (deliver p true))
                 (when-let [cb (:on-challenge-quorum opts)]
                   (try (cb (:token effect))
                        (catch Exception e
                          (binding [*out* *err*]
                            (println "Error in on-challenge-quorum callback:" (.getMessage e)))))))

               :tls/install-bundle
               (when tls-manager
                 (try
                   (tls/update-tls-bundle! tls-manager (:cert-pem effect) (:key-pem effect))
                   (println "[Cluster] Installed replicated TLS bundle from leader")
                   (catch Exception e
                     (binding [*out* *err*]
                       (println "Error updating TLS bundle:" (.getMessage e))))))

               :smtp/save-replicated-mail
               (try
                 (let [saved (smtp/save-eml! state-dir (:mail effect))]
                   (println (str "[Cluster] Replicated email saved [" (.getName ^File (:file saved)) "] from " (:from saved) " to " (str/join ", " (:to saved)))))
                 (catch Exception e
                   (binding [*out* *err*]
                     (println "Error saving replicated mail:" (.getMessage e)))))

               nil)))

         send-outbound!
         (fn [outbound]
           (doseq [{:keys [to channel message]} outbound]
             (let [payload (pr-str message)
                   targets (if (= to :all)
                             @peer-conns-atom
                             (if-let [c (get @peer-conns-atom to)] {to c} {}))]
               (doseq [[_pid conn] targets]
                 (when conn
                   (if (= transport :in-memory)
                     ;; In-memory transport: deliver directly via receiver callback
                     (when-let [recv-fn (:send-fn conn)]
                       (try (recv-fn message) (catch Exception _ nil)))
                     ;; clj-datachannel transport
                     (let [dc-node (:node conn)
                           ch-id (if (= channel :heartbeat)
                                   @(:heartbeat-id conn)
                                   @(:control-id conn))]
                       (when (and dc-node ch-id)
                         (try
                           (api/send! dc-node payload ch-id)
                           (catch Exception _ nil))))))))))

         dispatch-event!
         (fn dispatch-fn
           ([evt]
            (dispatch-fn evt (System/currentTimeMillis)))
           ([evt now-ms]
            (let [res (swap! cluster-state-atom
                             (fn [st]
                               (let [r (protocol/handle-cluster-event st evt now-ms)]
                                 ;; Attach outbound and effects as metadata to swap return
                                 (with-meta (:state r) {:outbound (:outbound r) :effects (:effects r)}))))
                  m (meta res)
                  outbound (:outbound m)
                  effects (:effects m)]
              (when (seq outbound)
                (send-outbound! outbound))
              (when (seq effects)
                (execute-effects! effects))
              res)))

         sorted-ids (vec (sort-by name (keys nodes-cfg)))
         node-idx (into {} (map-indexed (fn [i k] [k i]) sorted-ids))
         multi-peer? (> (count nodes-cfg) 2)

         connect-peer!
         (fn [pid]
           (if (= transport :in-memory)
             ;; In-memory descriptor
             (swap! peer-conns-atom assoc pid {:peer-id pid :transport :in-memory})
             ;; clj-datachannel descriptor
             (let [peer-cfg (get nodes-cfg pid)]
               (try
                 (when-let [old-node (:node (get @peer-conns-atom pid))]
                   (try (api/close! old-node) (catch Exception _ nil))
                   (Thread/sleep 50))
                 (let [peer-ip (or (:ip4 peer-cfg) (:ip peer-cfg) "127.0.0.1")
                       base-peer-port (int (or (:port peer-cfg) 5000))
                       peer-port (if multi-peer?
                                   (+ base-peer-port (int (get node-idx node-id 0)))
                                   base-peer-port)
                       active? (neg? (compare (name node-id) (name pid)))
                       setup (if active? "active" "passive")
                       raw-peer-fp (:fingerprint peer-cfg)
                       peer-fp (when (and (string? raw-peer-fp) (not (str/blank? raw-peer-fp)))
                                 (config/normalize-fingerprint raw-peer-fp))
                       _ (when (and (not (:allow-unauthenticated? opts)) (str/blank? (str peer-fp)))
                           (throw (ex-info (str "Missing required DTLS fingerprint for cluster peer: " (pr-str pid))
                                           {:peer-id pid :peer-cfg peer-cfg})))
                       base-local-port (int (or (get-in nodes-cfg [node-id :port]) 5000))
                       local-port (if multi-peer?
                                    (+ base-local-port (int (get node-idx pid 0)))
                                    base-local-port)
                       raw-node (api/create-node {:port local-port :setup setup})
                       local-fp (when-let [raw-fp (:fingerprint identity)]
                                  (config/normalize-fingerprint raw-fp))
                       local-ice (deterministic-ice-creds node-id local-fp)
                       node (assoc raw-node
                                   :cert-data (:cert-data identity)
                                   :ice-creds local-ice
                                   :local-sdp-params (assoc (:local-sdp-params raw-node)
                                                            :ice-ufrag (:ufrag local-ice)
                                                            :ice-pwd (:pwd local-ice)
                                                            :fingerprint local-fp
                                                            :setup setup))
                       ctrl-id (atom nil)
                       hb-id (atom nil)
                       remote-ice (deterministic-ice-creds pid peer-fp)
                       remote-sdp {:ip peer-ip
                                   :port peer-port
                                   :fingerprint peer-fp
                                   :remote-ice-ufrag (:ufrag remote-ice)
                                   :remote-ice-pwd (:pwd remote-ice)}
                       callbacks {:on-open (fn [evt]
                                             (when-not (:channel-id evt)
                                               ;; SCTP transport connected: create channels
                                               (let [cid (api/create-data-channel! node "control" {:ordered true})
                                                     hid (api/create-data-channel! node "heartbeat" {:ordered false :max-retransmits 0})]
                                                 (reset! ctrl-id cid)
                                                 (reset! hb-id hid)
                                                 (println (str "Cluster peer connected: " pid))
                                                 (dispatch-event! {:type :cluster/peer-connected :peer-id pid} (System/currentTimeMillis)))))
                                  :on-message (fn [evt]
                                                (let [payload (:payload evt)
                                                      text (if (string? payload) payload (String. ^bytes payload StandardCharsets/UTF_8))
                                                      msg (try (edn/read-string text) (catch Exception _ nil))]
                                                  (when msg
                                                    (dispatch-event! {:type :cluster/receive :from pid :message msg} (System/currentTimeMillis)))))
                                  :on-close (fn [_]
                                              (println (str "Cluster peer disconnected: " pid))
                                              (dispatch-event! {:type :cluster/peer-disconnected :peer-id pid} (System/currentTimeMillis)))}]
                   (api/start! node remote-sdp callbacks)
                   (swap! peer-conns-atom assoc pid {:node node :control-id ctrl-id :heartbeat-id hb-id :created-at (System/currentTimeMillis)}))
                 (catch Exception e
                   (binding [*out* *err*]
                     (println (str "Error establishing datachannel connection to peer " pid ": " (.getMessage e))))
                   (when (and (not (:allow-unauthenticated? opts)) (str/blank? (str (:fingerprint peer-cfg))))
                     (throw e))
                   nil)))))]

     ;; Initialize peer connection descriptors
     (doseq [pid peer-ids]
       (connect-peer! pid))

     ;; Background periodic heartbeat ticker
     (.scheduleWithFixedDelay scheduled-executor
                              ^Runnable
                              (fn []
                                (when (.get running?)
                                  (try
                                    (let [now-ms (System/currentTimeMillis)
                                          hb-timeout (long (get cluster-cfg :heartbeat-timeout-ms 15000))]
                                      (dispatch-event! {:type :cluster/tick} now-ms)
                                      (when (and (.get running?) (not= transport :in-memory))
                                        (doseq [pid peer-ids]
                                          (let [conn (get @peer-conns-atom pid)
                                                dc-node (:node conn)
                                                dc-state (when dc-node (try (api/get-state dc-node) (catch Exception _ nil)))
                                                alive? (or (contains? (:alive-peers @cluster-state-atom) pid)
                                                           (contains? (:healthy-nodes @cluster-state-atom) pid))
                                                age-ms (- now-ms (long (or (:created-at conn) 0)))]
                                            (when (or (nil? conn)
                                                      (= dc-state :closed)
                                                      (and (not alive?) (>= age-ms hb-timeout)))
                                              (connect-peer! pid))))))
                                    (catch Exception _ nil))))
                              0
                              hb-interval
                              TimeUnit/MILLISECONDS)

     (let [cluster-mgr {:config config
                        :tls-manager tls-manager
                        :acme-challenges-atom acme-challenges-atom
                        :state-atom cluster-state-atom
                        :quorum-promises-atom quorum-promises-atom
                        :peer-conns-atom peer-conns-atom
                        :dispatch-event! dispatch-event!
                        :running? running?
                        :stop-fn (fn []
                                   (.set running? false)
                                   (try (.shutdownNow scheduled-executor) (catch Exception _ nil))
                                   (try (.shutdownNow vthread-executor) (catch Exception _ nil))
                                   (doseq [[_ conn] @peer-conns-atom]
                                     (when-let [n (:node conn)]
                                       (try (api/close! n) (catch Exception _ nil)))))}]
       cluster-mgr))))

(defn publish-acme-challenge!
  "Publishes an ACME challenge across the cluster and waits up to timeout-ms
   for challenge quorum acknowledgment. Returns true on success, false on timeout."
  ([cluster-mgr token key-auth]
   (publish-acme-challenge! cluster-mgr token key-auth nil 5000))
  ([cluster-mgr token key-auth dns-txt]
   (publish-acme-challenge! cluster-mgr token key-auth dns-txt 5000))
  ([cluster-mgr token key-auth dns-txt timeout-ms]
   (let [p (promise)
         dispatch! (:dispatch-event! cluster-mgr)]
     (swap! (:quorum-promises-atom cluster-mgr) assoc token p)
     (dispatch! {:type :cluster/publish-acme-challenge
                 :token token
                 :key-auth key-auth
                 :dns-txt dns-txt}
                (System/currentTimeMillis))
     (let [res (deref p timeout-ms false)]
       (swap! (:quorum-promises-atom cluster-mgr) dissoc token)
       res))))

(defn clear-acme-challenge!
  "Clears an ACME challenge locally and across the cluster."
  [cluster-mgr token]
  (let [dispatch! (:dispatch-event! cluster-mgr)]
    (dispatch! {:type :cluster/clear-acme-challenge :token token} (System/currentTimeMillis))))

(defn publish-tls-bundle!
  "Broadcasts a newly issued TLS certificate and key bundle to all cluster peers."
  [cluster-mgr cert-pem key-pem expires-at]
  (let [dispatch! (:dispatch-event! cluster-mgr)]
    (dispatch! {:type :cluster/publish-tls-bundle
                :cert-pem cert-pem
                :key-pem key-pem
                :expires-at expires-at}
               (System/currentTimeMillis))))

(defn replicate-mail!
  "Broadcasts a received email across the cluster for synchronized persistence."
  [cluster-mgr mail-map]
  (let [dispatch! (:dispatch-event! cluster-mgr)]
    (dispatch! {:type :cluster/replicate-mail :mail mail-map} (System/currentTimeMillis))))

(defn stop-cluster!
  "Stops the cluster node, closing all peer connections and tickers cleanly."
  [cluster-mgr]
  (when-let [stop-fn (:stop-fn cluster-mgr)]
    (stop-fn))
  cluster-mgr)
