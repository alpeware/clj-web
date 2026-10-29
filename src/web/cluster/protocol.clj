(ns web.cluster.protocol
  "Pure Sans-IO deterministic cluster state machine for 3-node control plane.
   Implements peer liveness tracking, quorum-backed Bully leader election,
   ACME challenge replication and ACK tracking, TLS bundle broadcast,
   and inbound email replication."
  (:require [clojure.set :as set]))

(defn init-cluster-state
  "Initializes pure cluster state map from config.
   Options:
     :node/id (local node keyword, e.g. :ns1)
     :cluster {:nodes {:ns1 {...} :ns2 {...} :ns3 {...}}
               :heartbeat-interval-ms (default 5000)
               :heartbeat-timeout-ms (default 15000)}"
  [config]
  (let [node-id (:node/id config)
        nodes-cfg (get-in config [:cluster :nodes] {})
        all-nodes (set (if (seq nodes-cfg) (keys nodes-cfg) [node-id]))
        peer-ids (disj all-nodes node-id)
        hb-interval (long (get-in config [:cluster :heartbeat-interval-ms] 5000))
        hb-timeout (long (get-in config [:cluster :heartbeat-timeout-ms] 15000))
        peers (into {} (map (fn [pid] [pid {:last-seen-ms nil :connected? false :cert-expires-at nil}]) peer-ids))]
    {:node-id node-id
     :all-nodes all-nodes
     :heartbeat-interval-ms hb-interval
     :heartbeat-timeout-ms hb-timeout
     :peers peers
     :healthy-nodes #{node-id}
     :leader-id nil
     :role :follower
     :term 0
     :acme-challenges {}
     :acme-dns-challenges {}
     :pending-challenge-acks {}
     :tls-bundle nil
     :received-mail-ids #{}}))

(defn compute-healthy-nodes
  "Returns the set of reachable nodes including local node-id plus all peers
   whose last heartbeat was received within heartbeat-timeout-ms."
  [state now-ms]
  (let [node-id (:node-id state)
        hb-timeout (:heartbeat-timeout-ms state)
        peers (:peers state)
        healthy-peers (keep (fn [[pid info]]
                              (let [seen (:last-seen-ms info)]
                                (when (and seen (< (- now-ms seen) hb-timeout))
                                  pid)))
                            peers)]
    (conj (set healthy-peers) node-id)))

(defn elect-leader
  "Determines the cluster leader from healthy-nodes and total-configured-nodes.
   In a single-node cluster, the single node is leader.
   In a multi-node cluster, enforces Quorum Rule (>= 2 reachable nodes):
   if healthy-nodes count < 2, returns nil (split-brain immunity!).
   Otherwise returns the highest priority node (lexicographically smallest keyword name)."
  [healthy-nodes total-configured-nodes]
  (cond
    (empty? healthy-nodes) nil
    (<= total-configured-nodes 1) (first healthy-nodes)
    (< (count healthy-nodes) 2) nil
    :else (first (sort-by name healthy-nodes))))

(defn- update-liveness-and-leader
  [state now-ms]
  (let [healthy (compute-healthy-nodes state now-ms)
        leader (elect-leader healthy (count (:all-nodes state)))
        prev-role (:role state)
        new-role (if (and leader (= leader (:node-id state))) :leader :follower)
        leader-elected? (and (= new-role :leader) (not= prev-role :leader))
        new-term (if leader-elected? (inc (:term state)) (:term state))
        effects (if leader-elected?
                  [{:type :leader-elected :leader-id (:node-id state) :term new-term}]
                  [])]
    {:state (assoc state
                   :healthy-nodes healthy
                   :leader-id leader
                   :role new-role
                   :term new-term)
     :effects effects}))

(defn handle-cluster-event
  "Pure reducer function processing a cluster event given current state and now-ms.
   Returns {:state updated-state :outbound [messages...] :effects [effects...]}."
  [state event now-ms]
  (let [{:keys [state next-effects]} (let [res (update-liveness-and-leader state now-ms)]
                                       {:state (:state res) :next-effects (:effects res)})
        event-type (:type event)]
    (case event-type
      ;; -----------------------------------------------------------------------
      ;; Periodic Heartbeat Tick
      ;; -----------------------------------------------------------------------
      :cluster/tick
      (let [hb-msg {:to :all
                    :channel :heartbeat
                    :message {:type :cluster/heartbeat
                              :from (:node-id state)
                              :term (:term state)
                              :leader-id (:leader-id state)
                              :now-ms now-ms}}]
        {:state state
         :outbound [hb-msg]
         :effects next-effects})

      ;; -----------------------------------------------------------------------
      ;; Peer Connected
      ;; -----------------------------------------------------------------------
      :cluster/peer-connected
      (let [pid (:peer-id event)
            updated-peers (assoc-in (:peers state) [pid] {:last-seen-ms now-ms
                                                          :connected? true
                                                          :cert-expires-at (get-in state [:peers pid :cert-expires-at])})
            res (update-liveness-and-leader (assoc state :peers updated-peers) now-ms)
            st (:state res)
            outbound (if (and (= (:role st) :leader) (:tls-bundle st))
                       [{:to pid
                         :channel :control
                         :message (assoc (:tls-bundle st) :type :tls/bundle :from (:node-id st))}]
                       [])]
        {:state st
         :outbound outbound
         :effects (into next-effects (:effects res))})

      ;; -----------------------------------------------------------------------
      ;; Peer Disconnected
      ;; -----------------------------------------------------------------------
      :cluster/peer-disconnected
      (let [pid (:peer-id event)
            updated-peers (assoc-in (:peers state) [pid :connected?] false)
            res (update-liveness-and-leader (assoc state :peers updated-peers) now-ms)]
        {:state (:state res)
         :outbound []
         :effects (into next-effects (:effects res))})

      ;; -----------------------------------------------------------------------
      ;; Inbound Network Message Received
      ;; -----------------------------------------------------------------------
      :cluster/receive
      (let [pid (:from event)
            msg (:message event)
            msg-type (:type msg)
            updated-peers (assoc-in (:peers state) [pid :last-seen-ms] now-ms)
            res (update-liveness-and-leader (assoc state :peers updated-peers) now-ms)
            st (:state res)
            base-effects (into next-effects (:effects res))]
        (case msg-type
          ;; Heartbeat
          :cluster/heartbeat
          (let [cert-exp (:cert-expires-at msg)
                st' (if cert-exp
                      (assoc-in st [:peers pid :cert-expires-at] cert-exp)
                      st)]
            {:state st'
             :outbound []
             :effects base-effects})

          ;; ACME Challenge Set
          :acme/challenge-set
          (let [token (:token msg)
                key-auth (:key-auth msg)
                dns-txt (:dns-txt msg)
                st' (cond-> (assoc-in st [:acme-challenges token] key-auth)
                      dns-txt (assoc-in [:acme-dns-challenges "_acme-challenge"] [dns-txt]))
                ack-msg {:to pid
                         :channel :control
                         :message {:type :acme/challenge-ack
                                   :from (:node-id st')
                                   :token token}}]
            {:state st'
             :outbound [ack-msg]
             :effects (conj base-effects {:type :acme/challenge-updated :token token :key-auth key-auth})})

          ;; ACME Challenge ACK
          :acme/challenge-ack
          (let [token (:token msg)
                acks (conj (get-in st [:pending-challenge-acks token] #{(:node-id st)}) pid)
                st' (assoc-in st [:pending-challenge-acks token] acks)
                needed-peers (set (:healthy-nodes st'))
                quorum? (set/subset? needed-peers acks)
                quorum-effects (if quorum?
                                 [{:type :acme/challenge-quorum-reached :token token}]
                                 [])]
            {:state st'
             :outbound []
             :effects (into base-effects quorum-effects)})

          ;; ACME Challenge Clear
          :acme/challenge-clear
          (let [token (:token msg)
                st' (-> st
                        (update :acme-challenges dissoc token)
                        (update :acme-dns-challenges dissoc "_acme-challenge")
                        (update :pending-challenge-acks dissoc token))]
            {:state st'
             :outbound []
             :effects (conj base-effects {:type :acme/challenge-cleared :token token})})

          ;; TLS Bundle Broadcast
          :tls/bundle
          (let [bundle {:cert-pem (:cert-pem msg)
                        :key-pem (:key-pem msg)
                        :expires-at (:expires-at msg)}
                st' (assoc st :tls-bundle bundle)
                reply {:to pid
                       :channel :control
                       :message {:type :tls/bundle-ack
                                 :from (:node-id st')}}]
            {:state st'
             :outbound [reply]
             :effects (conj base-effects (assoc bundle :type :tls/install-bundle))})

          ;; TLS Bundle ACK
          :tls/bundle-ack
          {:state st
           :outbound []
           :effects base-effects}

          ;; Inbound Email Replicated
          :smtp/mail-received
          (let [mail-id (:id msg)
                already-seen? (contains? (:received-mail-ids st) mail-id)]
            (if already-seen?
              {:state st :outbound [] :effects base-effects}
              (let [st' (update st :received-mail-ids conj mail-id)]
                {:state st'
                 :outbound []
                 :effects (conj base-effects {:type :smtp/save-replicated-mail :mail (:mail msg)})})))

          ;; Default / Unknown message
          {:state st :outbound [] :effects base-effects}))

      ;; -----------------------------------------------------------------------
      ;; Local Commands (Leader or Node initiated)
      ;; -----------------------------------------------------------------------
      :cluster/publish-acme-challenge
      (let [token (:token event)
            key-auth (:key-auth event)
            dns-txt (:dns-txt event)
            st (cond-> (-> state
                           (assoc-in [:acme-challenges token] key-auth)
                           (assoc-in [:pending-challenge-acks token] #{(:node-id state)}))
                 dns-txt (assoc-in [:acme-dns-challenges "_acme-challenge"] [dns-txt]))
            broadcast {:to :all
                       :channel :control
                       :message {:type :acme/challenge-set
                                 :from (:node-id st)
                                 :token token
                                 :key-auth key-auth
                                 :dns-txt dns-txt}}
            needed-peers (set (:healthy-nodes st))
            immediate-quorum? (<= (count needed-peers) 1)
            effects (cond-> (conj next-effects {:type :acme/challenge-updated :token token :key-auth key-auth})
                      immediate-quorum? (conj {:type :acme/challenge-quorum-reached :token token}))]
        {:state st
         :outbound [broadcast]
         :effects effects})

      :cluster/clear-acme-challenge
      (let [token (:token event)
            st (-> state
                   (update :acme-challenges dissoc token)
                   (update :acme-dns-challenges dissoc "_acme-challenge")
                   (update :pending-challenge-acks dissoc token))
            broadcast {:to :all
                       :channel :control
                       :message {:type :acme/challenge-clear
                                 :from (:node-id st)
                                 :token token}}]
        {:state st
         :outbound [broadcast]
         :effects (conj next-effects {:type :acme/challenge-cleared :token token})})

      :cluster/publish-tls-bundle
      (let [bundle {:cert-pem (:cert-pem event)
                    :key-pem (:key-pem event)
                    :expires-at (:expires-at event)}
            st (assoc state :tls-bundle bundle)
            broadcast {:to :all
                       :channel :control
                       :message (assoc bundle
                                       :type :tls/bundle
                                       :from (:node-id st))}]
        {:state st
         :outbound [broadcast]
         :effects next-effects})

      :cluster/replicate-mail
      (let [mail (:mail event)
            mail-id (or (:id mail) (str (java.util.UUID/randomUUID)))
            st (update state :received-mail-ids conj mail-id)
            broadcast {:to :all
                       :channel :control
                       :message {:type :smtp/mail-received
                                 :from (:node-id st)
                                 :id mail-id
                                 :mail (dissoc mail :file)}}]
        {:state st
         :outbound [broadcast]
         :effects next-effects})

      ;; Default unrecognized event
      {:state state :outbound [] :effects next-effects})))
