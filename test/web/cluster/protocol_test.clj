(ns web.cluster.protocol-test
  "Unit and property tests for pure cluster protocol state machine.
   Tests peer liveness tracking, quorum-backed Bully leader election,
   split-brain immunity, ACME challenge replication, TLS bundle distribution,
   and email replication."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.cluster.protocol :as protocol]))

;; ---------------------------------------------------------------------------
;; Unit Tests: State Initialization & Liveness
;; ---------------------------------------------------------------------------

(deftest test-init-cluster-state
  (testing "3-node cluster initialization"
    (let [cfg {:node/id :ns1
               :cluster {:nodes {:ns1 {:ip "127.0.0.1" :port 5001}
                                 :ns2 {:ip "127.0.0.1" :port 5002}
                                 :ns3 {:ip "127.0.0.1" :port 5003}}
                         :heartbeat-interval-ms 3000
                         :heartbeat-timeout-ms 9000}}
          st (protocol/init-cluster-state cfg)]
      (is (= :ns1 (:node-id st)))
      (is (= #{:ns1 :ns2 :ns3} (:all-nodes st)))
      (is (= 3000 (:heartbeat-interval-ms st)))
      (is (= 9000 (:heartbeat-timeout-ms st)))
      (is (= #{:ns2 :ns3} (set (keys (:peers st)))))
      (is (= #{:ns1} (:healthy-nodes st)))
      (is (nil? (:leader-id st)))
      (is (= :follower (:role st)))
      (is (= 0 (:term st)))
      (is (= {} (:acme-challenges st)))
      (is (= {} (:acme-dns-challenges st)))
      (is (= {} (:pending-challenge-acks st)))
      (is (nil? (:tls-bundle st)))
      (is (= #{} (:received-mail-ids st)))))

  (testing "single-node cluster default initialization"
    (let [cfg {:node/id :ns1}
          st (protocol/init-cluster-state cfg)]
      (is (= :ns1 (:node-id st)))
      (is (= #{:ns1} (:all-nodes st)))
      (is (= 5000 (:heartbeat-interval-ms st)))
      (is (= 15000 (:heartbeat-timeout-ms st)))
      (is (= {} (:peers st)))
      (is (= #{:ns1} (:healthy-nodes st))))))

(deftest test-compute-healthy-nodes
  (let [st (-> (protocol/init-cluster-state {:node/id :ns1
                                             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}
                                                       :heartbeat-timeout-ms 15000}})
               (assoc-in [:peers :ns2 :last-seen-ms] 10000)
               (assoc-in [:peers :ns3 :last-seen-ms] 2000))]
    (testing "all peers within timeout are healthy"
      (is (= #{:ns1 :ns2 :ns3} (protocol/compute-healthy-nodes st 15000))))

    (testing "stale peer is excluded"
      ;; ns2: 22000 - 10000 = 12000 < 15000 (healthy)
      ;; ns3: 22000 - 2000 = 20000 >= 15000 (stale)
      (is (= #{:ns1 :ns2} (protocol/compute-healthy-nodes st 22000))))

    (testing "all peers stale returns only local node"
      (is (= #{:ns1} (protocol/compute-healthy-nodes st 30000))))

    (testing "peer never seen is excluded"
      (let [unseen-st (assoc-in st [:peers :ns2 :last-seen-ms] nil)]
        (is (= #{:ns1 :ns3} (protocol/compute-healthy-nodes unseen-st 15000)))))))

;; ---------------------------------------------------------------------------
;; Unit Tests: Bully Leader Election & Quorum Rule
;; ---------------------------------------------------------------------------

(deftest test-elect-leader-quorum-rule
  (testing "single-node cluster elects the local node"
    (is (= :ns1 (protocol/elect-leader #{:ns1} 1)))
    (is (nil? (protocol/elect-leader #{} 1)))
    (is (nil? (protocol/elect-leader #{} 0))))

  (testing "3-node cluster requires quorum (>= 2 reachable nodes)"
    ;; Full health: lowest lexicographical node wins (:ns1)
    (is (= :ns1 (protocol/elect-leader #{:ns1 :ns2 :ns3} 3)))

    ;; 2 of 3 healthy: quorum met
    (is (= :ns1 (protocol/elect-leader #{:ns1 :ns2} 3)))
    (is (= :ns1 (protocol/elect-leader #{:ns1 :ns3} 3)))
    ;; Failover: when ns1 is down, ns2 becomes leader
    (is (= :ns2 (protocol/elect-leader #{:ns2 :ns3} 3)))

    ;; Isolated partition (only 1 node reachable): QUORUM FAILS, returns nil!
    ;; Split-brain immunity: isolated node CANNOT elect itself leader
    (is (nil? (protocol/elect-leader #{:ns1} 3)))
    (is (nil? (protocol/elect-leader #{:ns2} 3)))
    (is (nil? (protocol/elect-leader #{:ns3} 3)))
    (is (nil? (protocol/elect-leader #{} 3)))))

;; ---------------------------------------------------------------------------
;; Unit Tests: State Machine Event Transitions
;; ---------------------------------------------------------------------------

(deftest test-handle-cluster-event-tick
  (let [cfg {:node/id :ns1
             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}
                       :heartbeat-interval-ms 5000
                       :heartbeat-timeout-ms 15000}}
        st (protocol/init-cluster-state cfg)]

    (testing "tick when isolated sends heartbeat but elects no leader"
      (let [res (protocol/handle-cluster-event st {:type :cluster/tick} 1000)]
        (is (= :follower (:role (:state res))))
        (is (nil? (:leader-id (:state res))))
        (is (= 0 (:term (:state res))))
        (is (= 1 (count (:outbound res))))
        (is (= :cluster/heartbeat (get-in (first (:outbound res)) [:message :type])))
        (is (= [] (:effects res)))))

    (testing "tick with quorum elects leader and emits :leader-elected effect"
      (let [st-quorum (assoc-in st [:peers :ns2 :last-seen-ms] 900)
            res (protocol/handle-cluster-event st-quorum {:type :cluster/tick} 1000)
            new-st (:state res)]
        (is (= :leader (:role new-st)))
        (is (= :ns1 (:leader-id new-st)))
        (is (= 1 (:term new-st)))
        (is (= [{:type :leader-elected :leader-id :ns1 :term 1}] (:effects res)))
        (is (= 1 (count (:outbound res))))
        (is (= :cluster/heartbeat (get-in (first (:outbound res)) [:message :type])))))

    (testing "subsequent tick while already leader does not duplicate :leader-elected effect"
      (let [st-leader (-> st
                          (assoc-in [:peers :ns2 :last-seen-ms] 900)
                          (assoc :role :leader :leader-id :ns1 :term 1))
            res (protocol/handle-cluster-event st-leader {:type :cluster/tick} 1000)]
        (is (= :leader (:role (:state res))))
        (is (= 1 (:term (:state res))))
        (is (= [] (:effects res)))))))

(deftest test-handle-cluster-event-peer-lifecycle
  (let [cfg {:node/id :ns1
             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}}
        st (protocol/init-cluster-state cfg)]

    (testing "peer-connected updates status, last-seen, and triggers election"
      (let [res (protocol/handle-cluster-event st {:type :cluster/peer-connected :peer-id :ns2} 1000)
            new-st (:state res)]
        (is (true? (get-in new-st [:peers :ns2 :connected?])))
        (is (= 1000 (get-in new-st [:peers :ns2 :last-seen-ms])))
        (is (= :leader (:role new-st)))
        (is (= :ns1 (:leader-id new-st)))))

    (testing "peer-connected sends tls-bundle if local node is leader with bundle"
      (let [st-with-bundle (assoc st
                                  :role :leader
                                  :leader-id :ns1
                                  :tls-bundle {:cert-pem "CERT" :key-pem "KEY" :expires-at 9999})
            res (protocol/handle-cluster-event st-with-bundle
                                               {:type :cluster/peer-connected :peer-id :ns2}
                                               1000)]
        (is (= 1 (count (:outbound res))))
        (let [msg (first (:outbound res))]
          (is (= :ns2 (:to msg)))
          (is (= :control (:channel msg)))
          (is (= :tls/bundle (get-in msg [:message :type])))
          (is (= "CERT" (get-in msg [:message :cert-pem]))))))

    (testing "peer-disconnected marks connected? false"
      (let [conn-st (assoc-in st [:peers :ns2 :connected?] true)
            res (protocol/handle-cluster-event conn-st {:type :cluster/peer-disconnected :peer-id :ns2} 1000)]
        (is (false? (get-in (:state res) [:peers :ns2 :connected?])))))))

(deftest test-handle-cluster-event-receive-heartbeat
  (let [cfg {:node/id :ns1
             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}}
        st (protocol/init-cluster-state cfg)
        hb-msg {:type :cluster/heartbeat
                :from :ns2
                :term 1
                :leader-id :ns1
                :cert-expires-at 123456789
                :now-ms 1000}
        res (protocol/handle-cluster-event st
                                           {:type :cluster/receive
                                            :from :ns2
                                            :message hb-msg}
                                           1000)
        new-st (:state res)]
    (is (= 1000 (get-in new-st [:peers :ns2 :last-seen-ms])))
    (is (= 123456789 (get-in new-st [:peers :ns2 :cert-expires-at])))
    (is (contains? (:healthy-nodes new-st) :ns2))))

(deftest test-acme-challenge-flow
  (let [cfg {:node/id :ns1
             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}}
        st (-> (protocol/init-cluster-state cfg)
               (assoc-in [:peers :ns2 :last-seen-ms] 900)
               (assoc-in [:peers :ns3 :last-seen-ms] 900)
               (assoc :role :leader :leader-id :ns1 :term 1))]

    (testing "leader publishes challenge: broadcasts to peers and tracks acks"
      (let [res (protocol/handle-cluster-event st
                                               {:type :cluster/publish-acme-challenge
                                                :token "tok-123"
                                                :key-auth "auth-456"
                                                :dns-txt "dns-txt-789"}
                                               1000)
            new-st (:state res)]
        (is (= "auth-456" (get-in new-st [:acme-challenges "tok-123"])))
        (is (= ["dns-txt-789"] (get-in new-st [:acme-dns-challenges "_acme-challenge"])))
        (is (= #{:ns1} (get-in new-st [:pending-challenge-acks "tok-123"])))
        (is (= 1 (count (:outbound res))))
        (let [broadcast (first (:outbound res))]
          (is (= :all (:to broadcast)))
          (is (= :acme/challenge-set (get-in broadcast [:message :type])))
          (is (= "tok-123" (get-in broadcast [:message :token]))))))

    (testing "follower receives :acme/challenge-set: updates local challenge and replies ack"
      (let [follower-st (-> (protocol/init-cluster-state {:node/id :ns2
                                                          :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}})
                            (assoc-in [:peers :ns1 :last-seen-ms] 900))
            msg {:type :acme/challenge-set
                 :from :ns1
                 :token "tok-123"
                 :key-auth "auth-456"
                 :dns-txt "dns-txt-789"}
            res (protocol/handle-cluster-event follower-st
                                               {:type :cluster/receive :from :ns1 :message msg}
                                               1000)
            new-st (:state res)]
        (is (= "auth-456" (get-in new-st [:acme-challenges "tok-123"])))
        (is (= ["dns-txt-789"] (get-in new-st [:acme-dns-challenges "_acme-challenge"])))
        (is (= [{:type :acme/challenge-updated :token "tok-123" :key-auth "auth-456"}]
               (:effects res)))
        (is (= 1 (count (:outbound res))))
        (let [ack (first (:outbound res))]
          (is (= :ns1 (:to ack)))
          (is (= :acme/challenge-ack (get-in ack [:message :type])))
          (is (= "tok-123" (get-in ack [:message :token]))))))

    (testing "leader receives acks until quorum reached"
      (let [pub-st (-> st
                       (assoc-in [:acme-challenges "tok-123"] "auth-456")
                       (assoc-in [:pending-challenge-acks "tok-123"] #{:ns1}))
            ;; First ACK from ns2
            res1 (protocol/handle-cluster-event pub-st
                                                {:type :cluster/receive
                                                 :from :ns2
                                                 :message {:type :acme/challenge-ack :token "tok-123"}}
                                                1000)
            st1 (:state res1)]
        (is (= #{:ns1 :ns2} (get-in st1 [:pending-challenge-acks "tok-123"])))
        ;; Healthy nodes: #{:ns1 :ns2 :ns3}, so quorum not yet complete (ns3 missing)
        (is (not-any? #(= (:type %) :acme/challenge-quorum-reached) (:effects res1)))

        ;; Second ACK from ns3 -> Quorum complete!
        (let [res2 (protocol/handle-cluster-event st1
                                                  {:type :cluster/receive
                                                   :from :ns3
                                                   :message {:type :acme/challenge-ack :token "tok-123"}}
                                                  1000)]
          (is (some #(= (:type %) :acme/challenge-quorum-reached) (:effects res2))))))

    (testing "clearing acme challenge broadcasts clear and removes locally"
      (let [set-st (-> st
                       (assoc-in [:acme-challenges "tok-123"] "auth-456")
                       (assoc-in [:acme-dns-challenges "_acme-challenge"] ["dns-txt-789"])
                       (assoc-in [:pending-challenge-acks "tok-123"] #{:ns1 :ns2 :ns3}))
            res (protocol/handle-cluster-event set-st
                                               {:type :cluster/clear-acme-challenge :token "tok-123"}
                                               1000)
            new-st (:state res)]
        (is (nil? (get-in new-st [:acme-challenges "tok-123"])))
        (is (nil? (get-in new-st [:acme-dns-challenges "_acme-challenge"])))
        (is (nil? (get-in new-st [:pending-challenge-acks "tok-123"])))
        (is (= 1 (count (:outbound res))))
        (is (= :acme/challenge-clear (get-in (first (:outbound res)) [:message :type])))))))

(deftest test-tls-bundle-flow
  (let [cfg {:node/id :ns1
             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}}
        st (-> (protocol/init-cluster-state cfg)
               (assoc-in [:peers :ns2 :last-seen-ms] 900)
               (assoc :role :leader :leader-id :ns1 :term 1))]

    (testing "leader publishes tls-bundle: broadcasts to all peers"
      (let [res (protocol/handle-cluster-event st
                                               {:type :cluster/publish-tls-bundle
                                                :cert-pem "CERT-PEM"
                                                :key-pem "KEY-PEM"
                                                :expires-at 999999}
                                               1000)
            new-st (:state res)]
        (is (= {:cert-pem "CERT-PEM" :key-pem "KEY-PEM" :expires-at 999999}
               (:tls-bundle new-st)))
        (is (= 1 (count (:outbound res))))
        (let [bcast (first (:outbound res))]
          (is (= :all (:to bcast)))
          (is (= :tls/bundle (get-in bcast [:message :type])))
          (is (= "CERT-PEM" (get-in bcast [:message :cert-pem]))))))

    (testing "follower receives tls-bundle: stores bundle, replies ack, and emits :tls/install-bundle"
      (let [follower-st (protocol/init-cluster-state {:node/id :ns2
                                                      :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}})
            msg {:type :tls/bundle
                 :cert-pem "CERT-PEM"
                 :key-pem "KEY-PEM"
                 :expires-at 999999}
            res (protocol/handle-cluster-event follower-st
                                               {:type :cluster/receive :from :ns1 :message msg}
                                               1000)
            new-st (:state res)]
        (is (= {:cert-pem "CERT-PEM" :key-pem "KEY-PEM" :expires-at 999999}
               (:tls-bundle new-st)))
        (is (= 1 (count (:outbound res))))
        (is (= :tls/bundle-ack (get-in (first (:outbound res)) [:message :type])))
        (is (= [{:type :tls/install-bundle
                 :cert-pem "CERT-PEM"
                 :key-pem "KEY-PEM"
                 :expires-at 999999}]
               (:effects res)))))))

(deftest test-smtp-mail-replication-flow
  (let [cfg {:node/id :ns1
             :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}}
        st (protocol/init-cluster-state cfg)]

    (testing "local replicate-mail broadcasts :smtp/mail-received without :file"
      (let [mail {:id "mail-uuid-1"
                  :from "sender@example.com"
                  :recipients ["admin@alpeware.com"]
                  :body "Hello cluster!"
                  :file "/tmp/should-not-be-sent.eml"}
            res (protocol/handle-cluster-event st
                                               {:type :cluster/replicate-mail :mail mail}
                                               1000)
            new-st (:state res)]
        (is (contains? (:received-mail-ids new-st) "mail-uuid-1"))
        (is (= 1 (count (:outbound res))))
        (let [bcast (first (:outbound res))]
          (is (= :all (:to bcast)))
          (is (= :smtp/mail-received (get-in bcast [:message :type])))
          (is (= "mail-uuid-1" (get-in bcast [:message :id])))
          (is (nil? (get-in bcast [:message :mail :file])))
          (is (= "Hello cluster!" (get-in bcast [:message :mail :body]))))))

    (testing "follower receives new mail: emits :smtp/save-replicated-mail"
      (let [follower-st (protocol/init-cluster-state {:node/id :ns2
                                                      :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}})
            msg {:type :smtp/mail-received
                 :from :ns1
                 :id "mail-uuid-2"
                 :mail {:from "user@domain.com" :body "Replicated text"}}
            res (protocol/handle-cluster-event follower-st
                                               {:type :cluster/receive :from :ns1 :message msg}
                                               1000)]
        (is (contains? (:received-mail-ids (:state res)) "mail-uuid-2"))
        (is (= [{:type :smtp/save-replicated-mail
                 :mail {:from "user@domain.com" :body "Replicated text"}}]
               (:effects res)))))

    (testing "follower receives duplicate mail: deduplicates without emitting effect"
      (let [seen-st (-> (protocol/init-cluster-state {:node/id :ns2
                                                      :cluster {:nodes {:ns1 {} :ns2 {} :ns3 {}}}})
                        (update :received-mail-ids conj "mail-uuid-2"))
            msg {:type :smtp/mail-received
                 :from :ns1
                 :id "mail-uuid-2"
                 :mail {:from "user@domain.com" :body "Replicated text"}}
            res (protocol/handle-cluster-event seen-st
                                               {:type :cluster/receive :from :ns1 :message msg}
                                               1000)]
        (is (empty? (:effects res)))
        (is (empty? (:outbound res)))))))

;; ---------------------------------------------------------------------------
;; Generative Property Tests: Split-Brain Immunity Invariant
;; ---------------------------------------------------------------------------

(def ^:private gen-cluster-partition
  "Generates arbitrary network partitions of [:ns1 :ns2 :ns3] by assigning each node
   to an integer partition bucket (0, 1, or 2)."
  (gen/fmap (fn [[p1 p2 p3]]
              {:ns1 p1 :ns2 p2 :ns3 p3})
            (gen/vector (gen/choose 0 2) 3)))

(defn- partition->reachable-component
  [partition node-id]
  (let [bucket (get partition node-id)]
    (set (keep (fn [[n b]] (when (= b bucket) n)) partition))))

(defspec prop-cluster-no-split-brain 100
  (prop/for-all [partition gen-cluster-partition]
                (let [total-nodes 3
                      healthy-1 (partition->reachable-component partition :ns1)
                      healthy-2 (partition->reachable-component partition :ns2)
                      healthy-3 (partition->reachable-component partition :ns3)

                      leader-1 (protocol/elect-leader healthy-1 total-nodes)
                      leader-2 (protocol/elect-leader healthy-2 total-nodes)
                      leader-3 (protocol/elect-leader healthy-3 total-nodes)

                      self-claimed-leaders (cond-> #{}
                                             (= leader-1 :ns1) (conj :ns1)
                                             (= leader-2 :ns2) (conj :ns2)
                                             (= leader-3 :ns3) (conj :ns3))]

      ;; Invariant 1: Quorum rule ensures an isolated node (healthy count < 2) NEVER elects itself leader
                  (when (< (count healthy-1) 2) (is (nil? leader-1)))
                  (when (< (count healthy-2) 2) (is (nil? leader-2)))
                  (when (< (count healthy-3) 2) (is (nil? leader-3)))

      ;; Invariant 2: In any network partition, at most ONE node in the entire cluster
      ;; can simultaneously claim leadership! (Absolute Split-Brain Immunity!)
                  (is (<= (count self-claimed-leaders) 1))

      ;; Invariant 3: If all 3 nodes are in the same partition, they all agree on the same leader
                  (when (= healthy-1 healthy-2 healthy-3 #{:ns1 :ns2 :ns3})
                    (is (= leader-1 leader-2 leader-3 :ns1)))

      ;; Invariant 4: If all 3 nodes are completely isolated, no leader exists
                  (when (and (= healthy-1 #{:ns1}) (= healthy-2 #{:ns2}) (= healthy-3 #{:ns3}))
                    (is (= nil leader-1 leader-2 leader-3)))
                  true)))
