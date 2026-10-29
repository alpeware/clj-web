(ns web.cluster.mesh-test
  "Integration and lifecycle tests for cluster mesh transport.
   Tests deterministic ICE credential derivation, DTLS fingerprint verification,
   node identity persistence, in-memory 3-node cluster lifecycle with leader election,
   ACME challenge replication + quorum ACK, TLS bundle distribution,
   inbound email replication to disk, and live datachannel WebRTC communication."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [datachannel.api :as api]
            [web.cluster.mesh :as mesh]
            [web.tls.context :as tls])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- create-temp-dir []
  (.toFile (Files/createTempDirectory "mesh-test" (into-array FileAttribute []))))

(defn- delete-dir-recursively [f]
  (when (.exists f)
    (doseq [child (.listFiles f)]
      (if (.isDirectory child)
        (delete-dir-recursively child)
        (.delete child)))
    (.delete f)))

;; ---------------------------------------------------------------------------
;; Unit Tests: ICE Credentials & DTLS Fingerprints
;; ---------------------------------------------------------------------------

(deftest test-deterministic-ice-creds
  (testing "generates stable ufrag (8 chars) and pwd (24 chars)"
    (let [c1 (mesh/deterministic-ice-creds :ns1)
          c2 (mesh/deterministic-ice-creds :ns1)
          c3 (mesh/deterministic-ice-creds :ns2)]
      (is (= 8 (count (:ufrag c1))))
      (is (= 24 (count (:pwd c1))))
      (is (= c1 c2) "Deterministic across repeated calls with same node-id")
      (is (not= (:ufrag c1) (:ufrag c3)) "Different node-ids produce different ufrag")
      (is (not= (:pwd c1) (:pwd c3)) "Different node-ids produce different pwd"))))

(deftest test-verify-peer-fingerprint
  (let [fp1 "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        fp2 "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF"
        cfg {:cluster {:nodes {:ns1 {:fingerprint fp1}
                               :ns2 {:fingerprint nil}
                               :ns3 {:fingerprint ""}}}}]
    (testing "exact matching fingerprint returns true"
      (is (true? (mesh/verify-peer-fingerprint? cfg :ns1 fp1))))

    (testing "case-insensitive and trimmed matching returns true"
      (is (true? (mesh/verify-peer-fingerprint? cfg :ns1 (str "  " (str/lower-case fp1) "  ")))))

    (testing "mismatching fingerprint returns false"
      (is (false? (mesh/verify-peer-fingerprint? cfg :ns1 fp2))))

    (testing "nil or blank configured fingerprint allows connection"
      (is (true? (mesh/verify-peer-fingerprint? cfg :ns2 fp2)))
      (is (true? (mesh/verify-peer-fingerprint? cfg :ns3 fp2)))
      (is (true? (mesh/verify-peer-fingerprint? cfg :unknown-node fp2))))))

;; ---------------------------------------------------------------------------
;; Unit Tests: Node Identity Persistence
;; ---------------------------------------------------------------------------

(deftest test-load-or-create-node-identity
  (let [dir (create-temp-dir)]
    (try
      (testing "generates and persists node identity on first call"
        (let [id1 (mesh/load-or-create-node-identity! dir :ns1)
              id-file (io/file dir "cluster" "node-identity.edn")]
          (is (.exists id-file) "Identity file was written to disk")
          (is (some? (:cert id1)))
          (is (some? (:key id1)))
          (is (string? (:fingerprint id1)))
          (is (some? (:ice-creds id1)))
          (is (= 8 (count (get-in id1 [:ice-creds :ufrag]))))

          (testing "loads existing persisted identity on second call"
            (let [id2 (mesh/load-or-create-node-identity! dir :ns1)]
              (is (= (:fingerprint id1) (:fingerprint id2)))
              (is (= (:ice-creds id1) (:ice-creds id2)))
              (is (= (tls/encode-cert-pem (:cert id1))
                     (tls/encode-cert-pem (:cert id2))))))))
      (finally
        (delete-dir-recursively dir)))))

;; ---------------------------------------------------------------------------
;; Integration Tests: 3-Node In-Memory Cluster Control Plane
;; ---------------------------------------------------------------------------

(deftest test-in-memory-3-node-cluster-lifecycle
  (let [dir1 (create-temp-dir)
        dir2 (create-temp-dir)
        dir3 (create-temp-dir)
        base-cfg {:cluster {:nodes {:ns1 {:ip "127.0.0.1" :port 5001}
                                    :ns2 {:ip "127.0.0.1" :port 5002}
                                    :ns3 {:ip "127.0.0.1" :port 5003}}
                            :heartbeat-interval-ms 10000
                            :heartbeat-timeout-ms 30000}}
        cfg1 (assoc base-cfg :node/id :ns1 :state-dir (str dir1))
        cfg2 (assoc base-cfg :node/id :ns2 :state-dir (str dir2))
        cfg3 (assoc base-cfg :node/id :ns3 :state-dir (str dir3))

        challenges1 (atom {})
        challenges2 (atom {})
        challenges3 (atom {})

        tls1 (tls/init-tls-manager! {:state-dir (str dir1) :domain "alpeware.com"})
        tls2 (tls/init-tls-manager! {:state-dir (str dir2) :domain "alpeware.com"})
        tls3 (tls/init-tls-manager! {:state-dir (str dir3) :domain "alpeware.com"})

        elected1 (promise)
        mgr1 (mesh/start-cluster! cfg1 tls1 challenges1
                                  {:transport :in-memory
                                   :on-leader-elected (fn [leader term]
                                                        (deliver elected1 [leader term]))})
        mgr2 (mesh/start-cluster! cfg2 tls2 challenges2 {:transport :in-memory})
        mgr3 (mesh/start-cluster! cfg3 tls3 challenges3 {:transport :in-memory})]
    (try
      ;; Cross-wire the 3 nodes' in-memory transport send functions
      (let [mgrs {:ns1 mgr1 :ns2 mgr2 :ns3 mgr3}]
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
        ((:dispatch-event! mgr1) {:type :cluster/peer-connected :peer-id :ns2} now)
        ((:dispatch-event! mgr1) {:type :cluster/peer-connected :peer-id :ns3} now)
        ((:dispatch-event! mgr2) {:type :cluster/peer-connected :peer-id :ns1} now)
        ((:dispatch-event! mgr2) {:type :cluster/peer-connected :peer-id :ns3} now)
        ((:dispatch-event! mgr3) {:type :cluster/peer-connected :peer-id :ns1} now)
        ((:dispatch-event! mgr3) {:type :cluster/peer-connected :peer-id :ns2} now))

      (testing "leader election: ns1 is elected leader with term 1"
        (let [[leader term] (deref elected1 3000 nil)]
          (is (= :ns1 leader))
          (is (= 1 term)))
        (is (= :leader (:role @(:state-atom mgr1))))
        (is (= :ns1 (:leader-id @(:state-atom mgr1))))
        (is (= :follower (:role @(:state-atom mgr2))))
        (is (= :ns1 (:leader-id @(:state-atom mgr2))))
        (is (= :follower (:role @(:state-atom mgr3))))
        (is (= :ns1 (:leader-id @(:state-atom mgr3)))))

      (testing "ACME challenge replication and quorum acknowledgment"
        (let [token "token-test-12345"
              key-auth "auth-test-key-67890"
              dns-txt "dns-txt-verification"
              quorum-ok? (mesh/publish-acme-challenge! mgr1 token key-auth dns-txt 3000)]
          (is (true? quorum-ok?) "Quorum ACK returned true within timeout")
          (is (= key-auth (get @challenges1 token)) "Token present on leader")
          (is (= key-auth (get @challenges2 token)) "Token replicated to node 2")
          (is (= key-auth (get @challenges3 token)) "Token replicated to node 3")

          (testing "clearing ACME challenge clears token across all nodes"
            (mesh/clear-acme-challenge! mgr1 token)
            (is (nil? (get @challenges1 token)))
            (is (nil? (get @challenges2 token)))
            (is (nil? (get @challenges3 token))))))

      (testing "TLS bundle broadcast and dynamic installation on followers"
        (let [new-cert-data (tls/generate-self-signed-cert "alpeware.com" 60)
              cert-pem (tls/encode-cert-pem (:certificate new-cert-data))
              key-pem (tls/encode-private-key-pem (:private-key new-cert-data))
              expires-at (:expires-at new-cert-data)
              orig-cert-2 (first (:certificates @(:bundle-atom tls2)))
              orig-cert-3 (first (:certificates @(:bundle-atom tls3)))]
          (mesh/publish-tls-bundle! mgr1 cert-pem key-pem expires-at)
          ;; Verify followers updated their dynamic bundle-atom
          (let [updated-cert-2 (first (:certificates @(:bundle-atom tls2)))
                updated-cert-3 (first (:certificates @(:bundle-atom tls3)))]
            (is (not= orig-cert-2 updated-cert-2))
            (is (not= orig-cert-3 updated-cert-3))
            (is (= (quot expires-at 1000) (quot (:expires-at @(:bundle-atom tls2)) 1000)))
            (is (= (quot expires-at 1000) (quot (:expires-at @(:bundle-atom tls3)) 1000))))))

      (testing "Inbound email replication to disk on peers"
        (let [mail {:id "mail-uuid-cluster-test"
                    :from "sender@example.org"
                    :recipients ["admin@alpeware.com"]
                    :subject "Cluster Email Replication"
                    :raw-eml "From: sender@example.org\r\nSubject: Cluster Email Replication\r\n\r\nThis email was received by ns2 and replicated to ns1 and ns3."}]
          ;; ns2 receives and replicates
          (mesh/replicate-mail! mgr2 mail)
          ;; Verify ns1 and ns3 persisted .eml files to disk
          (let [mail-dir-1 (io/file dir1 "mail")
                mail-dir-3 (io/file dir3 "mail")
                files-1 (.listFiles mail-dir-1)
                files-3 (.listFiles mail-dir-3)]
            (is (seq files-1) "Node 1 created .eml file in state-dir/mail")
            (is (seq files-3) "Node 3 created .eml file in state-dir/mail")
            (let [content-1 (slurp (first files-1))
                  content-3 (slurp (first files-3))]
              (is (str/includes? content-1 "Cluster Email Replication"))
              (is (str/includes? content-1 "sender@example.org"))
              (is (str/includes? content-3 "Cluster Email Replication"))
              (is (str/includes? content-3 "sender@example.org"))))))
      (finally
        (mesh/stop-cluster! mgr1)
        (mesh/stop-cluster! mgr2)
        (mesh/stop-cluster! mgr3)
        (delete-dir-recursively dir1)
        (delete-dir-recursively dir2)
        (delete-dir-recursively dir3)))))

;; ---------------------------------------------------------------------------
;; Integration Test: Live WebRTC DataChannel Communication over UDP
;; ---------------------------------------------------------------------------

(deftest test-live-datachannel-webrtc-transport
  (testing "establishes live WebRTC DataChannel connection and exchanges data"
    (let [port1 15481
          port2 15482
          node1 (api/create-node {:port port1 :setup "active"})
          node2 (api/create-node {:port port2 :setup "passive"})
          sdp1 (:local-sdp-params node1)
          sdp2 (:local-sdp-params node2)
          opened-prom (promise)
          msg-received-prom (promise)
          cbs2 {:on-open (fn [_e])
                :on-message (fn [e]
                              (deliver msg-received-prom (:payload e)))}
          cbs1 {:on-open (fn [e]
                           (when-not (:channel-id e)
                             (let [cid (api/create-data-channel! node1 "control" {:ordered true})]
                               (deliver opened-prom cid))))}]
      (try
        (api/start! node2 {:ip "127.0.0.1"
                           :port port1
                           :fingerprint (:fingerprint sdp1)
                           :remote-ice-ufrag (:ice-ufrag sdp1)
                           :remote-ice-pwd (:ice-pwd sdp1)}
                    cbs2)
        (api/start! node1 {:ip "127.0.0.1"
                           :port port2
                           :fingerprint (:fingerprint sdp2)
                           :remote-ice-ufrag (:ice-ufrag sdp2)
                           :remote-ice-pwd (:ice-pwd sdp2)}
                    cbs1)
        (let [cid (deref opened-prom 8000 nil)]
          (is (some? cid) "DataChannel opened successfully")
          (when cid
            (Thread/sleep 200)
            (api/send! node1 "ping-from-active-node" cid)
            (let [payload (deref msg-received-prom 5000 nil)
                  text (if (string? payload)
                         payload
                         (when payload
                           (String. ^bytes payload java.nio.charset.StandardCharsets/UTF_8)))]
              (is (= "ping-from-active-node" text) "Message arrived on remote passive node"))))
        (finally
          (api/close! node1)
          (api/close! node2))))))
