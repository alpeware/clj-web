(ns web.dns.server-test
  (:require [clojure.test :refer [deftest is testing]]
            [web.config :as cfg]
            [web.dns.codec :as codec]
            [web.dns.server :as server])
  (:import [java.io DataInputStream DataOutputStream]
           [java.net DatagramPacket DatagramSocket InetAddress Socket]))

(defn- send-udp-query [^String host ^long port query-pkt]
  (let [wire (codec/encode-packet query-pkt {:max-bytes 512})
        socket (DatagramSocket.)]
    (.setSoTimeout socket 3000)
    (try
      (let [addr (InetAddress/getByName host)
            packet (DatagramPacket. wire (alength wire) addr (int port))]
        (.send socket packet)
        (let [recv-buf (byte-array 1500)
              recv-packet (DatagramPacket. recv-buf (alength recv-buf))]
          (.receive socket recv-packet)
          (let [resp-bytes (byte-array (.getLength recv-packet))]
            (System/arraycopy recv-buf 0 resp-bytes 0 (.getLength recv-packet))
            (codec/decode-packet resp-bytes))))
      (finally
        (.close socket)))))

(defn- send-tcp-query [^String host ^long port query-pkt]
  (let [wire (codec/encode-packet query-pkt {:max-bytes 65535})
        socket (Socket. host (int port))]
    (.setSoTimeout socket 3000)
    (try
      (with-open [out (DataOutputStream. (.getOutputStream socket))
                  in (DataInputStream. (.getInputStream socket))]
        (.writeShort out (alength wire))
        (.write out wire 0 (alength wire))
        (.flush out)
        (let [resp-len (.readUnsignedShort in)
              resp-bytes (byte-array resp-len)]
          (.readFully in resp-bytes)
          (codec/decode-packet resp-bytes)))
      (finally
        (.close socket)))))

(defn- find-free-port []
  (try
    (with-open [s (java.net.ServerSocket. 0)]
      (.getLocalPort s))
    (catch Exception _ 15353)))

(deftest test-live-dns-server-udp-and-tcp
  (testing "live DNS server handles UDP, TCP, and TC=1 truncation fallback"
    (let [many-txt (vec (for [i (range 25)]
                          (str "dns-large-txt-record-for-truncation-testing-padding-" i "-abcdefghijklmnopqrstuvwxyz0123456789")))
          port (find-free-port)
          config (cfg/normalize-config
                  {:node/id :ns1
                   :domain "example.com"
                   :cluster {:allow-unauthenticated? true
                             :nodes {:ns1 {:ip4 "127.0.0.1" :ip6 nil}
                                     :ns2 {:ip4 "127.0.0.2" :ip6 nil}}}
                   :dns {:bind-ip "127.0.0.1"
                         :port port
                         :subdomains #{"@" "www" "big"}
                         :txt-records {"big" many-txt}}})
          cluster-st (atom {:healthy-nodes #{:ns1 :ns2}})
          server (server/start-dns-server! config cluster-st)
          udp-port (:udp-port server)
          tcp-port (:tcp-port server)]
      (is (pos? udp-port))
      (is (pos? tcp-port))
      (try
        ;; 1. Simple UDP query
        (let [query {:id 1001
                     :qr? false
                     :opcode 0
                     :aa? false
                     :tc? false
                     :rd? true
                     :ra? false
                     :rcode :noerror
                     :questions [{:qname "example.com" :qtype :A :qclass :IN}]
                     :answers []
                     :authority []
                     :additional []}
              resp (send-udp-query "127.0.0.1" udp-port query)]
          (is (= 1001 (:id resp)))
          (is (true? (:qr? resp)))
          (is (true? (:aa? resp)))
          (is (false? (:tc? resp)))
          (is (= :noerror (:rcode resp)))
          (is (seq (:answers resp)))
          (is (= #{"127.0.0.1" "127.0.0.2"} (set (map :rdata (:answers resp))))))

        ;; 2. Out-of-zone query over UDP returns REFUSED
        (let [query {:id 1002
                     :qr? false
                     :questions [{:qname "out-of-zone.org" :qtype :A :qclass :IN}]}
              resp (send-udp-query "127.0.0.1" udp-port query)]
          (is (= :refused (:rcode resp)))
          (is (empty? (:answers resp))))

        ;; 3. Unknown subdomain over UDP returns NXDOMAIN
        (let [query {:id 1003
                     :qr? false
                     :questions [{:qname "unknown.example.com" :qtype :A :qclass :IN}]}
              resp (send-udp-query "127.0.0.1" udp-port query)]
          (is (= :nxdomain (:rcode resp)))
          (is (seq (:authority resp))))

        ;; 4. Large TXT query over UDP triggers TC=1 (truncation)
        (let [query {:id 1004
                     :qr? false
                     :questions [{:qname "big.example.com" :qtype :TXT :qclass :IN}]}
              resp-udp (send-udp-query "127.0.0.1" udp-port query)]
          (is (= 1004 (:id resp-udp)))
          (is (true? (:tc? resp-udp)))
          (is (empty? (:answers resp-udp)))

          ;; 5. Client falls back to TCP and gets all TXT records cleanly
          (let [resp-tcp (send-tcp-query "127.0.0.1" tcp-port query)]
            (is (= 1004 (:id resp-tcp)))
            (is (false? (:tc? resp-tcp)))
            (is (= :noerror (:rcode resp-tcp)))
            (is (= 25 (count (:answers resp-tcp))))
            (is (= many-txt (mapv (comp first :rdata) (:answers resp-tcp))))))

        (finally
          (server/stop-dns-server! server))))))
