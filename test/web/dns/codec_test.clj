(ns web.dns.codec-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.dns.codec :as codec]))

(deftest test-encode-decode-header
  (testing "round-trip preservation of DNS header flags"
    (let [pkt {:id 4660
               :qr? true
               :opcode 0
               :aa? true
               :tc? false
               :rd? true
               :ra? false
               :z 0
               :rcode :noerror
               :questions []
               :answers []
               :authority []
               :additional []}
          wire (codec/encode-packet pkt)
          decoded (codec/decode-packet wire)]
      (is (= 4660 (:id decoded)))
      (is (true? (:qr? decoded)))
      (is (= 0 (:opcode decoded)))
      (is (true? (:aa? decoded)))
      (is (false? (:tc? decoded)))
      (is (true? (:rd? decoded)))
      (is (false? (:ra? decoded)))
      (is (= :noerror (:rcode decoded))))))

(deftest test-0x20-case-preservation
  (testing "preserves exact mixed ASCII casing in questions"
    (let [qname "wWw.ExAmPlE.cOm"
          pkt {:id 100
               :qr? false
               :opcode 0
               :aa? false
               :tc? false
               :rd? true
               :ra? false
               :rcode :noerror
               :questions [{:qname qname :qtype :A :qclass :IN}]
               :answers []
               :authority []
               :additional []}
          wire (codec/encode-packet pkt)
          decoded (codec/decode-packet wire)
          q (first (:questions decoded))]
      (is (= qname (:qname q)))
      (is (= "www.example.com" (:qname-lower q)))
      (is (= :A (:qtype q)))
      (is (= :IN (:qclass q))))))

(deftest test-record-types-roundtrip
  (testing "A, AAAA, NS, SOA, MX, TXT, CAA record types round-trip cleanly"
    (let [soa {:mname "ns1.example.com"
               :rname "hostmaster.example.com"
               :serial 2026102901
               :refresh 3600
               :retry 600
               :expire 604800
               :minimum 60}
          mx {:preference 10 :exchange "ns1.example.com"}
          caa {:flags 0 :tag "issue" :value "letsencrypt.org"}
          pkt {:id 200
               :qr? true
               :opcode 0
               :aa? true
               :tc? false
               :rd? false
               :ra? false
               :rcode :noerror
               :questions [{:qname "example.com" :qtype :ANY :qclass :IN}]
               :answers [{:name "example.com" :type :A :class :IN :ttl 60 :rdata "1.2.3.4"}
                         {:name "example.com" :type :AAAA :class :IN :ttl 60 :rdata "2001:db8::1"}
                         {:name "example.com" :type :NS :class :IN :ttl 3600 :rdata "ns1.example.com"}
                         {:name "example.com" :type :SOA :class :IN :ttl 60 :rdata soa}
                         {:name "example.com" :type :MX :class :IN :ttl 60 :rdata mx}
                         {:name "example.com" :type :TXT :class :IN :ttl 60 :rdata ["v=spf1 -all"]}
                         {:name "example.com" :type :CAA :class :IN :ttl 60 :rdata caa}]
               :authority []
               :additional []}
          wire (codec/encode-packet pkt)
          decoded (codec/decode-packet wire)]
      (is (= 7 (count (:answers decoded))))
      (let [[a aaaa ns-rec soa-rec mx-rec txt-rec caa-rec] (:answers decoded)]
        (is (= "1.2.3.4" (:rdata a)))
        (is (= "2001:db8:0:0:0:0:0:1" (:rdata aaaa)))
        (is (= "ns1.example.com" (:rdata ns-rec)))
        (is (= soa (:rdata soa-rec)))
        (is (= mx (:rdata mx-rec)))
        (is (= ["v=spf1 -all"] (:rdata txt-rec)))
        (is (= caa (:rdata caa-rec)))))))

(deftest test-pointer-compression
  (testing "repeated domain suffixes use RFC 1035 pointer compression"
    (let [pkt {:id 300
               :qr? true
               :opcode 0
               :aa? true
               :tc? false
               :rd? false
               :ra? false
               :rcode :noerror
               :questions [{:qname "example.com" :qtype :NS :qclass :IN}]
               :answers [{:name "example.com" :type :NS :class :IN :ttl 3600 :rdata "ns1.example.com"}
                         {:name "example.com" :type :NS :class :IN :ttl 3600 :rdata "ns2.example.com"}
                         {:name "example.com" :type :NS :class :IN :ttl 3600 :rdata "ns3.example.com"}]
               :authority []
               :additional []}
          wire (codec/encode-packet pkt)
          decoded (codec/decode-packet wire)]
      ;; Wire size with compression should be much smaller than uncompressed (~100 bytes vs ~170 bytes)
      (is (< (alength wire) 120))
      (is (= 3 (count (:answers decoded))))
      (is (= ["ns1.example.com" "ns2.example.com" "ns3.example.com"]
             (mapv :rdata (:answers decoded)))))))

(deftest test-malformed-packets-safety
  (testing "malformed wire inputs throw ex-info with {:type :dns/formerr}"
    ;; 1. Too short for header
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Packet too short"
                          (codec/decode-packet (byte-array 8))))

    ;; 2. Pointer loop
    (let [buf (byte-array [0 1 ;; id
                           0 0 ;; flags
                           0 1 ;; qdcount = 1
                           0 0 0 0 0 0
                           ;; Pointer at offset 12 pointing back to offset 12
                           (unchecked-byte 0xC0) 12
                           0 1 0 1])]
      (is (thrown? clojure.lang.ExceptionInfo (codec/decode-packet buf))))

    ;; 3. Pointer out of bounds
    (let [buf (byte-array [0 1 0 0 0 1 0 0 0 0 0 0
                           (unchecked-byte 0xC0) (unchecked-byte 250)
                           0 1 0 1])]
      (is (thrown? clojure.lang.ExceptionInfo (codec/decode-packet buf))))))

(deftest test-udp-512-truncation
  (testing "encode-packet with max-bytes 512 cleanly sets TC=1 on overflow"
    (let [many-txt (vec (for [i (range 40)]
                          {:name "example.com"
                           :type :TXT
                           :class :IN
                           :ttl 60
                           :rdata [(str "long-txt-record-padding-content-number-" i "-abcdefghijklmnopqrstuvwxyz0123456789")]}))
          pkt {:id 400
               :qr? true
               :opcode 0
               :aa? true
               :tc? false
               :rd? false
               :ra? false
               :rcode :noerror
               :questions [{:qname "example.com" :qtype :TXT :qclass :IN}]
               :answers many-txt
               :authority []
               :additional []}
          ;; 1. Full encoding exceeds 512
          full-wire (codec/encode-packet pkt {:max-bytes 65535})
          _ (is (> (alength full-wire) 512))

          ;; 2. UDP 512 encoding triggers TC=1 truncation
          udp-wire (codec/encode-packet pkt {:max-bytes 512})
          decoded-udp (codec/decode-packet udp-wire)]
      (is (<= (alength udp-wire) 512))
      (is (true? (:tc? decoded-udp)))
      (is (= 1 (count (:questions decoded-udp))))
      (is (= "example.com" (:qname (first (:questions decoded-udp)))))
      (is (empty? (:answers decoded-udp))))))

;; Property-based test
(def gen-label
  (gen/such-that #(and (pos? (count %)) (<= (count %) 20))
                 (gen/fmap (fn [chars] (apply str chars))
                           (gen/not-empty (gen/vector (gen/elements (map char (concat (range 97 123) (range 65 91)))) 1 10)))))

(def gen-domain
  (gen/fmap (fn [labels] (str/join "." labels))
            (gen/vector gen-label 1 3)))

(defspec prop-roundtrip-a-records
  100
  (prop/for-all [id (gen/choose 0 65535)
                 domain gen-domain
                 b0 (gen/choose 1 254)
                 b1 (gen/choose 0 254)
                 b2 (gen/choose 0 254)
                 b3 (gen/choose 1 254)]
                (let [ip (str b0 "." b1 "." b2 "." b3)
                      pkt {:id id
                           :qr? true
                           :opcode 0
                           :aa? true
                           :tc? false
                           :rd? true
                           :ra? false
                           :rcode :noerror
                           :questions [{:qname domain :qtype :A :qclass :IN}]
                           :answers [{:name domain :type :A :class :IN :ttl 60 :rdata ip}]
                           :authority []
                           :additional []}
                      wire (codec/encode-packet pkt)
                      decoded (codec/decode-packet wire)
                      ans (first (:answers decoded))]
                  (and (= id (:id decoded))
                       (= domain (:qname (first (:questions decoded))))
                       (= :A (:type ans))
                       (= ip (:rdata ans))))))
