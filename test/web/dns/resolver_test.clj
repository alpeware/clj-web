(ns web.dns.resolver-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.config :as cfg]
            [web.dns.resolver :as resolver]))

(def test-config
  (cfg/normalize-config
   {:node/id :ns1
    :domain "example.com"
    :cluster {:allow-unauthenticated? true
              :nodes {:ns1 {:ip4 "34.10.10.1" :ip6 "2001:db8::1"}
                      :ns2 {:ip4 "34.10.10.2" :ip6 "2001:db8::2"}
                      :ns3 {:ip4 "34.10.10.3" :ip6 nil}}}
    :dns {:ttl-seconds 60
          :ns-ttl-seconds 3600
          :subdomains #{"@" "www" "docs" "mvn"}
          :txt-records {"@" ["v=spf1 -all"]
                        "_dmarc" ["v=DMARC1; p=reject; rua=mailto:postmaster@example.com"]}}}))

(deftest test-out-of-zone-refused
  (testing "queries outside the authoritative zone receive REFUSED with empty answers"
    (let [query {:id 101
                 :qr? false
                 :rd? true
                 :questions [{:qname "google.com" :qtype :A :qclass :IN}]}
          resp (resolver/resolve-query test-config {} query)]
      (is (= 101 (:id resp)))
      (is (true? (:qr? resp)))
      (is (false? (:aa? resp)))
      (is (false? (:ra? resp)))
      (is (= :refused (:rcode resp)))
      (is (empty? (:answers resp)))
      (is (= "google.com" (:qname (first (:questions resp))))))))

(deftest test-unknown-subdomain-nxdomain
  (testing "unknown in-zone subdomain returns NXDOMAIN and SOA in authority section"
    (let [query {:id 102
                 :qr? false
                 :rd? true
                 :questions [{:qname "nonexistent.example.com" :qtype :A :qclass :IN}]}
          resp (resolver/resolve-query test-config {} query)]
      (is (= 102 (:id resp)))
      (is (true? (:qr? resp)))
      (is (true? (:aa? resp)))
      (is (false? (:ra? resp)))
      (is (= :nxdomain (:rcode resp)))
      (is (empty? (:answers resp)))
      (is (= 1 (count (:authority resp))))
      (let [soa (first (:authority resp))]
        (is (= :SOA (:type soa)))
        (is (= "example.com" (:name soa)))
        (is (= "ns1.example.com" (get-in soa [:rdata :mname])))
        (is (= "hostmaster.example.com" (get-in soa [:rdata :rname])))))))

(deftest test-nameserver-glue-records
  (testing "ns1, ns2, ns3 resolve deterministically to static IPs with ns-ttl-seconds"
    (let [q-ns1 {:id 103 :qr? false :rd? false :questions [{:qname "ns1.example.com" :qtype :A :qclass :IN}]}
          r-ns1 (resolver/resolve-query test-config {} q-ns1)
          ans1 (first (:answers r-ns1))]
      (is (= :noerror (:rcode r-ns1)))
      (is (= "34.10.10.1" (:rdata ans1)))
      (is (= 3600 (:ttl ans1))))

    (let [q-ns2 {:id 104 :qr? false :rd? false :questions [{:qname "ns2.example.com" :qtype :A :qclass :IN}]}
          r-ns2 (resolver/resolve-query test-config {} q-ns2)
          ans2 (first (:answers r-ns2))]
      (is (= :noerror (:rcode r-ns2)))
      (is (= "34.10.10.2" (:rdata ans2)))
      (is (= 3600 (:ttl ans2))))

    (testing "ns1 AAAA resolves IPv6"
      (let [q-aaaa {:id 105 :qr? false :rd? false :questions [{:qname "ns1.example.com" :qtype :AAAA :qclass :IN}]}
            r-aaaa (resolver/resolve-query test-config {} q-aaaa)
            ans-aaaa (first (:answers r-aaaa))]
        (is (= :noerror (:rcode r-aaaa)))
        (is (= "2001:db8::1" (:rdata ans-aaaa)))
        (is (= 3600 (:ttl ans-aaaa)))))

    (testing "ns3 AAAA with nil IPv6 returns NOERROR with 0 answers and SOA in authority"
      (let [q-noip6 {:id 106 :qr? false :rd? false :questions [{:qname "ns3.example.com" :qtype :AAAA :qclass :IN}]}
            r-noip6 (resolver/resolve-query test-config {} q-noip6)]
        (is (= :noerror (:rcode r-noip6)))
        (is (empty? (:answers r-noip6)))
        (is (= :SOA (:type (first (:authority r-noip6)))))))))

(deftest test-healthy-nodes-filtering-and-fail-safe
  (testing "multi-A resolution filters by healthy nodes in cluster-state"
    (let [cluster-st {:healthy-nodes #{:ns1 :ns3}}
          q {:id 0 :qr? false :rd? false :questions [{:qname "www.example.com" :qtype :A :qclass :IN}]}
          resp (resolver/resolve-query test-config cluster-st q)
          ans-ips (set (map :rdata (:answers resp)))]
      (is (= :noerror (:rcode resp)))
      (is (= #{"34.10.10.1" "34.10.10.3"} ans-ips))
      (is (not (contains? ans-ips "34.10.10.2")))))

  (testing "fail-safe fallback returns local node IP when cluster state has no healthy peers"
    (let [cluster-st {:healthy-nodes #{}}
          q {:id 0 :qr? false :rd? false :questions [{:qname "example.com" :qtype :A :qclass :IN}]}
          resp (resolver/resolve-query test-config cluster-st q)]
      (is (= :noerror (:rcode resp)))
      (is (= ["34.10.10.1"] (mapv :rdata (:answers resp)))))))

(deftest test-round-robin-rotation
  (testing "query ID rotates multi-A answers"
    (let [cluster-st {:healthy-nodes #{:ns1 :ns2 :ns3}}
          q0 {:id 0 :qr? false :rd? false :questions [{:qname "example.com" :qtype :A :qclass :IN}]}
          q1 {:id 1 :qr? false :rd? false :questions [{:qname "example.com" :qtype :A :qclass :IN}]}
          resp0 (resolver/resolve-query test-config cluster-st q0)
          resp1 (resolver/resolve-query test-config cluster-st q1)
          ips0 (mapv :rdata (:answers resp0))
          ips1 (mapv :rdata (:answers resp1))]
      (is (= ["34.10.10.1" "34.10.10.2" "34.10.10.3"] ips0))
      (is (= ["34.10.10.2" "34.10.10.3" "34.10.10.1"] ips1)))))

(deftest test-apex-records
  (testing "NS query at apex returns ns1, ns2, ns3"
    (let [q {:id 201 :qr? false :questions [{:qname "example.com" :qtype :NS :qclass :IN}]}
          resp (resolver/resolve-query test-config {} q)]
      (is (= :noerror (:rcode resp)))
      (is (= ["ns1.example.com" "ns2.example.com" "ns3.example.com"]
             (mapv :rdata (:answers resp))))))

  (testing "MX query at apex returns configured MX records"
    (let [q {:id 202 :qr? false :questions [{:qname "example.com" :qtype :MX :qclass :IN}]}
          resp (resolver/resolve-query test-config {} q)]
      (is (= :noerror (:rcode resp)))
      (is (= [{:preference 10 :exchange "ns1.example.com"}
              {:preference 20 :exchange "ns2.example.com"}
              {:preference 30 :exchange "ns3.example.com"}]
             (mapv :rdata (:answers resp))))))

  (testing "CAA query at apex returns Let's Encrypt CAA"
    (let [q {:id 203 :qr? false :questions [{:qname "example.com" :qtype :CAA :qclass :IN}]}
          resp (resolver/resolve-query test-config {} q)]
      (is (= :noerror (:rcode resp)))
      (is (= [{:flags 0 :tag "issue" :value "letsencrypt.org"}]
             (mapv :rdata (:answers resp)))))))

(deftest test-txt-and-acme-challenges
  (testing "TXT queries resolve SPF, DMARC, and dynamic ACME challenges"
    ;; SPF on apex
    (let [q-spf {:id 301 :qr? false :questions [{:qname "example.com" :qtype :TXT :qclass :IN}]}
          r-spf (resolver/resolve-query test-config {} q-spf)]
      (is (= [["v=spf1 -all"]] (mapv :rdata (:answers r-spf)))))

    ;; DMARC
    (let [q-dmarc {:id 302 :qr? false :questions [{:qname "_dmarc.example.com" :qtype :TXT :qclass :IN}]}
          r-dmarc (resolver/resolve-query test-config {} q-dmarc)]
      (is (= [["v=DMARC1; p=reject; rua=mailto:postmaster@example.com"]]
             (mapv :rdata (:answers r-dmarc)))))

    ;; Dynamic ACME challenge from cluster-state
    (let [cluster-st {:acme-dns-challenges {"_acme-challenge" ["dns-token-12345"]}}
          q-acme {:id 303 :qr? false :questions [{:qname "_acme-challenge.example.com" :qtype :TXT :qclass :IN}]}
          r-acme (resolver/resolve-query test-config cluster-st q-acme)]
      (is (= [["dns-token-12345"]] (mapv :rdata (:answers r-acme)))))))

(deftest test-any-query-minimal-response
  (testing "ANY query returns minimal response per RFC 8482"
    (let [q {:id 401 :qr? false :questions [{:qname "www.example.com" :qtype :ANY :qclass :IN}]}
          resp (resolver/resolve-query test-config {:healthy-nodes #{:ns1}} q)]
      (is (= :noerror (:rcode resp)))
      (is (= :A (:type (first (:answers resp)))))
      (is (= "34.10.10.1" (:rdata (first (:answers resp))))))))

;; Property test
(defspec prop-resolver-invariants
  100
  (prop/for-all [id (gen/choose 0 65535)
                 sub (gen/elements ["@" "www" "docs" "mvn"])
                 qtype (gen/elements [:A :AAAA :NS :SOA :MX :TXT :CAA :ANY])]
                (let [qname (if (= sub "@") "example.com" (str sub ".example.com"))
                      query {:id id
                             :qr? false
                             :rd? true
                             :questions [{:qname qname :qtype qtype :qclass :IN}]}
                      cluster-st {:healthy-nodes #{:ns1 :ns2}}
                      resp (resolver/resolve-query test-config cluster-st query)]
                  (and (= id (:id resp))
                       (true? (:qr? resp))
                       (false? (:ra? resp))
                       (true? (:aa? resp))
                       (= :noerror (:rcode resp))
                       (= qname (:qname (first (:questions resp))))))))
