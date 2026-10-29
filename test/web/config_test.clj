(ns web.config-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.config :as cfg]))

(deftest test-default-config-values
  (testing "default-config exposes expected static default structure"
    (is (= "/var/lib/clj-web" (:state-dir cfg/default-config)))
    (is (= {:bind-ip "0.0.0.0"
            :port 5000
            :heartbeat-interval-ms 5000
            :heartbeat-timeout-ms 15000
            :nodes {}}
           (:cluster cfg/default-config)))
    (is (= {:bind-ip "0.0.0.0"
            :port 53
            :ttl-seconds 60
            :ns-ttl-seconds 3600
            :subdomains #{"@" "www" "docs" "mvn"}
            :caa-records [{:flags 0 :tag "issue" :value "letsencrypt.org"}]}
           (:dns cfg/default-config)))
    (is (= {:enabled? true
            :bind-ip "0.0.0.0"
            :port 25
            :max-message-bytes 131072
            :socket-timeout-ms 30000}
           (:smtp cfg/default-config)))
    (is (= {:enabled? true
            :directory-url "https://acme-v02.api.letsencrypt.org/directory"
            :contact-email nil
            :renew-before-days 30}
           (:acme cfg/default-config)))
    (is (= {:bind-ip "0.0.0.0"
            :http-port 80
            :https-port 443
            :content-root "/var/www/clj-web/public"
            :cache-max-bytes 134217728
            :cache-max-file-bytes 2097152
            :directory-listing? true
            :monthly-egress-limit-bytes 900000000}
           (:http cfg/default-config)))))

(deftest test-normalize-config-minimal
  (testing "minimal configuration populates all defaults and domain-derived fields"
    (let [raw {:node/id :ns1 :domain "example.com"}
          cfg (cfg/normalize-config raw)]
      (is (= :ns1 (:node/id cfg)))
      (is (= "example.com" (:domain cfg)))
      (is (= "/var/lib/clj-web" (:state-dir cfg)))

      ;; Cluster
      (is (= "0.0.0.0" (get-in cfg [:cluster :bind-ip])))
      (is (= 5000 (get-in cfg [:cluster :port])))
      (is (= 5000 (get-in cfg [:cluster :heartbeat-interval-ms])))
      (is (= 15000 (get-in cfg [:cluster :heartbeat-timeout-ms])))
      (is (= {} (get-in cfg [:cluster :nodes])))

      ;; DNS
      (is (= "0.0.0.0" (get-in cfg [:dns :bind-ip])))
      (is (= 53 (get-in cfg [:dns :port])))
      (is (= 60 (get-in cfg [:dns :ttl-seconds])))
      (is (= 3600 (get-in cfg [:dns :ns-ttl-seconds])))
      (is (= "hostmaster.example.com" (get-in cfg [:dns :hostmaster])))
      (is (= #{"@" "www" "docs" "mvn"} (get-in cfg [:dns :subdomains])))
      (is (= [{:preference 10 :exchange "ns1.example.com"}
              {:preference 20 :exchange "ns2.example.com"}
              {:preference 30 :exchange "ns3.example.com"}]
             (get-in cfg [:dns :mx-records])))
      (is (= {"@" ["v=spf1 -all"]
              "_dmarc" ["v=DMARC1; p=reject; rua=mailto:postmaster@example.com"]}
             (get-in cfg [:dns :txt-records])))
      (is (= [{:flags 0 :tag "issue" :value "letsencrypt.org"}]
             (get-in cfg [:dns :caa-records])))

      ;; SMTP
      (is (true? (get-in cfg [:smtp :enabled?])))
      (is (= "0.0.0.0" (get-in cfg [:smtp :bind-ip])))
      (is (= 25 (get-in cfg [:smtp :port])))
      (is (= 131072 (get-in cfg [:smtp :max-message-bytes])))
      (is (= 30000 (get-in cfg [:smtp :socket-timeout-ms])))
      (is (= #{"admin@example.com"
               "hostmaster@example.com"
               "postmaster@example.com"
               "security@example.com"}
             (get-in cfg [:smtp :allowed-recipients])))

      ;; ACME
      (is (true? (get-in cfg [:acme :enabled?])))
      (is (= "https://acme-v02.api.letsencrypt.org/directory" (get-in cfg [:acme :directory-url])))
      (is (nil? (get-in cfg [:acme :contact-email])))
      (is (= 30 (get-in cfg [:acme :renew-before-days])))
      (is (= ["example.com" "ns1.example.com" "ns2.example.com" "ns3.example.com"]
             (get-in cfg [:acme :domains])))

      ;; HTTP
      (is (= "0.0.0.0" (get-in cfg [:http :bind-ip])))
      (is (= 80 (get-in cfg [:http :http-port])))
      (is (= 443 (get-in cfg [:http :https-port])))
      (is (= "/var/www/clj-web/public" (get-in cfg [:http :content-root])))
      (is (= 134217728 (get-in cfg [:http :cache-max-bytes])))
      (is (= 2097152 (get-in cfg [:http :cache-max-file-bytes])))
      (is (true? (get-in cfg [:http :directory-listing?])))
      (is (= 900000000 (get-in cfg [:http :monthly-egress-limit-bytes]))))))

(deftest test-normalize-config-casing-and-trim
  (testing "uppercased or whitespace-padded domain is normalized to lower-case"
    (let [cfg (cfg/normalize-config {:node/id :ns2 :domain "  EXAMPLE.ORG  "})]
      (is (= "example.org" (:domain cfg)))
      (is (= "hostmaster.example.org" (get-in cfg [:dns :hostmaster])))
      (is (= ["example.org" "ns1.example.org" "ns2.example.org" "ns3.example.org"]
             (get-in cfg [:acme :domains]))))))

(deftest test-normalize-config-custom-overrides
  (testing "custom settings merge properly without losing other defaults"
    (let [cfg (cfg/normalize-config {:node/id :ns3
                                     :domain "alpeware.dev"
                                     :state-dir "/custom/state"
                                     :cluster {:port 6000
                                               :nodes {:ns1 {:port 6000}}}
                                     :dns {:port 1053
                                           :ttl-seconds 120}
                                     :smtp {:port 2525
                                            :allowed-recipients ["dev@alpeware.dev"]}
                                     :acme {:contact-email "mailto:ops@alpeware.dev"}
                                     :http {:http-port 8080
                                            :content-root "/custom/public"}})]
      (is (= "/custom/state" (:state-dir cfg)))
      (is (= 6000 (get-in cfg [:cluster :port])))
      (is (= 5000 (get-in cfg [:cluster :heartbeat-interval-ms])))
      (is (= 1053 (get-in cfg [:dns :port])))
      (is (= 120 (get-in cfg [:dns :ttl-seconds])))
      (is (= 3600 (get-in cfg [:dns :ns-ttl-seconds])))
      (is (= 2525 (get-in cfg [:smtp :port])))
      (is (= #{"dev@alpeware.dev"} (get-in cfg [:smtp :allowed-recipients])))
      (is (= "mailto:ops@alpeware.dev" (get-in cfg [:acme :contact-email])))
      (is (= 8080 (get-in cfg [:http :http-port])))
      (is (= 443 (get-in cfg [:http :https-port])))
      (is (= "/custom/public" (get-in cfg [:http :content-root]))))))

(deftest test-normalize-config-validation-errors
  (testing "validation failures throw ex-info with descriptive details"
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config nil)))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config "not-a-map")))

    ;; :node/id checks
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:domain "example.com"})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id "ns1" :domain "example.com"})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id nil :domain "example.com"})))

    ;; :domain checks
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain ""})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "   "})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "bad domain.com"})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "bad/domain.com"})))

    ;; :state-dir checks
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :state-dir ""})))

    ;; Port validation checks
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :cluster {:port 0}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :cluster {:port 65536}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :dns {:port -1}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :smtp {:port "25"}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :http {:http-port 0}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :http {:https-port 70000}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :cluster {:nodes {:ns2 {:port 0}}}})))

    ;; Non-negative/positive integer checks
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :dns {:ttl-seconds -1}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :cluster {:heartbeat-interval-ms 0}})))
    (is (thrown? clojure.lang.ExceptionInfo (cfg/normalize-config {:node/id :ns1 :domain "example.com" :smtp {:max-message-bytes -100}})))))

(deftest test-load-config-from-disk
  (testing "load-config reads EDN file from disk and normalizes it"
    (let [tmp-file (java.io.File/createTempFile "clj-web-config" ".edn")]
      (try
        (spit tmp-file (pr-str {:node/id :ns1
                                :domain "disk-test.com"
                                :http {:http-port 8081}}))
        (let [cfg (cfg/load-config (.getAbsolutePath tmp-file))]
          (is (= :ns1 (:node/id cfg)))
          (is (= "disk-test.com" (:domain cfg)))
          (is (= 8081 (get-in cfg [:http :http-port])))
          (is (= 443 (get-in cfg [:http :https-port]))))
        (finally
          (.delete tmp-file)))))

  (testing "load-config throws on non-existent file"
    (is (thrown? clojure.lang.ExceptionInfo (cfg/load-config "/tmp/non-existent-config-clj-web-xyz.edn"))))

  (testing "load-config throws on syntax error in EDN"
    (let [tmp-file (java.io.File/createTempFile "clj-web-bad" ".edn")]
      (try
        (spit tmp-file "{:node/id :ns1 :domain }")
        (is (thrown? clojure.lang.ExceptionInfo (cfg/load-config (.getAbsolutePath tmp-file))))
        (finally
          (.delete tmp-file))))))

;; Property-based test
(def gen-valid-domain
  (gen/fmap (fn [[name tld]]
              (str (str/lower-case name) "." tld))
            (gen/tuple (gen/such-that #(and (pos? (count %))
                                            (re-matches #"^[a-z0-9]+$" %))
                                      (gen/fmap #(str/replace % #"[^a-z0-9]" "a") (gen/not-empty gen/string-alphanumeric)))
                       (gen/elements ["com" "org" "net" "dev" "io"]))))

(def gen-valid-node-id
  (gen/fmap keyword
            (gen/such-that #(and (pos? (count %))
                                 (re-matches #"^[a-z0-9-]+$" %))
                           (gen/fmap #(str/replace % #"[^a-z0-9-]" "n") (gen/not-empty gen/string-alphanumeric)))))

(defspec prop-normalize-config-invariants
  100
  (prop/for-all [node-id gen-valid-node-id
                 domain gen-valid-domain]
                (let [cfg (cfg/normalize-config {:node/id node-id :domain domain})]
                  (and (= node-id (:node/id cfg))
                       (= domain (:domain cfg))
                       (integer? (get-in cfg [:cluster :port]))
                       (<= 1 (get-in cfg [:cluster :port]) 65535)
                       (integer? (get-in cfg [:dns :port]))
                       (<= 1 (get-in cfg [:dns :port]) 65535)
                       (integer? (get-in cfg [:smtp :port]))
                       (<= 1 (get-in cfg [:smtp :port]) 65535)
                       (integer? (get-in cfg [:http :http-port]))
                       (<= 1 (get-in cfg [:http :http-port]) 65535)
                       (integer? (get-in cfg [:http :https-port]))
                       (<= 1 (get-in cfg [:http :https-port]) 65535)
                       (= (str "hostmaster." domain) (get-in cfg [:dns :hostmaster]))
                       (contains? (get-in cfg [:smtp :allowed-recipients]) (str "admin@" domain))
                       (= domain (first (get-in cfg [:acme :domains])))))))
