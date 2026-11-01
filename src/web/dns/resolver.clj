(ns web.dns.resolver
  "Pure authoritative DNS zone resolver.
   Evaluates incoming DNS queries against configured zone, healthy cluster nodes,
   and dynamic ACME challenge tokens. Never performs open recursion."
  (:require [clojure.string :as str]))

(defn- strip-trailing-dot [^String s]
  (if (and s (str/ends-with? s "."))
    (subs s 0 (dec (count s)))
    (or s "")))

(defn- make-soa-record
  [config]
  (let [domain (:domain config)
        dns-cfg (:dns config)]
    {:name domain
     :type :SOA
     :class :IN
     :ttl (get dns-cfg :ttl-seconds 60)
     :rdata {:mname (str "ns1." domain)
             :rname (get dns-cfg :hostmaster (str "hostmaster." domain))
             :serial (get dns-cfg :serial (quot (System/currentTimeMillis) 1000))
             :refresh 3600
             :retry 600
             :expire 604800
             :minimum (get dns-cfg :ttl-seconds 60)}}))

(defn- resolve-a-records
  [qname config cluster-state query-id]
  (let [all-nodes (get-in config [:cluster :nodes] {})
        healthy-ids (set (:healthy-nodes cluster-state))
        ;; 1. Check healthy nodes first
        healthy-ips (vec (keep (fn [nid]
                                 (let [ip (:ip4 (get all-nodes nid))]
                                   (when (and (string? ip) (not (str/blank? ip)))
                                     ip)))
                               healthy-ids))
        ;; 2. Fail-safe fallback if no healthy nodes in cluster state
        ips (if (seq healthy-ips)
              healthy-ips
              (let [local-nid (:node/id config)
                    local-ip (:ip4 (get all-nodes local-nid))]
                (if (and (string? local-ip) (not (str/blank? local-ip)))
                  [local-ip]
                  (vec (keep (fn [[_ n]]
                               (let [ip (:ip4 n)]
                                 (when (and (string? ip) (not (str/blank? ip)))
                                   ip)))
                             all-nodes)))))
        ttl (get-in config [:dns :ttl-seconds] 60)]
    (if (empty? ips)
      {:answers []
       :authority [(make-soa-record config)]}
      (let [n (count ips)
            shift (mod (or query-id 0) n)
            rotated (vec (concat (drop shift ips) (take shift ips)))]
        {:answers (mapv (fn [ip]
                          {:name qname
                           :type :A
                           :class :IN
                           :ttl ttl
                           :rdata ip})
                        rotated)
         :authority []}))))

(defn- resolve-aaaa-records
  [qname config cluster-state query-id]
  (let [all-nodes (get-in config [:cluster :nodes] {})
        healthy-ids (set (:healthy-nodes cluster-state))
        healthy-ips (vec (keep (fn [nid]
                                 (let [ip (:ip6 (get all-nodes nid))]
                                   (when (and (string? ip) (not (str/blank? ip)))
                                     ip)))
                               healthy-ids))
        ips (if (seq healthy-ips)
              healthy-ips
              (let [local-nid (:node/id config)
                    local-ip (:ip6 (get all-nodes local-nid))]
                (if (and (string? local-ip) (not (str/blank? local-ip)))
                  [local-ip]
                  (vec (keep (fn [[_ n]]
                               (let [ip (:ip6 n)]
                                 (when (and (string? ip) (not (str/blank? ip)))
                                   ip)))
                             all-nodes)))))
        ttl (get-in config [:dns :ttl-seconds] 60)]
    (if (empty? ips)
      {:answers []
       :authority [(make-soa-record config)]}
      (let [n (count ips)
            shift (mod (or query-id 0) n)
            rotated (vec (concat (drop shift ips) (take shift ips)))]
        {:answers (mapv (fn [ip]
                          {:name qname
                           :type :AAAA
                           :class :IN
                           :ttl ttl
                           :rdata ip})
                        rotated)
         :authority []}))))

(def ^:private node-ingress-map
  {"node1.ingress" :ns1
   "node2.ingress" :ns2
   "node3.ingress" :ns3})

(defn- resolve-static-node-query
  "Resolves A/AAAA records for a specific cluster node config."
  [base-response qname qtype node-cfg opts]
  (let [ttl (:ttl opts)
        config (:config opts)]
    (case qtype
      (:A :ANY)
      (if-let [ip4 (:ip4 node-cfg)]
        (assoc base-response
               :rcode :noerror
               :answers [{:name qname
                          :type :A
                          :class :IN
                          :ttl ttl
                          :rdata ip4}]
               :authority [])
        (assoc base-response
               :rcode :noerror
               :answers []
               :authority [(make-soa-record config)]))

      :AAAA
      (if-let [ip6 (:ip6 node-cfg)]
        (assoc base-response
               :rcode :noerror
               :answers [{:name qname
                          :type :AAAA
                          :class :IN
                          :ttl ttl
                          :rdata ip6}]
               :authority [])
        (assoc base-response
               :rcode :noerror
               :answers []
               :authority [(make-soa-record config)]))

      ;; Any other record on static node host
      (assoc base-response
             :rcode :noerror
             :answers []
             :authority [(make-soa-record config)]))))

(defn resolve-query
  "Pure authoritative DNS query resolver.
   Resolves query-pkt against config and cluster-state.
   Guarantees:
     - Sets :qr? true, :ra? false (never open recursion), copies :id and :rd?
     - Preserves original 0x20 casing in :questions and answered records
     - Returns :refused on out-of-zone queries
     - Returns :nxdomain + SOA for unknown subdomains
     - Filters multi-A / AAAA records by cluster liveness with fail-safe fallback
     - Resolves ns1..ns3 glue records deterministically."
  [config cluster-state query-pkt]
  (let [cluster-st (if (instance? clojure.lang.IDeref cluster-state)
                     @cluster-state
                     cluster-state)
        questions (or (:questions query-pkt) [])]
    (if (empty? questions)
      {:id (:id query-pkt)
       :qr? true
       :opcode (or (:opcode query-pkt) 0)
       :aa? false
       :tc? false
       :rd? (boolean (:rd? query-pkt))
       :ra? false
       :rcode :formerr
       :questions []
       :answers []
       :authority []
       :additional []}

      (let [q (first questions)
            qname (or (:qname q) "")
            qname-clean (strip-trailing-dot (str/lower-case (or (:qname-lower q) qname)))
            domain (strip-trailing-dot (str/lower-case (or (:domain config) "")))
            qtype (or (:qtype q) :A)
            query-id (:id query-pkt)]

        ;; 1. Out-of-zone check
        (if-not (or (= qname-clean domain)
                    (str/ends-with? qname-clean (str "." domain)))
          {:id query-id
           :qr? true
           :opcode (or (:opcode query-pkt) 0)
           :aa? false
           :tc? false
           :rd? (boolean (:rd? query-pkt))
           :ra? false
           :rcode :refused
           :questions questions
           :answers []
           :authority []
           :additional []}

          ;; In-zone query
          (let [relative (if (= qname-clean domain)
                           "@"
                           (subs qname-clean 0 (- (count qname-clean) (inc (count domain)))))
                base-response {:id query-id
                               :qr? true
                               :opcode (or (:opcode query-pkt) 0)
                               :aa? true
                               :tc? false
                               :rd? (boolean (:rd? query-pkt))
                               :ra? false
                               :questions questions
                               :additional []}]

            (cond
              ;; 2. Nameserver host queries (ns1, ns2, ns3)
              (contains? #{"ns1" "ns2" "ns3"} relative)
              (let [node-kw (keyword relative)
                    node-cfg (get-in config [:cluster :nodes node-kw])
                    ns-ttl (get-in config [:dns :ns-ttl-seconds] 3600)]
                (resolve-static-node-query base-response qname qtype node-cfg {:ttl ns-ttl :config config}))

              ;; 2b. Node ingress host queries (node1.ingress, node2.ingress, node3.ingress)
              (contains? node-ingress-map relative)
              (let [node-kw (get node-ingress-map relative)
                    node-cfg (get-in config [:cluster :nodes node-kw])
                    ttl (get-in config [:dns :ttl-seconds] 60)]
                (resolve-static-node-query base-response qname qtype node-cfg {:ttl ttl :config config}))

              ;; 3. Check if host is configured in-zone
              :else
              (let [subdomains (set (get-in config [:dns :subdomains]))
                    txt-records (get-in config [:dns :txt-records] {})
                    acme-challenges (:acme-dns-challenges cluster-st {})
                    configured-host? (or (= relative "@")
                                         (contains? subdomains relative)
                                         (contains? subdomains "*")
                                         (contains? txt-records relative)
                                         (= relative "_acme-challenge")
                                         (contains? acme-challenges relative))]

                (if-not configured-host?
                  ;; Unknown subdomain -> NXDOMAIN + SOA in authority
                  (assoc base-response
                         :rcode :nxdomain
                         :answers []
                         :authority [(make-soa-record config)])

                  ;; 4. Resolve configured in-zone host according to QTYPE
                  (case qtype
                    :A
                    (let [{:keys [answers authority]} (resolve-a-records qname config cluster-st query-id)]
                      (assoc base-response
                             :rcode :noerror
                             :answers answers
                             :authority authority))

                    :AAAA
                    (let [{:keys [answers authority]} (resolve-aaaa-records qname config cluster-st query-id)]
                      (assoc base-response
                             :rcode :noerror
                             :answers answers
                             :authority authority))

                    :NS
                    (if (= relative "@")
                      (let [ns-ttl (get-in config [:dns :ns-ttl-seconds] 3600)]
                        (assoc base-response
                               :rcode :noerror
                               :answers [{:name qname :type :NS :class :IN :ttl ns-ttl :rdata (str "ns1." domain)}
                                         {:name qname :type :NS :class :IN :ttl ns-ttl :rdata (str "ns2." domain)}
                                         {:name qname :type :NS :class :IN :ttl ns-ttl :rdata (str "ns3." domain)}]
                               :authority []))
                      (assoc base-response
                             :rcode :noerror
                             :answers []
                             :authority [(make-soa-record config)]))

                    :SOA
                    (assoc base-response
                           :rcode :noerror
                           :answers [(assoc (make-soa-record config) :name qname)]
                           :authority [])

                    :MX
                    (if (= relative "@")
                      (let [ttl (get-in config [:dns :ttl-seconds] 60)
                            mx-records (get-in config [:dns :mx-records] [])]
                        (assoc base-response
                               :rcode :noerror
                               :answers (mapv (fn [mx]
                                                {:name qname
                                                 :type :MX
                                                 :class :IN
                                                 :ttl ttl
                                                 :rdata mx})
                                              mx-records)
                               :authority []))
                      (assoc base-response
                             :rcode :noerror
                             :answers []
                             :authority [(make-soa-record config)]))

                    :TXT
                    (let [merged-txt (merge txt-records acme-challenges)
                          txt-val (get merged-txt relative)
                          ttl (get-in config [:dns :ttl-seconds] 60)]
                      (if txt-val
                        (let [items (if (coll? txt-val) txt-val [txt-val])]
                          (assoc base-response
                                 :rcode :noerror
                                 :answers (mapv (fn [item]
                                                  {:name qname
                                                   :type :TXT
                                                   :class :IN
                                                   :ttl ttl
                                                   :rdata (if (vector? item) item [(str item)])})
                                                items)
                                 :authority []))
                        (assoc base-response
                               :rcode :noerror
                               :answers []
                               :authority [(make-soa-record config)])))

                    :CAA
                    (if (= relative "@")
                      (let [ttl (get-in config [:dns :ttl-seconds] 60)
                            caa-records (get-in config [:dns :caa-records] [])]
                        (assoc base-response
                               :rcode :noerror
                               :answers (mapv (fn [caa]
                                                {:name qname
                                                 :type :CAA
                                                 :class :IN
                                                 :ttl ttl
                                                 :rdata caa})
                                              caa-records)
                               :authority []))
                      (assoc base-response
                             :rcode :noerror
                             :answers []
                             :authority [(make-soa-record config)]))

                    :ANY
                    ;; RFC 8482: minimal response (A records or SOA)
                    (let [{:keys [answers]} (resolve-a-records qname config cluster-st query-id)]
                      (if (seq answers)
                        (assoc base-response
                               :rcode :noerror
                               :answers answers
                               :authority [])
                        (assoc base-response
                               :rcode :noerror
                               :answers [(assoc (make-soa-record config) :name qname)]
                               :authority [])))

                    ;; Unknown / unhandled QTYPE
                    (assoc base-response
                           :rcode :noerror
                           :answers []
                           :authority [(make-soa-record config)])))))))))))
