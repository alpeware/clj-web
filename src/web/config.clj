(ns web.config
  "Configuration schema defaults, normalization, and validation for clj-web."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def default-config
  "Sensible static defaults for clj-web configuration.
   Domain-specific defaults (e.g. hostmaster, MX/TXT/CAA records, ACME SANs,
   and allowed SMTP recipients) are populated dynamically in `normalize-config`."
  {:state-dir "/var/lib/clj-web"
   :cluster {:bind-ip "0.0.0.0"
             :port 5000
             :heartbeat-interval-ms 5000
             :heartbeat-timeout-ms 15000
             :nodes {}}
   :dns {:bind-ip "0.0.0.0"
         :port 53
         :ttl-seconds 60
         :ns-ttl-seconds 3600
         :subdomains #{"@" "www" "docs" "mvn"}
         :caa-records [{:flags 0 :tag "issue" :value "letsencrypt.org"}]}
   :smtp {:enabled? true
          :bind-ip "0.0.0.0"
          :port 25
          :max-message-bytes 131072
          :socket-timeout-ms 30000}
   :acme {:enabled? true
          :directory-url "https://acme-v02.api.letsencrypt.org/directory"
          :contact-email nil
          :renew-before-days 30}
   :http {:bind-ip "0.0.0.0"
          :http-port 80
          :https-port 443
          :content-root "/var/www/clj-web/public"
          :cache-max-bytes 134217728
          :cache-max-file-bytes 2097152
          :directory-listing? true
          :monthly-egress-limit-bytes 900000000}})

(defn- valid-port? [p]
  (and (integer? p) (<= 1 p 65535)))

(defn- validate-port! [field-name p]
  (when-not (valid-port? p)
    (throw (ex-info (str "Invalid port number for " field-name ": " (pr-str p) " (must be integer between 1 and 65535)")
                    {:field field-name :port p}))))

(defn- validate-pos-int! [field-name n]
  (when-not (and (integer? n) (pos? n))
    (throw (ex-info (str "Field " field-name " must be a positive integer: " (pr-str n))
                    {:field field-name :value n}))))

(defn- validate-non-neg-int! [field-name n]
  (when-not (and (integer? n) (not (neg? n)))
    (throw (ex-info (str "Field " field-name " must be a non-negative integer: " (pr-str n))
                    {:field field-name :value n}))))

(defn- validate-non-blank-string! [field-name s]
  (when-not (and (string? s) (not (str/blank? s)))
    (throw (ex-info (str "Field " field-name " must be a non-blank string: " (pr-str s))
                    {:field field-name :value s}))))

(def ^:private fingerprint-regex #"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")

(defn normalize-fingerprint
  "Trims whitespace, strips an optional case-insensitive 'SHA-256:' prefix,
   uppercases it, and validates that it matches 32-byte hex format (XX:XX:...).
   Throws ex-info if invalid."
  [fp]
  (when-not (string? fp)
    (throw (ex-info "Fingerprint must be a string" {:fingerprint fp})))
  (let [cleaned (-> fp
                    str/trim
                    (str/replace-first #"(?i)^SHA-256:\s*" "")
                    str/upper-case)]
    (when-not (re-matches fingerprint-regex cleaned)
      (throw (ex-info (str "Invalid SHA-256 fingerprint format: " (pr-str fp))
                      {:fingerprint fp :normalized cleaned})))
    cleaned))

(defn normalize-config
  "Validates and normalizes raw configuration map, populating defaults.
   Validates required :node/id (keyword) and :domain (non-blank lowercased string).
   Throws ex-info on invalid or missing required fields."
  [raw-cfg]
  (when-not (map? raw-cfg)
    (throw (ex-info "Configuration must be a map" {:config raw-cfg})))
  (let [node-id (:node/id raw-cfg)]
    (when-not (keyword? node-id)
      (throw (ex-info ":node/id must be a keyword (e.g. :ns1)" {:node/id node-id})))
    (let [raw-domain (:domain raw-cfg)]
      (when-not (and (string? raw-domain) (not (str/blank? raw-domain)))
        (throw (ex-info ":domain must be a non-blank string" {:domain raw-domain})))
      (let [domain (str/lower-case (str/trim raw-domain))]
        (when (or (str/includes? domain " ")
                  (str/includes? domain "/")
                  (str/includes? domain "\\"))
          (throw (ex-info ":domain contains invalid characters" {:domain domain})))

        (let [raw-state-dir (:state-dir raw-cfg)
              state-dir (if (some? raw-state-dir)
                          (do
                            (validate-non-blank-string! :state-dir raw-state-dir)
                            raw-state-dir)
                          (:state-dir default-config))

              ;; Cluster
              cluster-cfg (:cluster raw-cfg {})
              cluster-bind-ip (get cluster-cfg :bind-ip (get-in default-config [:cluster :bind-ip]))
              _ (validate-non-blank-string! :cluster/bind-ip cluster-bind-ip)
              cluster-port (get cluster-cfg :port (get-in default-config [:cluster :port]))
              _ (validate-port! :cluster/port cluster-port)
              hb-interval (get cluster-cfg :heartbeat-interval-ms (get-in default-config [:cluster :heartbeat-interval-ms]))
              _ (validate-pos-int! :cluster/heartbeat-interval-ms hb-interval)
              hb-timeout (get cluster-cfg :heartbeat-timeout-ms (get-in default-config [:cluster :heartbeat-timeout-ms]))
              _ (validate-pos-int! :cluster/heartbeat-timeout-ms hb-timeout)
              cluster-nodes (get cluster-cfg :nodes (get-in default-config [:cluster :nodes]))
              _ (when-not (map? cluster-nodes)
                  (throw (ex-info ":cluster :nodes must be a map" {:nodes cluster-nodes})))
              require-fps? (get cluster-cfg :require-fingerprints? false)
              normalized-nodes
              (into {}
                    (map (fn [[n-id n-info]]
                           (when (and (map? n-info) (contains? n-info :port))
                             (validate-port! (keyword "cluster.nodes" (name n-id)) (:port n-info)))
                           (let [raw-fp (:fingerprint n-info)]
                             (when (and require-fps? (not= n-id node-id) (str/blank? (str raw-fp)))
                               (throw (ex-info (str "Missing required fingerprint for remote peer: " (pr-str n-id))
                                               {:node-id n-id :node-info n-info})))
                             [n-id (if (some? raw-fp)
                                     (assoc n-info :fingerprint (normalize-fingerprint raw-fp))
                                     n-info)])))
                    cluster-nodes)
              cluster (merge (:cluster default-config)
                             cluster-cfg
                             {:bind-ip cluster-bind-ip
                              :port cluster-port
                              :heartbeat-interval-ms hb-interval
                              :heartbeat-timeout-ms hb-timeout
                              :nodes normalized-nodes})

              ;; DNS
              dns-cfg (:dns raw-cfg {})
              dns-bind-ip (get dns-cfg :bind-ip (get-in default-config [:dns :bind-ip]))
              _ (validate-non-blank-string! :dns/bind-ip dns-bind-ip)
              dns-port (get dns-cfg :port (get-in default-config [:dns :port]))
              _ (validate-port! :dns/port dns-port)
              ttl (get dns-cfg :ttl-seconds (get-in default-config [:dns :ttl-seconds]))
              _ (validate-non-neg-int! :dns/ttl-seconds ttl)
              ns-ttl (get dns-cfg :ns-ttl-seconds (get-in default-config [:dns :ns-ttl-seconds]))
              _ (validate-non-neg-int! :dns/ns-ttl-seconds ns-ttl)
              hostmaster (get dns-cfg :hostmaster (str "hostmaster." domain))
              _ (validate-non-blank-string! :dns/hostmaster hostmaster)
              subdomains (set (get dns-cfg :subdomains (get-in default-config [:dns :subdomains])))
              mx-records (get dns-cfg :mx-records
                              [{:preference 10 :exchange (str "ns1." domain)}
                               {:preference 20 :exchange (str "ns2." domain)}
                               {:preference 30 :exchange (str "ns3." domain)}])
              _ (when-not (coll? mx-records)
                  (throw (ex-info ":dns :mx-records must be a collection" {:mx-records mx-records})))
              _ (doseq [mx mx-records]
                  (when-not (and (map? mx) (integer? (:preference mx)) (string? (:exchange mx)))
                    (throw (ex-info "Invalid MX record" {:mx mx}))))
              txt-records (get dns-cfg :txt-records
                               {"@" ["v=spf1 -all"]
                                "_dmarc" [(str "v=DMARC1; p=reject; rua=mailto:postmaster@" domain)]})
              _ (when-not (map? txt-records)
                  (throw (ex-info ":dns :txt-records must be a map" {:txt-records txt-records})))
              caa-records (get dns-cfg :caa-records (get-in default-config [:dns :caa-records]))
              _ (when-not (coll? caa-records)
                  (throw (ex-info ":dns :caa-records must be a collection" {:caa-records caa-records})))
              dns (merge (:dns default-config)
                         dns-cfg
                         {:bind-ip dns-bind-ip
                          :port dns-port
                          :ttl-seconds ttl
                          :ns-ttl-seconds ns-ttl
                          :hostmaster hostmaster
                          :subdomains subdomains
                          :mx-records mx-records
                          :txt-records txt-records
                          :caa-records caa-records})

              ;; SMTP
              smtp-cfg (:smtp raw-cfg {})
              smtp-enabled? (get smtp-cfg :enabled? (get-in default-config [:smtp :enabled?]))
              smtp-bind-ip (get smtp-cfg :bind-ip (get-in default-config [:smtp :bind-ip]))
              _ (validate-non-blank-string! :smtp/bind-ip smtp-bind-ip)
              smtp-port (get smtp-cfg :port (get-in default-config [:smtp :port]))
              _ (validate-port! :smtp/port smtp-port)
              max-msg-bytes (get smtp-cfg :max-message-bytes (get-in default-config [:smtp :max-message-bytes]))
              _ (validate-pos-int! :smtp/max-message-bytes max-msg-bytes)
              sock-timeout (get smtp-cfg :socket-timeout-ms (get-in default-config [:smtp :socket-timeout-ms]))
              _ (validate-pos-int! :smtp/socket-timeout-ms sock-timeout)
              allowed-recipients (if (contains? smtp-cfg :allowed-recipients)
                                   (set (map (comp str/lower-case str/trim) (:allowed-recipients smtp-cfg)))
                                   #{(str "admin@" domain)
                                     (str "hostmaster@" domain)
                                     (str "postmaster@" domain)
                                     (str "security@" domain)})
              smtp (merge (:smtp default-config)
                          smtp-cfg
                          {:enabled? (boolean smtp-enabled?)
                           :bind-ip smtp-bind-ip
                           :port smtp-port
                           :max-message-bytes max-msg-bytes
                           :socket-timeout-ms sock-timeout
                           :allowed-recipients allowed-recipients})

              ;; ACME
              acme-cfg (:acme raw-cfg {})
              acme-enabled? (get acme-cfg :enabled? (get-in default-config [:acme :enabled?]))
              acme-dir-url (get acme-cfg :directory-url (get-in default-config [:acme :directory-url]))
              _ (validate-non-blank-string! :acme/directory-url acme-dir-url)
              contact-email (get acme-cfg :contact-email (get-in default-config [:acme :contact-email]))
              _ (when (some? contact-email)
                  (validate-non-blank-string! :acme/contact-email contact-email))
              renew-before-days (get acme-cfg :renew-before-days (get-in default-config [:acme :renew-before-days]))
              _ (validate-pos-int! :acme/renew-before-days renew-before-days)
              acme-domains (vec (get acme-cfg :domains
                                     [domain
                                      (str "ns1." domain)
                                      (str "ns2." domain)
                                      (str "ns3." domain)]))
              _ (when-not (and (coll? acme-domains) (seq acme-domains) (every? string? acme-domains))
                  (throw (ex-info ":acme :domains must be a non-empty collection of strings" {:domains acme-domains})))
              acme (merge (:acme default-config)
                          acme-cfg
                          {:enabled? (boolean acme-enabled?)
                           :directory-url acme-dir-url
                           :contact-email contact-email
                           :renew-before-days renew-before-days
                           :domains acme-domains})

              ;; HTTP
              http-cfg (:http raw-cfg {})
              http-bind-ip (get http-cfg :bind-ip (get-in default-config [:http :bind-ip]))
              _ (validate-non-blank-string! :http/bind-ip http-bind-ip)
              http-port (get http-cfg :http-port (get-in default-config [:http :http-port]))
              _ (validate-port! :http/http-port http-port)
              https-port (get http-cfg :https-port (get-in default-config [:http :https-port]))
              _ (validate-port! :http/https-port https-port)
              content-root (get http-cfg :content-root (get-in default-config [:http :content-root]))
              _ (validate-non-blank-string! :http/content-root content-root)
              cache-max-bytes (get http-cfg :cache-max-bytes (get-in default-config [:http :cache-max-bytes]))
              _ (validate-pos-int! :http/cache-max-bytes cache-max-bytes)
              cache-max-file (get http-cfg :cache-max-file-bytes (get-in default-config [:http :cache-max-file-bytes]))
              _ (validate-pos-int! :http/cache-max-file-bytes cache-max-file)
              dir-listing? (get http-cfg :directory-listing? (get-in default-config [:http :directory-listing?]))
              egress-limit (get http-cfg :monthly-egress-limit-bytes (get-in default-config [:http :monthly-egress-limit-bytes]))
              _ (validate-pos-int! :http/monthly-egress-limit-bytes egress-limit)
              http (merge (:http default-config)
                          http-cfg
                          {:bind-ip http-bind-ip
                           :http-port http-port
                           :https-port https-port
                           :content-root content-root
                           :cache-max-bytes cache-max-bytes
                           :cache-max-file-bytes cache-max-file
                           :directory-listing? (boolean dir-listing?)
                           :monthly-egress-limit-bytes egress-limit})]
          (assoc raw-cfg
                 :node/id node-id
                 :domain domain
                 :state-dir state-dir
                 :cluster cluster
                 :dns dns
                 :smtp smtp
                 :acme acme
                 :http http))))))

(defn load-config
  "Reads an EDN configuration file from path and normalizes it."
  [path]
  (let [f (io/file path)]
    (when-not (.exists f)
      (throw (ex-info (str "Config file not found: " path) {:path path})))
    (let [content (try
                    (slurp f)
                    (catch Exception e
                      (throw (ex-info (str "Failed to read config file: " path)
                                      {:path path}
                                      e))))
          raw-cfg (try
                    (edn/read-string content)
                    (catch Exception e
                      (throw (ex-info (str "Invalid EDN in config file: " path)
                                      {:path path}
                                      e))))]
      (normalize-config raw-cfg))))
