(ns web.main
  "Main entrypoint, system lifecycle wiring, and CLI commands for clj-web.
   Orchestrates DNS (UDP/TCP 53), HTTP (80) & HTTPS (443), inbound SMTP (25),
   ACME v2 certificate provisioning, and 3-node DataChannel full-mesh clustering."
  (:gen-class)
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [web.acme.client :as acme]
            [web.cluster.mesh :as mesh]
            [web.config :as config]
            [web.dns.server :as dns]
            [web.http.server :as http]
            [web.smtp.server :as smtp]
            [web.tls.context :as tls])
  (:import [java.io File]))

(declare stop-node!)

(defn start-node!
  "Starts all clj-web subsystems according to normalized configuration.
   Options:
     :cluster-opts (map passed to mesh/start-cluster!)
     :smtp-opts    (map passed to smtp/start-smtp-server!)
     :acme-opts    (map passed to acme/start-acme-loop!)
   Returns unified node map with all running subsystem handles and :stop-fn."
  ([raw-or-normalized-config]
   (start-node! raw-or-normalized-config {}))
  ([raw-or-normalized-config opts]
   (let [raw-cfg (if (and (= (get-in opts [:cluster-opts :transport]) :in-memory)
                          (not (contains? (:cluster raw-or-normalized-config) :require-fingerprints?)))
                   (assoc-in raw-or-normalized-config [:cluster :allow-unauthenticated?] true)
                   raw-or-normalized-config)
         cfg (config/normalize-config raw-cfg)
         acme-challenges-atom (atom {})
         tls-manager (tls/init-tls-manager! cfg)
         cluster-mgr (mesh/start-cluster! cfg tls-manager acme-challenges-atom (:cluster-opts opts {}))
         dns-server (dns/start-dns-server! cfg (:state-atom cluster-mgr))
         smtp-server (when (get-in cfg [:smtp :enabled?] true)
                       (smtp/start-smtp-server! cfg tls-manager
                                                (merge {:on-mail-received (fn [mail] (mesh/replicate-mail! cluster-mgr mail))}
                                                       (:smtp-opts opts {}))))
         http-servers (http/start-http-servers! cfg tls-manager acme-challenges-atom)
         acme-mgr (when (get-in cfg [:acme :enabled?] true)
                    (acme/start-acme-loop! cfg cluster-mgr tls-manager (:acme-opts opts {})))
         node-map {:config cfg
                   :tls-manager tls-manager
                   :acme-challenges-atom acme-challenges-atom
                   :cluster-mgr cluster-mgr
                   :dns-server dns-server
                   :smtp-server smtp-server
                   :http-servers http-servers
                   :acme-mgr acme-mgr}]
     (assoc node-map :stop-fn #(stop-node! node-map)))))

(defn stop-node!
  "Cleanly shuts down all subsystems of a clj-web node in reverse startup order."
  [node]
  (when node
    (when-let [acme (:acme-mgr node)]
      (try (acme/stop-acme-loop! acme) (catch Exception _ nil)))
    (when-let [http (:http-servers node)]
      (try (http/stop-http-servers! http) (catch Exception _ nil)))
    (when-let [smtp (:smtp-server node)]
      (try (smtp/stop-smtp-server! smtp) (catch Exception _ nil)))
    (when-let [dns (:dns-server node)]
      (try (dns/stop-dns-server! dns) (catch Exception _ nil)))
    (when-let [cluster (:cluster-mgr node)]
      (try (mesh/stop-cluster! cluster) (catch Exception _ nil))))
  node)

;; ---------------------------------------------------------------------------
;; CLI Entrypoint & Subcommands
;; ---------------------------------------------------------------------------

(defn- print-usage []
  (println "Usage: clj-web <command> [args...]")
  (println "")
  (println "Commands:")
  (println "  run <config.edn>                         Start clj-web node in foreground")
  (println "  print-fingerprint <config.edn>           Display DTLS SHA-256 certificate fingerprint")
  (println "  list-mail <config.edn>                   List saved RFC 822 .eml emails in state-dir/mail")
  (println "  read-mail <config.edn> [id-or-filename]  Read and display saved email headers and plain text body")
  (println ""))

(defn- cmd-print-fingerprint [config-path]
  (let [cfg (config/load-config config-path)
        identity (mesh/load-or-create-node-identity! (:state-dir cfg) (:node/id cfg))]
    (println (str "Node: " (:node/id cfg)))
    (println (str "State directory: " (:state-dir cfg)))
    (println (str "SHA-256 Fingerprint: " (:fingerprint identity)))))

(defn- parse-eml-summary [^File f]
  (try
    (with-open [r (io/reader f)]
      (loop [headers {}]
        (let [line (.readLine r)]
          (cond
            (or (nil? line) (str/blank? line))
            (assoc headers :file (.getName f) :id (str/replace (.getName f) #"\.eml$" ""))

            (re-matches #"(?i)^From:\s*(.*)$" line)
            (let [[_ v] (re-matches #"(?i)^From:\s*(.*)$" line)]
              (recur (assoc headers :from (str/trim v))))

            (re-matches #"(?i)^To:\s*(.*)$" line)
            (let [[_ v] (re-matches #"(?i)^To:\s*(.*)$" line)]
              (recur (assoc headers :recipients [(str/trim v)])))

            (re-matches #"(?i)^Subject:\s*(.*)$" line)
            (let [[_ v] (re-matches #"(?i)^Subject:\s*(.*)$" line)]
              (recur (assoc headers :subject (str/trim v))))

            :else
            (recur headers)))))
    (catch Exception _
      {:file (.getName f) :id (.getName f)})))

(defn- cmd-list-mail [config-path]
  (let [cfg (config/load-config config-path)
        emails (smtp/list-emails (:state-dir cfg))]
    (println (str "Found " (count emails) " emails in " (:state-dir cfg) "/mail/:"))
    (doseq [m emails]
      (let [parsed (when-let [^File f (:file m)]
                     (parse-eml-summary f))
            info (merge m parsed)]
        (println (format "  [%s] From: %s | To: %s | Subject: %s | File: %s"
                         (or (:id info) "unknown")
                         (or (:from info) "unknown")
                         (str/join ", " (or (:recipients info) []))
                         (or (:subject info) "(no subject)")
                         (or (:file info) "")))))))

(defn- extract-plain-body
  "Extracts plain text body from a raw RFC 822 / MIME .eml string.
   Extracts text/plain MIME part if present, otherwise body after initial headers."
  [^String raw-eml]
  (when raw-eml
    (let [[_ body] (str/split raw-eml #"\r?\n\r?\n" 2)
          raw-body (or body raw-eml)]
      (if-let [[_ part] (re-find #"(?is)Content-Type:\s*text/plain[^\r\n]*(?:\r?\n[^\r\n]+)*\r?\n\r?\n(.*?)(?:\r?\n--|\z)" raw-eml)]
        (str/trim part)
        (str/trim raw-body)))))

(defn- cmd-read-mail [config-path target-id]
  (let [cfg (config/load-config config-path)
        emails (smtp/list-emails (:state-dir cfg))]
    (if (empty? emails)
      (println (str "No emails found in " (:state-dir cfg) "/mail/."))
      (let [target (when-not (str/blank? target-id) (str/trim target-id))
            selected (if (or (nil? target) (= target "latest"))
                       (last emails)
                       (some (fn [m]
                               (let [^File f (:file m)
                                     fname (when f (.getName f))
                                     base-id (when fname (str/replace fname #"\.eml$" ""))]
                                 (when (or (= (:id m) target)
                                           (= base-id target)
                                           (= fname target)
                                           (= fname (str target ".eml")))
                                   m)))
                             emails))]
        (if-not selected
          (println (str "Email not found: " target-id))
          (let [^File f (:file selected)
                raw-eml (slurp f)
                summary (parse-eml-summary f)
                id (or (:id summary) (:id selected) (when f (str/replace (.getName f) #"\.eml$" "")) "unknown")
                from (or (:from summary) "unknown")
                to (let [r (:recipients summary)]
                     (cond
                       (coll? r) (str/join ", " r)
                       (some? r) (str r)
                       :else "unknown"))
                subject (or (:subject summary) "(no subject)")
                filename (if f (.getName f) (or (:file summary) ""))
                body (extract-plain-body raw-eml)]
            (println "============================================================")
            (println (str "ID:      " id))
            (println (str "From:    " from))
            (println (str "To:      " to))
            (println (str "Subject: " subject))
            (println (str "File:    " filename))
            (println "------------------------------------------------------------")
            (println body)
            (println "============================================================")))))))

(defn- cmd-run [config-path]
  (let [cfg (config/load-config config-path)
        node (start-node! cfg)
        shutdown-hook (Thread. ^Runnable (fn []
                                           (println "\nReceived shutdown signal. Stopping clj-web node...")
                                           (stop-node! node)
                                           (println "Shutdown complete.")))]
    (.addShutdownHook (Runtime/getRuntime) shutdown-hook)
    (let [node-id (:node/id cfg)
          domain (:domain cfg)
          dns-port (get-in cfg [:dns :port] 53)
          http-port (get-in cfg [:http :http-port] 80)
          https-port (get-in cfg [:http :https-port] 443)
          smtp-port (get-in cfg [:smtp :port] 25)
          cluster-port (get-in cfg [:cluster :nodes node-id :port] 5000)
          peers (disj (set (keys (get-in cfg [:cluster :nodes] {}))) node-id)]
      (println "============================================================")
      (println (format "clj-web node '%s' started for domain '%s'" node-id domain))
      (println (format "  DNS Server:    port %d (UDP & TCP)" dns-port))
      (println (format "  HTTP Server:   port %d" http-port))
      (println (format "  HTTPS Server:  port %d" https-port))
      (println (format "  SMTP Server:   port %d (STARTTLS)" smtp-port))
      (println (format "  Cluster Mesh:  port %d (Peers: %s)" cluster-port (str/join ", " peers)))
      (println "============================================================"))
    ;; Block until interrupted
    (try
      @(promise)
      (catch InterruptedException _
        (stop-node! node)))))

(defn -main
  "CLI entrypoint for clj-web."
  [& args]
  (let [cmd (first args)
        arg (second args)]
    (cond
      (or (nil? cmd) (#{"--help" "-h" "help"} cmd))
      (print-usage)

      (= cmd "print-fingerprint")
      (if arg
        (cmd-print-fingerprint arg)
        (do (println "Error: Missing <config.edn> argument.") (print-usage) (System/exit 1)))

      (= cmd "list-mail")
      (if arg
        (cmd-list-mail arg)
        (do (println "Error: Missing <config.edn> argument.") (print-usage) (System/exit 1)))

      (= cmd "read-mail")
      (if arg
        (cmd-read-mail arg (nth args 2 nil))
        (do (println "Error: Missing <config.edn> argument.") (print-usage) (System/exit 1)))

      (= cmd "run")
      (if arg
        (cmd-run arg)
        (do (println "Error: Missing <config.edn> argument.") (print-usage) (System/exit 1)))

      ;; Fallback: if first argument is a path (e.g. config.edn)
      (and cmd (or (str/ends-with? cmd ".edn") (.exists (clojure.java.io/file cmd))))
      (cmd-run cmd)

      :else
      (do
        (println (str "Unknown command: " cmd))
        (print-usage)
        (System/exit 1)))))
