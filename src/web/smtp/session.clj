(ns web.smtp.session
  "Pure Sans-IO RFC 5321 inbound SMTP state machine.
   Enforces strict open-relay prevention, message size caps (128 KB default),
   dot-unstuffing, STARTTLS transitions, and command sequence rules."
  (:require [clojure.string :as str])
  (:import [java.nio.charset StandardCharsets]))

(defn init-session
  "Initializes an SMTP session state map.
   Options:
     :domain (default \"localhost\")
     :max-message-bytes (default 131072 = 128 KB)
     :allowed-recipients (set of lowercase email addresses or wildcard \"@domain\")
     :tls-active? (boolean, default false)"
  ([] (init-session {}))
  ([opts]
   (let [domain (or (:domain opts) "localhost")
         max-bytes (long (or (:max-message-bytes opts) 131072))
         recipients (set (keep (fn [r]
                                 (when r
                                   (-> (if (keyword? r) (name r) (str r))
                                       (str/trim)
                                       (str/lower-case))))
                               (or (:allowed-recipients opts) [])))
         tls? (boolean (:tls-active? opts))]
     {:state :connected
      :domain domain
      :max-message-bytes max-bytes
      :allowed-recipients recipients
      :tls-active? tls?
      :helo nil
      :mail-from nil
      :rcpt-to []
      :data-lines []
      :data-bytes 0
      :over-size? false})))

(defn greeting
  "Generates initial 220 service ready greeting upon client TCP connection."
  [session-state]
  {:state (assoc session-state :state :greeted)
   :responses [(str "220 " (:domain session-state) " ESMTP clj-web ready")]})

(defn- recipient-allowed?
  "Checks if recipient address is allowed by configuration to prevent open relay.
   Only accepts exact addresses in allowed-recipients or addresses at @<domain>
   when (str \"@\" domain-lower) is in allowed-recipients. Never allows out-of-domain relay."
  [allowed-recipients domain addr]
  (let [addr-lower (str/lower-case (or addr ""))
        domain-lower (str/lower-case (or domain ""))
        domain-suffix (str "@" domain-lower)]
    (or (contains? allowed-recipients addr-lower)
        (and (str/ends-with? addr-lower domain-suffix)
             (contains? allowed-recipients domain-suffix)))))

(defn- parse-mail-from-line
  "Parses reverse-path and optional SIZE= parameter from MAIL FROM line."
  [raw-line]
  (let [line (str/replace-first raw-line #"(?i)^MAIL\s*FROM:\s*" "")
        size-match (re-find #"(?i)\bSIZE=(\d+)" line)
        size (when size-match (Long/parseLong (second size-match)))
        path-match (re-find #"<([^>]*)>" line)]
    (if path-match
      {:from (second path-match) :size size}
      (let [clean (str/trim (str/replace line #"(?i)\bSIZE=\d+" ""))]
        (if (str/blank? clean)
          {:from "" :size size}
          {:from clean :size size})))))

(defn- parse-rcpt-to-line
  "Parses forward-path from RCPT TO line."
  [raw-line]
  (let [line (str/replace-first raw-line #"(?i)^RCPT\s*TO:\s*" "")
        path-match (re-find #"<([^>]*)>" line)]
    (if path-match
      (second path-match)
      (str/trim line))))

(defn handle-smtp-line
  "Pure function processing a single SMTP line without CRLF.
   Returns {:state updated-state :responses [strings...] :effects [effects...]}."
  [state raw-line]
  (let [line (or raw-line "")]
    (if (= (:state state) :reading-data)
      ;; -----------------------------------------------------------------------
      ;; DATA mode: collecting message body until "."
      ;; -----------------------------------------------------------------------
      (if (= line ".")
        ;; End of data stream
        (if (or (:over-size? state) (> (:data-bytes state) (:max-message-bytes state)))
          {:state (assoc state :state :greeted :mail-from nil :rcpt-to [] :data-lines [] :data-bytes 0 :over-size? false)
           :responses ["552 5.3.4 Message size exceeds fixed maximum"]
           :effects []}
          (let [data-str (str (str/join "\r\n" (:data-lines state)) "\r\n")]
            {:state (assoc state :state :greeted :mail-from nil :rcpt-to [] :data-lines [] :data-bytes 0 :over-size? false)
             :responses ["250 2.0.0 OK: queued"]
             :effects [{:type :deliver-mail
                        :from (:mail-from state)
                        :to (:rcpt-to state)
                        :helo (:helo state)
                        :data-str data-str
                        :size-bytes (:data-bytes state)}]}))

        ;; Data line: leading-dot unstuffing (RFC 5321 §4.5.2) and size check
        (let [unstuffed (if (str/starts-with? line "..") (subs line 1) line)
              line-bytes (+ (alength (.getBytes ^String line StandardCharsets/UTF_8)) 2)
              new-bytes (+ (:data-bytes state) line-bytes)
              max-bytes (:max-message-bytes state)]
          (cond
            ;; Exceeded 2 * max-bytes: immediate abort and close connection
            (> new-bytes (* 2 max-bytes))
            {:state (assoc state :state :greeted :mail-from nil :rcpt-to [] :data-lines [] :data-bytes 0 :over-size? false)
             :responses ["552 5.3.4 Message size exceeds fixed maximum"]
             :effects [{:type :close}]}

            ;; Exceeded max-bytes: stop accumulating data lines to bound memory
            (> new-bytes max-bytes)
            {:state (assoc state
                           :data-lines []
                           :data-bytes new-bytes
                           :over-size? true)
             :responses []
             :effects []}

            ;; Within limit: accumulate data lines
            :else
            {:state (assoc state
                           :data-lines (conj (:data-lines state) unstuffed)
                           :data-bytes new-bytes)
             :responses []
             :effects []})))

      ;; -----------------------------------------------------------------------
      ;; Command mode
      ;; -----------------------------------------------------------------------
      (let [trimmed (str/trim line)
            upper (str/upper-case trimmed)]
        (cond
          (str/blank? trimmed)
          {:state state :responses ["500 5.5.1 Empty command"] :effects []}

          ;; EHLO
          (or (= upper "EHLO") (str/starts-with? upper "EHLO "))
          (let [helo-arg (str/trim (subs trimmed (min (count trimmed) 4)))
                clean-helo (if (str/blank? helo-arg) "client" helo-arg)
                responses (concat
                           [(str "250-" (:domain state))]
                           (when-not (:tls-active? state)
                             ["250-STARTTLS"])
                           [(str "250-SIZE " (:max-message-bytes state))
                            "250 8BITMIME"])]
            {:state (assoc state
                           :helo clean-helo
                           :mail-from nil
                           :rcpt-to []
                           :data-lines []
                           :data-bytes 0
                           :state :greeted)
             :responses (vec responses)
             :effects []})

          ;; HELO
          (or (= upper "HELO") (str/starts-with? upper "HELO "))
          (let [helo-arg (str/trim (subs trimmed (min (count trimmed) 4)))
                clean-helo (if (str/blank? helo-arg) "client" helo-arg)]
            {:state (assoc state
                           :helo clean-helo
                           :mail-from nil
                           :rcpt-to []
                           :data-lines []
                           :data-bytes 0
                           :state :greeted)
             :responses [(str "250 " (:domain state))]
             :effects []})

          ;; STARTTLS
          (= upper "STARTTLS")
          (if (:tls-active? state)
            {:state state :responses ["503 5.5.1 TLS already active"] :effects []}
            {:state (assoc state
                           :helo nil
                           :mail-from nil
                           :rcpt-to []
                           :data-lines []
                           :data-bytes 0
                           :tls-active? true
                           :state :greeted)
             :responses ["220 2.0.0 Ready to start TLS"]
             :effects [{:type :starttls}]})

          ;; MAIL FROM:
          (str/starts-with? (str/replace upper #"\s+" "") "MAILFROM:")
          (if-not (:helo state)
            {:state state :responses ["503 5.5.1 Send HELO/EHLO first"] :effects []}
            (let [{:keys [from size]} (parse-mail-from-line trimmed)]
              (cond
                (and size (> size (:max-message-bytes state)))
                {:state state :responses ["552 5.3.4 Message size exceeds fixed maximum"] :effects []}

                :else
                {:state (assoc state
                               :mail-from from
                               :rcpt-to []
                               :data-lines []
                               :data-bytes 0
                               :state :mail)
                 :responses ["250 2.1.0 OK"]
                 :effects []})))

          ;; RCPT TO:
          (str/starts-with? (str/replace upper #"\s+" "") "RCPTTO:")
          (if-not (or (= (:state state) :mail) (= (:state state) :rcpt))
            {:state state :responses ["503 5.5.1 Need MAIL command"] :effects []}
            (let [addr (parse-rcpt-to-line trimmed)
                  addr-lower (str/lower-case addr)]
              (cond
                (not (recipient-allowed? (:allowed-recipients state) (:domain state) addr-lower))
                {:state state :responses ["550 5.7.1 Relay access denied"] :effects []}

                (>= (count (:rcpt-to state)) 16)
                {:state state :responses ["452 4.5.3 Too many recipients"] :effects []}

                :else
                {:state (assoc state
                               :rcpt-to (conj (:rcpt-to state) addr-lower)
                               :state :rcpt)
                 :responses ["250 2.1.5 OK"]
                 :effects []})))

          ;; DATA
          (= upper "DATA")
          (cond
            (empty? (:rcpt-to state))
            {:state state :responses ["503 5.5.1 Need RCPT command"] :effects []}

            :else
            {:state (assoc state
                           :state :reading-data
                           :data-lines []
                           :data-bytes 0)
             :responses ["354 Start mail input; end with <CRLF>.<CRLF>"]
             :effects []})

          ;; RSET
          (= upper "RSET")
          {:state (assoc state
                         :mail-from nil
                         :rcpt-to []
                         :data-lines []
                         :data-bytes 0
                         :state :greeted)
           :responses ["250 2.0.0 OK"]
           :effects []}

          ;; NOOP
          (or (= upper "NOOP") (str/starts-with? upper "NOOP "))
          {:state state :responses ["250 2.0.0 OK"] :effects []}

          ;; VRFY
          (or (= upper "VRFY") (str/starts-with? upper "VRFY "))
          {:state state :responses ["252 2.5.2 Cannot VRFY user"] :effects []}

          ;; QUIT
          (= upper "QUIT")
          {:state (assoc state :state :quit)
           :responses ["221 2.0.0 Bye"]
           :effects [{:type :close}]}

          ;; Unrecognized
          :else
          {:state state :responses ["500 5.5.1 Command unrecognized"] :effects []})))))
