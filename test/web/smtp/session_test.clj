(ns web.smtp.session-test
  "Unit and property tests for RFC 5321 inbound SMTP state machine.
   Tests command sequencing, open-relay prevention, size caps, dot-unstuffing,
   and generative property invariants."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.smtp.session :as session]))

(deftest test-session-init-and-greeting
  (testing "init-session defaults"
    (let [s (session/init-session)]
      (is (= :connected (:state s)))
      (is (= "localhost" (:domain s)))
      (is (= 131072 (:max-message-bytes s)))
      (is (false? (:tls-active? s)))
      (is (nil? (:helo s)))
      (is (nil? (:mail-from s)))
      (is (= [] (:rcpt-to s)))
      (is (= [] (:data-lines s)))
      (is (= 0 (:data-bytes s)))))

  (testing "greeting transitions to :greeted with 220 banner"
    (let [s (session/init-session {:domain "mail.example.com"})
          res (session/greeting s)]
      (is (= :greeted (get-in res [:state :state])))
      (is (= ["220 mail.example.com ESMTP clj-web ready"] (:responses res))))))

(deftest test-ehlo-helo-commands
  (let [s (session/init-session {:domain "mail.example.com" :max-message-bytes 65536})]
    (testing "EHLO advertises STARTTLS, SIZE, 8BITMIME when TLS is inactive"
      (let [res (session/handle-smtp-line s "EHLO client.remote.org")
            st (:state res)]
        (is (= :greeted (:state st)))
        (is (= "client.remote.org" (:helo st)))
        (is (= ["250-mail.example.com"
                "250-STARTTLS"
                "250-SIZE 65536"
                "250 8BITMIME"]
               (:responses res)))))

    (testing "EHLO omits STARTTLS when TLS is already active"
      (let [tls-s (assoc s :tls-active? true)
            res (session/handle-smtp-line tls-s "EHLO client.remote.org")]
        (is (= ["250-mail.example.com"
                "250-SIZE 65536"
                "250 8BITMIME"]
               (:responses res)))))

    (testing "HELO returns single 250 response"
      (let [res (session/handle-smtp-line s "HELO client.remote.org")]
        (is (= :greeted (get-in res [:state :state])))
        (is (= "client.remote.org" (get-in res [:state :helo])))
        (is (= ["250 mail.example.com"] (:responses res)))))))

(deftest test-starttls-command
  (let [s (-> (session/init-session {:domain "example.com"})
              (assoc :helo "client.org" :state :greeted))]
    (testing "STARTTLS when inactive emits effect and resets envelope"
      (let [res (session/handle-smtp-line s "STARTTLS")
            st (:state res)]
        (is (= ["220 2.0.0 Ready to start TLS"] (:responses res)))
        (is (= [{:type :starttls}] (:effects res)))
        (is (true? (:tls-active? st)))
        (is (= :greeted (:state st)))
        (is (nil? (:helo st)))))

    (testing "STARTTLS when active returns 503 error"
      (let [tls-s (assoc s :tls-active? true)
            res (session/handle-smtp-line tls-s "STARTTLS")]
        (is (= ["503 5.5.1 TLS already active"] (:responses res)))
        (is (empty? (:effects res)))))))

(deftest test-out-of-order-commands
  (let [clean (session/init-session {:domain "example.com"})]
    (testing "MAIL FROM before HELO/EHLO returns 503"
      (let [res (session/handle-smtp-line clean "MAIL FROM:<alice@sender.org>")]
        (is (= ["503 5.5.1 Send HELO/EHLO first"] (:responses res)))))

    (testing "RCPT TO before MAIL FROM returns 503"
      (let [helo-s (assoc clean :helo "client.org" :state :greeted)
            res (session/handle-smtp-line helo-s "RCPT TO:<admin@example.com>")]
        (is (= ["503 5.5.1 Need MAIL command"] (:responses res)))))

    (testing "DATA before RCPT TO returns 503"
      (let [mail-s (assoc clean :helo "client.org" :mail-from "alice@sender.org" :state :mail)
            res (session/handle-smtp-line mail-s "DATA")]
        (is (= ["503 5.5.1 Need RCPT command"] (:responses res)))))))

(deftest test-mail-from-and-size-cap
  (let [s (-> (session/init-session {:domain "example.com" :max-message-bytes 1000})
              (assoc :helo "client.org" :state :greeted))]
    (testing "Valid MAIL FROM sets reverse-path"
      (let [res (session/handle-smtp-line s "MAIL FROM:<alice@sender.org>")
            st (:state res)]
        (is (= ["250 2.1.0 OK"] (:responses res)))
        (is (= :mail (:state st)))
        (is (= "alice@sender.org" (:mail-from st)))))

    (testing "MAIL FROM with bounce sender <>"
      (let [res (session/handle-smtp-line s "MAIL FROM:<>")
            st (:state res)]
        (is (= ["250 2.1.0 OK"] (:responses res)))
        (is (= "" (:mail-from st)))))

    (testing "MAIL FROM with SIZE within bounds"
      (let [res (session/handle-smtp-line s "MAIL FROM:<alice@sender.org> SIZE=500")]
        (is (= ["250 2.1.0 OK"] (:responses res)))))

    (testing "MAIL FROM with SIZE exceeding maximum returns 552"
      (let [res (session/handle-smtp-line s "MAIL FROM:<alice@sender.org> SIZE=2000")]
        (is (= ["552 5.3.4 Message size exceeds fixed maximum"] (:responses res)))))))

(deftest test-rcpt-to-open-relay-prevention
  (let [allowed #{"admin@example.com" "postmaster@example.com" "security@example.com"}
        s (-> (session/init-session {:domain "example.com" :allowed-recipients allowed})
              (assoc :helo "client.org" :mail-from "alice@sender.org" :state :mail))]
    (testing "Allowed recipient accepted with 250"
      (let [res (session/handle-smtp-line s "RCPT TO:<admin@example.com>")
            st (:state res)]
        (is (= ["250 2.1.5 OK"] (:responses res)))
        (is (= :rcpt (:state st)))
        (is (= ["admin@example.com"] (:rcpt-to st)))))

    (testing "Disallowed recipient (open relay attempt) rejected with 550"
      (let [res (session/handle-smtp-line s "RCPT TO:<victim@otherdomain.com>")
            st (:state res)]
        (is (= ["550 5.7.1 Relay access denied"] (:responses res)))
        (is (empty? (:rcpt-to st)))))

    (testing "Domain wildcard allowlist accepts any address at domain"
      (let [wildcard-s (-> (session/init-session {:domain "example.com" :allowed-recipients #{"@example.com"}})
                           (assoc :helo "client.org" :mail-from "alice@sender.org" :state :mail))
            res (session/handle-smtp-line wildcard-s "RCPT TO:<anyone@example.com>")]
        (is (= ["250 2.1.5 OK"] (:responses res)))
        (is (= ["anyone@example.com"] (get-in res [:state :rcpt-to])))))

    (testing "Too many recipients (limit 16) returns 452"
      (let [full-rcpt (vec (repeat 16 "admin@example.com"))
            full-s (assoc s :rcpt-to full-rcpt :state :rcpt)
            res (session/handle-smtp-line full-s "RCPT TO:<admin@example.com>")]
        (is (= ["452 4.5.3 Too many recipients"] (:responses res)))))))

(deftest test-data-delivery-and-dot-unstuffing
  (let [allowed #{"admin@example.com"}
        s (-> (session/init-session {:domain "example.com" :allowed-recipients allowed :max-message-bytes 1000})
              (assoc :helo "client.org" :mail-from "alice@sender.org" :rcpt-to ["admin@example.com"] :state :rcpt))]
    (testing "DATA command transitions to :reading-data with 354"
      (let [res (session/handle-smtp-line s "DATA")
            st (:state res)]
        (is (= :reading-data (:state st)))
        (is (= ["354 Start mail input; end with <CRLF>.<CRLF>"] (:responses res)))
        (is (= [] (:data-lines st)))
        (is (= 0 (:data-bytes st)))))

    (testing "Data collection, dot-unstuffing, and completion with ."
      (let [d1 (session/handle-smtp-line (assoc s :state :reading-data :data-lines [] :data-bytes 0) "Subject: Test")
            d2 (session/handle-smtp-line (:state d1) "..Dot unstuff line")
            d3 (session/handle-smtp-line (:state d2) "Normal line")
            finish (session/handle-smtp-line (:state d3) ".")]
        (is (= ["250 2.0.0 OK: queued"] (:responses finish)))
        (let [effect (first (:effects finish))]
          (is (= :deliver-mail (:type effect)))
          (is (= "alice@sender.org" (:from effect)))
          (is (= ["admin@example.com"] (:to effect)))
          (is (= "client.org" (:helo effect)))
          (is (.contains ^String (:data-str effect) "Subject: Test\r\n.Dot unstuff line\r\nNormal line\r\n")))
        ;; Envelope reset
        (let [final-st (:state finish)]
          (is (= :greeted (:state final-st)))
          (is (nil? (:mail-from final-st)))
          (is (= [] (:rcpt-to final-st)))
          (is (= [] (:data-lines final-st)))
          (is (= 0 (:data-bytes final-st))))))

    (testing "Data size exceeding max-message-bytes returns 552 upon ."
      (let [small-s (assoc s :state :reading-data :data-lines [] :data-bytes 0 :max-message-bytes 30)
            d1 (session/handle-smtp-line small-s "This is a line that exceeds the 30 byte limit")
            finish (session/handle-smtp-line (:state d1) ".")]
        (is (= ["552 5.3.4 Message size exceeds fixed maximum"] (:responses finish)))
        (is (empty? (:effects finish)))))))

(deftest test-control-commands
  (let [s (-> (session/init-session {:domain "example.com"})
              (assoc :helo "client.org" :mail-from "alice@sender.org" :rcpt-to ["admin@example.com"] :state :rcpt))]
    (testing "RSET clears envelope and returns 250"
      (let [res (session/handle-smtp-line s "RSET")
            st (:state res)]
        (is (= ["250 2.0.0 OK"] (:responses res)))
        (is (= :greeted (:state st)))
        (is (nil? (:mail-from st)))
        (is (= [] (:rcpt-to st)))))

    (testing "NOOP returns 250"
      (let [res (session/handle-smtp-line s "NOOP")]
        (is (= ["250 2.0.0 OK"] (:responses res)))))

    (testing "VRFY returns 252"
      (let [res (session/handle-smtp-line s "VRFY admin")]
        (is (= ["252 2.5.2 Cannot VRFY user"] (:responses res)))))

    (testing "QUIT returns 221 and emits :close"
      (let [res (session/handle-smtp-line s "QUIT")]
        (is (= ["221 2.0.0 Bye"] (:responses res)))
        (is (= [{:type :close}] (:effects res)))
        (is (= :quit (get-in res [:state :state])))))

    (testing "Unknown command returns 500"
      (let [res (session/handle-smtp-line s "FOOBAR")]
        (is (= ["500 5.5.1 Command unrecognized"] (:responses res)))))))

(defspec prop-smtp-invariants-fuzzing 100
  (prop/for-all [commands (gen/vector (gen/one-of [(gen/elements ["EHLO client.org"
                                                                  "HELO client.org"
                                                                  "STARTTLS"
                                                                  "RSET"
                                                                  "NOOP"
                                                                  "VRFY"
                                                                  "QUIT"
                                                                  "MAIL FROM:<alice@sender.org>"
                                                                  "MAIL FROM:<attacker@evil.org>"
                                                                  "RCPT TO:<admin@example.com>"
                                                                  "RCPT TO:<victim@other.com>"
                                                                  "DATA"
                                                                  "."
                                                                  "Subject: Hello"
                                                                  "..Leading dot"
                                                                  "FOOBAR"
                                                                  ""])
                                                   gen/string-ascii])
                                      1 60)]
                (let [allowed #{"admin@example.com"}
                      initial (session/init-session {:domain "example.com"
                                                     :allowed-recipients allowed
                                                     :max-message-bytes 2048})]
                  (loop [cmds commands
                         st initial
                         delivered []]
                    (if (empty? cmds)
          ;; Invariants:
          ;; 1. Every delivered mail must have been addressed only to allowed recipients
                      (every? (fn [mail]
                                (and (seq (:to mail))
                                     (every? #(contains? allowed %) (:to mail))
                                     (<= (:size-bytes mail) 2048)))
                              delivered)
                      (let [cmd (first cmds)
                            result (try
                                     (session/handle-smtp-line st cmd)
                                     (catch Exception _ nil))]
                        (if-not result
                          false
                          (let [effects (:effects result)
                                new-delivered (into delivered (filter #(= (:type %) :deliver-mail) effects))]
                            (recur (rest cmds) (:state result) new-delivered)))))))))
