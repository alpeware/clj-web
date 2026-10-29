(ns web.http.ratelimit
  "Pure Sans-IO functional token-bucket rate limiter and egress budget tracker.
   Provides per-subnet bucket tracking for DNS RRL, HTTP rate limiting,
   monthly egress byte accounting, and stale bucket eviction."
  (:require [clojure.string :as str]))

(defn init-limiter
  "Initializes rate limiter and egress budget state map."
  ([] (init-limiter {}))
  ([opts]
   (merge {:capacity (double (get opts :capacity 100.0))
           :refill-per-sec (double (get opts :refill-per-sec 10.0))
           :monthly-egress-limit-bytes (long (get opts :monthly-egress-limit-bytes 900000000))
           :buckets {}
           :egress-by-month {}}
          (dissoc opts :capacity :refill-per-sec :monthly-egress-limit-bytes))))

(defn ip->subnet-key
  "Normalizes IPv4 address to /24 prefix (e.g. \"1.2.3.4\" -> \"1.2.3.0/24\")
   and IPv6 to first 4 hextets (/64, e.g. \"2001:db8:85a3:0::/64\").
   Strips ports and square brackets if present. If already a subnet prefix, returns as-is."
  [ip-str]
  (when ip-str
    (let [s (str/trim (str ip-str))]
      (if (or (str/ends-with? s "/24")
              (str/ends-with? s "/64"))
        s
        (let [cleaned (-> s
                          (str/replace #"^\[" "")
                          (str/replace #"\](?::\d+)?$" ""))
              cleaned (if (and (str/includes? cleaned ".")
                               (str/includes? cleaned ":")
                               (not (str/includes? cleaned "::")))
                        (first (str/split cleaned #":"))
                        cleaned)
              addr (try
                     (java.net.InetAddress/ofLiteral cleaned)
                     (catch Exception _
                       (try
                         (java.net.InetAddress/getByName cleaned)
                         (catch Exception _ nil))))]
          (cond
            (instance? java.net.Inet4Address addr)
            (let [bs (.getAddress addr)]
              (str (bit-and (nth bs 0) 0xff) "."
                   (bit-and (nth bs 1) 0xff) "."
                   (bit-and (nth bs 2) 0xff) ".0/24"))

            (instance? java.net.Inet6Address addr)
            (let [bs (.getAddress addr)
                  hextets (for [i (range 0 8 2)]
                            (bit-or (bit-shift-left (bit-and (nth bs i) 0xff) 8)
                                    (bit-and (nth bs (inc i)) 0xff)))]
              (str (str/join ":" (map #(format "%x" %) (take 4 hextets))) "::/64"))

            :else
            cleaned))))))

(defn check-and-consume
  "Pure function evaluating a token bucket consumption against bucket-key.
   Refills tokens according to elapsed time since last-refill-ms up to capacity.
   Returns {:allowed? boolean :state updated-state :remaining double :retry-after-ms long}."
  ([state bucket-key tokens now-ms]
   (check-and-consume state bucket-key tokens now-ms nil))
  ([state bucket-key tokens now-ms opts]
   (let [capacity (double (or (:capacity opts)
                              (get-in state [:buckets bucket-key :capacity])
                              (:capacity state)
                              100.0))
         refill-rate (double (or (:refill-per-sec opts)
                                 (get-in state [:buckets bucket-key :refill-per-sec])
                                 (:refill-per-sec state)
                                 10.0))
         bucket (get-in state [:buckets bucket-key])
         tokens-requested (double (max 0.0 tokens))
         now-ms (long now-ms)
         tokens-before (if bucket
                         (let [last-ms (long (or (:last-refill-ms bucket) now-ms))
                               elapsed-ms (max 0 (- now-ms last-ms))
                               refill (* elapsed-ms (/ refill-rate 1000.0))]
                           (min capacity (+ (double (:tokens bucket)) refill)))
                         capacity)
         allowed? (>= tokens-before tokens-requested)]
     (if allowed?
       (let [remaining (- tokens-before tokens-requested)
             updated-bucket (assoc (or bucket {})
                                   :tokens remaining
                                   :last-refill-ms now-ms)]
         {:allowed? true
          :state (assoc-in state [:buckets bucket-key] updated-bucket)
          :remaining (double remaining)
          :retry-after-ms 0})
       (let [missing (- tokens-requested tokens-before)
             retry-after-ms (if (<= refill-rate 0.0)
                              Long/MAX_VALUE
                              (long (Math/ceil (/ (* missing 1000.0) refill-rate))))
             updated-bucket (assoc (or bucket {})
                                   :tokens tokens-before
                                   :last-refill-ms now-ms)]
         {:allowed? false
          :state (assoc-in state [:buckets bucket-key] updated-bucket)
          :remaining (double tokens-before)
          :retry-after-ms retry-after-ms})))))

(defn record-egress
  "Pure function tracking monthly egress bytes under :egress-by-month ({month-key total-bytes})
   and returning {:allowed? boolean :state updated-state :remaining-bytes long}
   against :monthly-egress-limit-bytes."
  [state bytes-count month-key]
  (let [limit (long (get state :monthly-egress-limit-bytes 900000000))
        current-bytes (long (get-in state [:egress-by-month month-key] 0))
        bytes-to-add (long (max 0 bytes-count))
        new-total (+ current-bytes bytes-to-add)
        allowed? (<= new-total limit)
        remaining-bytes (long (max 0 (- limit new-total)))
        updated-state (assoc-in state [:egress-by-month month-key] new-total)]
    {:allowed? allowed?
     :state updated-state
     :remaining-bytes remaining-bytes}))

(defn prune-stale-buckets
  "Pure function to evict token buckets that have been idle for >= max-idle-ms,
   bounding RAM consumption."
  [state now-ms max-idle-ms]
  (let [now-ms (long now-ms)
        max-idle-ms (long max-idle-ms)
        buckets (get state :buckets {})
        active (into {}
                     (remove (fn [[_k bucket]]
                               (let [last-ms (long (or (:last-refill-ms bucket) 0))]
                                 (>= (- now-ms last-ms) max-idle-ms))))
                     buckets)]
    (assoc state :buckets active)))
