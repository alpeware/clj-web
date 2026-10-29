(ns web.http.ratelimit-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.http.ratelimit :as rl]))

(deftest test-ip->subnet-key
  (testing "IPv4 addresses normalize to /24 prefix"
    (is (= "1.2.3.0/24" (rl/ip->subnet-key "1.2.3.4")))
    (is (= "1.2.3.0/24" (rl/ip->subnet-key "1.2.3.4:8080")))
    (is (= "192.168.1.0/24" (rl/ip->subnet-key "192.168.1.254")))
    (is (= "10.0.0.0/24" (rl/ip->subnet-key " 10.0.0.1:53 ")))
    (is (= "1.2.3.0/24" (rl/ip->subnet-key "1.2.3.0/24"))))

  (testing "IPv6 addresses normalize to /64 (first 4 hextets)"
    (is (= "2001:db8:85a3:0::/64" (rl/ip->subnet-key "2001:0db8:85a3:0000:0000:8a2e:0370:7334")))
    (is (= "2001:db8:85a3:0::/64" (rl/ip->subnet-key "2001:db8:85a3::1")))
    (is (= "2001:db8:85a3:1::/64" (rl/ip->subnet-key "[2001:db8:85a3:1::1]:443")))
    (is (= "0:0:0:0::/64" (rl/ip->subnet-key "::1")))
    (is (= "2001:db8:85a3:0::/64" (rl/ip->subnet-key "2001:db8:85a3:0::/64"))))

  (testing "nil or unparseable input"
    (is (nil? (rl/ip->subnet-key nil)))
    (is (= "internal-host" (rl/ip->subnet-key "internal-host")))))

(deftest test-check-and-consume-lifecycle
  (testing "initial consumption from fresh bucket"
    (let [s0 (rl/init-limiter {:capacity 10.0 :refill-per-sec 2.0})
          r1 (rl/check-and-consume s0 "1.2.3.0/24" 4.0 1000)]
      (is (true? (:allowed? r1)))
      (is (= 6.0 (:remaining r1)))
      (is (= 0 (:retry-after-ms r1)))

      (testing "exceeding remaining tokens returns allowed? false with retry-after-ms"
        (let [r2 (rl/check-and-consume (:state r1) "1.2.3.0/24" 8.0 1000)]
          (is (false? (:allowed? r2)))
          (is (= 6.0 (:remaining r2)))
          ;; Missing 2.0 tokens at 2.0 tokens/sec = 1000 ms
          (is (= 1000 (:retry-after-ms r2)))

          (testing "tokens refill over elapsed time"
            ;; Advance 500 ms -> 1.0 token refilled -> 7.0 tokens available
            (let [r3 (rl/check-and-consume (:state r2) "1.2.3.0/24" 7.0 1500)]
              (is (true? (:allowed? r3)))
              (is (= 0.0 (:remaining r3)))
              (is (= 0 (:retry-after-ms r3))))

            ;; Advance 10 seconds -> refilled and capped at capacity 10.0
            (let [r4 (rl/check-and-consume (:state r2) "1.2.3.0/24" 10.0 11000)]
              (is (true? (:allowed? r4)))
              (is (= 0.0 (:remaining r4))))))))))

(deftest test-record-egress-budget
  (testing "monthly egress tracking enforces budget and records totals"
    (let [s0 (rl/init-limiter {:monthly-egress-limit-bytes 1000})
          ;; Consume 400 bytes
          r1 (rl/record-egress s0 400 "2026-10")]
      (is (true? (:allowed? r1)))
      (is (= 600 (:remaining-bytes r1)))
      (is (= 400 (get-in (:state r1) [:egress-by-month "2026-10"])))

      ;; Consume 500 bytes -> 900 total
      (let [r2 (rl/record-egress (:state r1) 500 "2026-10")]
        (is (true? (:allowed? r2)))
        (is (= 100 (:remaining-bytes r2)))
        (is (= 900 (get-in (:state r2) [:egress-by-month "2026-10"])))

        ;; Consume 200 bytes -> 1100 total (budget exceeded)
        (let [r3 (rl/record-egress (:state r2) 200 "2026-10")]
          (is (false? (:allowed? r3)))
          (is (= 0 (:remaining-bytes r3)))
          (is (= 1100 (get-in (:state r3) [:egress-by-month "2026-10"])))

          ;; Distinct month has independent fresh budget
          (let [r4 (rl/record-egress (:state r3) 300 "2026-11")]
            (is (true? (:allowed? r4)))
            (is (= 700 (:remaining-bytes r4)))
            (is (= 300 (get-in (:state r4) [:egress-by-month "2026-11"])))
            ;; 2026-10 remains 1100
            (is (= 1100 (get-in (:state r4) [:egress-by-month "2026-10"])))))))))

(deftest test-prune-stale-buckets
  (testing "prunes idle buckets while keeping active buckets"
    (let [s0 (rl/init-limiter {:capacity 20.0 :refill-per-sec 5.0})
          s1 (:state (rl/check-and-consume s0 "1.1.1.0/24" 1.0 1000))
          s2 (:state (rl/check-and-consume s1 "2.2.2.0/24" 1.0 4000))]
      (is (contains? (:buckets s2) "1.1.1.0/24"))
      (is (contains? (:buckets s2) "2.2.2.0/24"))

      ;; At now-ms = 5000 with max-idle-ms = 2000:
      ;; "1.1.1.0/24" idle time = 4000 >= 2000 -> evicted
      ;; "2.2.2.0/24" idle time = 1000 < 2000 -> kept
      (let [pruned (rl/prune-stale-buckets s2 5000 2000)]
        (is (not (contains? (:buckets pruned) "1.1.1.0/24")))
        (is (contains? (:buckets pruned) "2.2.2.0/24"))))))

;; Generative Property Tests
(defspec prop-token-bucket-invariants
  100
  (prop/for-all [capacity (gen/choose 10 100)
                 refill-rate (gen/choose 1 20)
                 deltas (gen/vector (gen/tuple (gen/choose 0 5000) (gen/choose 1 30)) 1 20)]
                (let [init-s (rl/init-limiter {:capacity (double capacity)
                                               :refill-per-sec (double refill-rate)})]
                  (loop [state init-s
                         now 1000
                         remaining-deltas deltas]
                    (if (empty? remaining-deltas)
                      true
                      (let [[elapsed req-tokens] (first remaining-deltas)
                            current-time (+ now elapsed)
                            res (rl/check-and-consume state "test-bucket" (double req-tokens) current-time)
                            rem-tokens (:remaining res)]
            ;; Invariant 1: remaining tokens never exceed capacity
            ;; Invariant 2: remaining tokens never negative
            ;; Invariant 3: if allowed, retry-after is 0; if rejected, retry-after >= 0
                        (if (and (<= 0.0 rem-tokens (+ capacity 0.001))
                                 (if (:allowed? res)
                                   (zero? (:retry-after-ms res))
                                   (>= (:retry-after-ms res) 0)))
                          (recur (:state res) current-time (rest remaining-deltas))
                          false)))))))

(defspec prop-monotonic-egress-accounting
  100
  (prop/for-all [limit (gen/choose 1000 100000)
                 increments (gen/vector (gen/choose 0 5000) 1 30)]
                (let [init-s (rl/init-limiter {:monthly-egress-limit-bytes limit})
                      month "2026-10"]
                  (loop [state init-s
                         expected-total 0
                         remaining-incs increments]
                    (if (empty? remaining-incs)
                      (= expected-total (get-in state [:egress-by-month month] 0))
                      (let [inc-bytes (first remaining-incs)
                            next-total (+ expected-total inc-bytes)
                            res (rl/record-egress state inc-bytes month)
                            curr-recorded (get-in (:state res) [:egress-by-month month])]
            ;; Monotonic: new total >= old total
                        (if (and (= curr-recorded next-total)
                                 (>= curr-recorded expected-total)
                                 (= (:allowed? res) (<= curr-recorded limit))
                                 (= (:remaining-bytes res) (max 0 (- limit curr-recorded))))
                          (recur (:state res) next-total (rest remaining-incs))
                          false)))))))

(defspec prop-bucket-pruning-invariants
  100
  (prop/for-all [now-ms (gen/choose 10000 50000)
                 max-idle (gen/choose 1000 5000)
                 bucket-times (gen/vector (gen/choose 0 50000) 1 20)]
                (let [buckets (into {}
                                    (map-indexed (fn [idx t]
                                                   [(str "bucket-" idx)
                                                    {:tokens 10.0 :last-refill-ms (long t)}])
                                                 bucket-times))
                      state {:buckets buckets}
                      pruned (rl/prune-stale-buckets state now-ms max-idle)
                      remaining-buckets (:buckets pruned)]
      ;; Every remaining bucket must have idle time < max-idle
                  (every? (fn [[_k b]]
                            (< (- now-ms (:last-refill-ms b)) max-idle))
                          remaining-buckets))))
