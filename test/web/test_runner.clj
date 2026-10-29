(ns web.test-runner
  "Discovers and executes all test namespaces under test/."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :as t]))

(defn find-test-namespaces
  "Recursively scans dir for *-test.clj files and returns namespace symbols."
  ([] (find-test-namespaces "test"))
  ([dir]
   (let [dir-file (io/file dir)
         dir-path (.toPath dir-file)]
     (if-not (.exists dir-file)
       []
       (->> (file-seq dir-file)
            (filter (fn [f]
                      (and (.isFile f)
                           (str/ends-with? (.getName f) ".clj"))))
            (map (fn [f]
                   (let [rel (.relativize dir-path (.toPath f))
                         rel-str (str rel)
                         no-ext (subs rel-str 0 (- (count rel-str) 4))]
                     (-> no-ext
                         (str/replace #"[/\\\\]" ".")
                         (str/replace "_" "-")
                         symbol))))
            (filter (fn [sym]
                      (str/ends-with? (name sym) "-test")))
            sort
            vec)))))

(defn -main
  "CLI entrypoint for running tests."
  [& _args]
  (let [test-nses (find-test-namespaces "test")]
    (when (empty? test-nses)
      (println "No test namespaces found under test/!")
      (System/exit 1))
    (println "Running tests in namespaces:" test-nses)
    (doseq [ns-sym test-nses]
      (require ns-sym))
    (let [results (apply t/run-tests test-nses)
          failures (+ (:fail results 0) (:error results 0))]
      (if (zero? failures)
        (do
          (println "\nAll tests passed successfully.")
          (System/exit 0))
        (do
          (println (str "\nTests failed: " (:fail results 0) " failures, " (:error results 0) " errors."))
          (System/exit 1))))))
