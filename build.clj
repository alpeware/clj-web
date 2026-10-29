(ns build
  "Build script for clj-web using tools.build."
  (:require [clojure.java.io :as io]
            [clojure.tools.build.api :as b]))

(def class-dir "target/classes")
(def uber-file "target/clj-web.jar")

(def java-cmd
  (or (System/getenv "JAVA_CMD")
      (let [jhome (System/getProperty "java.home")
            jexe (io/file jhome "bin" "java")]
        (if (.exists jexe)
          (.getAbsolutePath jexe)
          "java"))))

(def java-opts
  ["--enable-native-access=ALL-UNNAMED"
   "--add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED"
   "--add-exports=java.base/sun.security.x509=ALL-UNNAMED"])

(defn clean [_]
  (b/delete {:path "target"}))

(defn uber [_]
  (clean nil)
  (let [basis (b/create-basis {:project "deps.edn"})
        src-dirs (filterv #(.exists (io/file %)) ["src" "resources"])]
    (b/copy-dir {:src-dirs src-dirs
                 :target-dir class-dir})
    (b/compile-clj {:basis basis
                    :src-dirs ["src"]
                    :class-dir class-dir
                    :ns-compile ['web.main]
                    :java-cmd java-cmd
                    :java-opts java-opts})
    (b/uber {:class-dir class-dir
             :uber-file uber-file
             :basis basis
             :main 'web.main})
    (println (format "Uberjar built successfully at %s" uber-file))))
