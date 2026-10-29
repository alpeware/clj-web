(ns web.http.content-test
  "Unit and property tests for static content delivery engine:
   path resolution & security guards, two-tier caching, ETag/304,
   HTTP Range/206, Gzip negotiation, and directory listings."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [web.http.content :as content])
  (:import [java.io ByteArrayInputStream File]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.util.zip GZIPInputStream]))

(defn- delete-dir-recursively! [^File f]
  (when (.isDirectory f)
    (doseq [child (.listFiles f)]
      (delete-dir-recursively! child)))
  (.delete f))

(defn- with-temp-content-dir [f]
  (let [dir (.toFile (Files/createTempDirectory "clj-web-content-test" (into-array java.nio.file.attribute.FileAttribute [])))]
    (try
      (f dir)
      (finally
        (delete-dir-recursively! dir)))))

(defn- gunzip-bytes [^bytes bs]
  (with-open [gis (GZIPInputStream. (ByteArrayInputStream. bs))]
    (.readAllBytes gis)))

(deftest test-content-type-for-path
  (testing "Known file extensions map to appropriate Content-Type"
    (is (= "text/html; charset=utf-8" (content/content-type-for-path "index.html")))
    (is (= "text/html; charset=utf-8" (content/content-type-for-path "about.htm")))
    (is (= "text/css; charset=utf-8" (content/content-type-for-path "style.css")))
    (is (= "application/json; charset=utf-8" (content/content-type-for-path "manifest.json")))
    (is (= "text/markdown; charset=utf-8" (content/content-type-for-path "README.md")))
    (is (= "text/plain; charset=utf-8" (content/content-type-for-path "data.edn")))
    (is (= "text/plain; charset=utf-8" (content/content-type-for-path "code.clj")))
    (is (= "text/plain; charset=utf-8" (content/content-type-for-path "checksum.sha256")))
    (is (= "application/java-archive" (content/content-type-for-path "library.jar")))
    (is (= "application/gzip" (content/content-type-for-path "archive.tar.gz")))
    (is (= "application/gzip" (content/content-type-for-path "archive.tgz")))
    (is (= "application/xml; charset=utf-8" (content/content-type-for-path "pom.xml")))
    (is (= "application/octet-stream" (content/content-type-for-path "unknown.bin")))))

(deftest test-resolve-safe-path
  (with-temp-content-dir
    (fn [^File root]
      (let [root-str (.getAbsolutePath root)
            hello (io/file root "hello.txt")
            sub (io/file root "sub")
            sub-file (io/file sub "nested.txt")
            outside (.toFile (Files/createTempFile "outside" ".txt" (into-array java.nio.file.attribute.FileAttribute [])))]
        (spit hello "Hello World")
        (.mkdirs sub)
        (spit sub-file "Nested Content")
        (spit outside "Outside Content")

        (testing "Valid file resolution"
          (let [res (content/resolve-safe-path root-str "/hello.txt")]
            (is (= :ok (:status res)))
            (is (= "hello.txt" (:relative-path res)))
            (is (.exists ^File (:file res)))))

        (testing "Valid nested file resolution"
          (let [res (content/resolve-safe-path root-str "/sub/nested.txt")]
            (is (= :ok (:status res)))
            (is (= "sub/nested.txt" (str/replace (:relative-path res) "\\" "/")))))

        (testing "Non-existent path returns :not-found"
          (let [res (content/resolve-safe-path root-str "/missing.txt")]
            (is (= :not-found (:status res)))))

        (testing "Path traversal attacks return :forbidden"
          (is (= :forbidden (:status (content/resolve-safe-path root-str "/../outside.txt"))))
          (is (= :forbidden (:status (content/resolve-safe-path root-str "/sub/../../outside.txt"))))
          (is (= :forbidden (:status (content/resolve-safe-path root-str "/..%2foutside.txt"))))
          (is (= :forbidden (:status (content/resolve-safe-path root-str "/%2e%2e/outside.txt")))))

        (testing "Hidden files and dot directories return :forbidden"
          (let [hidden (io/file root ".hidden")]
            (spit hidden "secret")
            (is (= :forbidden (:status (content/resolve-safe-path root-str "/.hidden"))))
            (is (= :forbidden (:status (content/resolve-safe-path root-str "/.git/config"))))))

        (testing "Null byte injection returns :forbidden"
          (is (= :forbidden (:status (content/resolve-safe-path root-str "/hello.txt\u0000.png"))))
          (is (= :forbidden (:status (content/resolve-safe-path root-str "/hello.txt%00.png")))))

        (testing "Symlink pointing outside content root returns :forbidden"
          (let [link-path (.toPath (io/file root "escaped-link.txt"))]
            (try
              (Files/createSymbolicLink link-path (.toPath outside) (into-array java.nio.file.attribute.FileAttribute []))
              (is (= :forbidden (:status (content/resolve-safe-path root-str "/escaped-link.txt"))))
              (catch UnsupportedOperationException _
                ;; Filesystem does not support symlinks, skip
                nil))))

        (.delete outside)))))

(deftest test-serve-static-request-methods-and-errors
  (with-temp-content-dir
    (fn [^File root]
      (let [root-str (.getAbsolutePath root)
            cfg {:http {:content-root root-str}}
            cache-atom (atom (content/init-content-cache))]
        (testing "POST / PUT / DELETE rejected with 405 Method Not Allowed"
          (let [res (content/serve-static-request cfg cache-atom {:request/method :POST :request/uri {:path "/"}})]
            (is (= 405 (:response/status res)))
            (is (= "GET, HEAD" (get (:response/headers res) "Allow")))))

        (testing "Non-existent file returns 404"
          (let [res (content/serve-static-request cfg cache-atom {:request/method :GET :request/uri {:path "/no-such.txt"}})]
            (is (= 404 (:response/status res)))))

        (testing "Path traversal returns 403"
          (let [res (content/serve-static-request cfg cache-atom {:request/method :GET :request/uri {:path "/../etc/passwd"}})]
            (is (= 403 (:response/status res)))))))))

(deftest test-serve-static-request-file-delivery
  (with-temp-content-dir
    (fn [^File root]
      (let [root-str (.getAbsolutePath root)
            cfg {:http {:content-root root-str}}
            cache-atom (atom (content/init-content-cache))
            test-file (io/file root "document.txt")
            content-str "This is static content for testing ETag and caching."]
        (spit test-file content-str)

        (testing "Serves file with 200 OK, ETag, and Content-Type"
          (let [req {:request/method :GET
                     :request/uri {:path "/document.txt"}
                     :request/headers {}}
                res (content/serve-static-request cfg cache-atom req)]
            (is (= 200 (:response/status res)))
            (is (= "text/plain; charset=utf-8" (get (:response/headers res) "Content-Type")))
            (is (some? (get (:response/headers res) "ETag")))
            (is (some? (get (:response/headers res) "X-Checksum-SHA256")))
            (is (= content-str (String. ^bytes (:response/body res) StandardCharsets/UTF_8)))

            ;; Test HEAD request returns same headers with nil body
            (let [head-req {:request/method :HEAD
                            :request/uri {:path "/document.txt"}
                            :request/headers {}}
                  head-res (content/serve-static-request cfg cache-atom head-req)]
              (is (= 200 (:response/status head-res)))
              (is (= (get (:response/headers res) "ETag") (get (:response/headers head-res) "ETag")))
              (is (nil? (:response/body head-res))))

            ;; Test If-None-Match conditional request returns 304 Not Modified
            (let [etag (get (:response/headers res) "ETag")
                  inm-req {:request/method :GET
                           :request/uri {:path "/document.txt"}
                           :request/headers {:header/if-none-match [etag]}}
                  inm-res (content/serve-static-request cfg cache-atom inm-req)]
              (is (= 304 (:response/status inm-res)))
              (is (nil? (:response/body inm-res))))

            ;; Test mismatching If-None-Match returns 200 OK
            (let [inm-req {:request/method :GET
                           :request/uri {:path "/document.txt"}
                           :request/headers {:header/if-none-match ["\"wrong-etag\""]}}
                  inm-res (content/serve-static-request cfg cache-atom inm-req)]
              (is (= 200 (:response/status inm-res)))
              (is (some? (:response/body inm-res))))))))))

(deftest test-serve-static-request-gzip-negotiation
  (with-temp-content-dir
    (fn [^File root]
      (let [root-str (.getAbsolutePath root)
            cfg {:http {:content-root root-str}}
            cache-atom (atom (content/init-content-cache))
            test-file (io/file root "compressible.json")
            ;; Repetitive JSON to ensure gzip size is smaller than raw size
            large-json (str "{\"items\": ["
                            (str/join "," (map #(str "{\"id\": " % ", \"name\": \"item-" % "\"}") (range 100)))
                            "]}")]
        (spit test-file large-json)

        (testing "Serves pre-computed Gzip when Accept-Encoding includes gzip"
          (let [req {:request/method :GET
                     :request/uri {:path "/compressible.json"}
                     :request/headers {:header/accept-encoding ["gzip, deflate, br"]}}
                res (content/serve-static-request cfg cache-atom req)]
            (is (= 200 (:response/status res)))
            (is (= "gzip" (get (:response/headers res) "Content-Encoding")))
            (is (= "Accept-Encoding" (get (:response/headers res) "Vary")))
            (is (bytes? (:response/body res)))
            (let [decompressed (String. (gunzip-bytes (:response/body res)) StandardCharsets/UTF_8)]
              (is (= large-json decompressed)))))

        (testing "Does not serve Gzip when Accept-Encoding does not include gzip"
          (let [req {:request/method :GET
                     :request/uri {:path "/compressible.json"}
                     :request/headers {}}
                res (content/serve-static-request cfg cache-atom req)]
            (is (= 200 (:response/status res)))
            (is (nil? (get (:response/headers res) "Content-Encoding")))
            (is (= large-json (String. ^bytes (:response/body res) StandardCharsets/UTF_8)))))))))

(deftest test-serve-static-request-range
  (with-temp-content-dir
    (fn [^File root]
      (let [root-str (.getAbsolutePath root)
            cfg {:http {:content-root root-str}}
            cache-atom (atom (content/init-content-cache))
            test-file (io/file root "sample.txt")
            data "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
        (spit test-file data)
        (let [total-len (count data)]

          (testing "Range: bytes=0-9 returns first 10 bytes with 206 Partial Content"
            (let [req {:request/method :GET
                       :request/uri {:path "/sample.txt"}
                       :request/headers {:header/range ["bytes=0-9"]}}
                  res (content/serve-static-request cfg cache-atom req)]
              (is (= 206 (:response/status res)))
              (is (= (str "bytes 0-9/" total-len) (get (:response/headers res) "Content-Range")))
              (is (= "10" (get (:response/headers res) "Content-Length")))
              (is (= "0123456789" (String. ^bytes (:response/body res) StandardCharsets/UTF_8)))))

          (testing "Range: bytes=10- returns bytes from offset 10 to end"
            (let [req {:request/method :GET
                       :request/uri {:path "/sample.txt"}
                       :request/headers {:header/range ["bytes=10-"]}}
                  res (content/serve-static-request cfg cache-atom req)]
              (is (= 206 (:response/status res)))
              (is (= (str "bytes 10-" (dec total-len) "/" total-len) (get (:response/headers res) "Content-Range")))
              (is (= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" (String. ^bytes (:response/body res) StandardCharsets/UTF_8)))))

          (testing "Range: bytes=-5 returns suffix 5 bytes"
            (let [req {:request/method :GET
                       :request/uri {:path "/sample.txt"}
                       :request/headers {:header/range ["bytes=-5"]}}
                  res (content/serve-static-request cfg cache-atom req)]
              (is (= 206 (:response/status res)))
              (is (= "VWXYZ" (String. ^bytes (:response/body res) StandardCharsets/UTF_8)))))

          (testing "Invalid or out-of-bounds Range returns 416"
            (let [req {:request/method :GET
                       :request/uri {:path "/sample.txt"}
                       :request/headers {:header/range ["bytes=100-200"]}}
                  res (content/serve-static-request cfg cache-atom req)]
              (is (= 416 (:response/status res)))
              (is (= (str "bytes */" total-len) (get (:response/headers res) "Content-Range"))))))))))

(deftest test-directory-listing-and-indexes
  (with-temp-content-dir
    (fn [^File root]
      (let [root-str (.getAbsolutePath root)
            sub (io/file root "docs")]
        (.mkdirs sub)
        (spit (io/file sub "file1.txt") "Content 1")
        (spit (io/file sub "file2.txt") "Content 2")

        (testing "Directory listing generates Markdown list when index is absent"
          (let [cfg {:http {:content-root root-str :directory-listing? true}}
                cache-atom (atom (content/init-content-cache))
                req {:request/method :GET :request/uri {:path "/docs"} :request/headers {}}
                res (content/serve-static-request cfg cache-atom req)
                body-str (String. ^bytes (:response/body res) StandardCharsets/UTF_8)]
            (is (= 200 (:response/status res)))
            (is (= "text/markdown; charset=utf-8" (get (:response/headers res) "Content-Type")))
            (is (.contains body-str "# Index of /docs"))
            (is (.contains body-str "file1.txt"))
            (is (.contains body-str "file2.txt"))))

        (testing "Directory listing disabled returns 403"
          (let [cfg {:http {:content-root root-str :directory-listing? false}}
                cache-atom (atom (content/init-content-cache))
                req {:request/method :GET :request/uri {:path "/docs"} :request/headers {}}
                res (content/serve-static-request cfg cache-atom req)]
            (is (= 403 (:response/status res)))))

        (testing "Prefers index.md when present"
          (spit (io/file sub "index.md") "# Welcome to Docs")
          (let [cfg {:http {:content-root root-str :directory-listing? true}}
                cache-atom (atom (content/init-content-cache))
                req {:request/method :GET :request/uri {:path "/docs"} :request/headers {}}
                res (content/serve-static-request cfg cache-atom req)
                body-str (String. ^bytes (:response/body res) StandardCharsets/UTF_8)]
            (is (= 200 (:response/status res)))
            (is (= "text/markdown; charset=utf-8" (get (:response/headers res) "Content-Type")))
            (is (.contains body-str "# Welcome to Docs"))))))))

(defspec prop-lru-cache-eviction-invariants 100
  (prop/for-all [file-sizes (gen/vector (gen/choose 10 200) 1 50)]
                (let [max-bytes 500
                      cache (atom (content/init-content-cache {:max-bytes max-bytes}))]
                  (doseq [[idx sz] (map-indexed vector file-sizes)
                          :let [path (str "/file-" idx ".txt")
                                raw-bytes (byte-array sz (byte 65))
                                entry {:tier 1
                                       :raw-bytes raw-bytes
                                       :cached-bytes sz}]]
                    (swap! cache (fn [c]
                                   (#'content/cache-put c path entry))))
                  (let [st @cache]
        ;; Cache capacity invariant:
        ;; Either cache has 1 item that is larger than max-bytes, or current-bytes <= max-bytes
                    (if (> (count (:order st)) 1)
                      (<= (:current-bytes st) max-bytes)
                      true)))))
