(ns web.http.content
  "Static content delivery engine: safe path resolution, path traversal guards,
   two-tier LRU RAM cache and zero-copy disk streaming, ETag (304), HTTP Range (206),
   and pre-computed gzip compression."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io ByteArrayOutputStream File]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.security MessageDigest]
           [java.util Arrays]
           [java.util.zip GZIPOutputStream]))

;; ---------------------------------------------------------------------------
;; Content-Type & Compression Utilities
;; ---------------------------------------------------------------------------

(defn content-type-for-path
  "Determines Content-Type header value based on file extension."
  [path-str]
  (let [lower (str/lower-case (or path-str ""))]
    (cond
      (or (str/ends-with? lower ".tar.gz")
          (str/ends-with? lower ".tgz")) "application/gzip"
      (str/ends-with? lower ".md") "text/markdown; charset=utf-8"
      (or (str/ends-with? lower ".clj")
          (str/ends-with? lower ".cljc")
          (str/ends-with? lower ".cljs")
          (str/ends-with? lower ".edn")
          (str/ends-with? lower ".txt")
          (str/ends-with? lower ".sha1")
          (str/ends-with? lower ".sha256")) "text/plain; charset=utf-8"
      (str/ends-with? lower ".sh") "text/x-shellscript; charset=utf-8"
      (or (str/ends-with? lower ".html")
          (str/ends-with? lower ".htm")) "text/html; charset=utf-8"
      (str/ends-with? lower ".css") "text/css; charset=utf-8"
      (str/ends-with? lower ".json") "application/json; charset=utf-8"
      (or (str/ends-with? lower ".xml")
          (str/ends-with? lower ".pom")) "application/xml; charset=utf-8"
      (str/ends-with? lower ".jar") "application/java-archive"
      :else "application/octet-stream")))

(defn compressible-content-type?
  "Returns true if the MIME type benefits from Gzip compression."
  [ct]
  (let [ct-lower (str/lower-case (or ct ""))]
    (or (str/starts-with? ct-lower "text/")
        (str/includes? ct-lower "json")
        (str/includes? ct-lower "xml")
        (str/includes? ct-lower "markdown"))))

(defn- sha256-hex [^bytes bs]
  (let [md (MessageDigest/getInstance "SHA-256")
        digest (.digest md bs)]
    (apply str (map #(format "%02x" (bit-and % 0xFF)) digest))))

(defn- sha256-file [^File file]
  (let [md (MessageDigest/getInstance "SHA-256")
        buf (byte-array 65536)]
    (with-open [is (io/input-stream file)]
      (loop []
        (let [n (.read is buf)]
          (when (pos? n)
            (.update md buf 0 n)
            (recur)))))
    (apply str (map #(format "%02x" (bit-and % 0xFF)) (.digest md)))))

(defn- gzip-bytes [^bytes bs]
  (let [baos (ByteArrayOutputStream.)]
    (with-open [gz (GZIPOutputStream. baos)]
      (.write gz bs 0 (alength bs)))
    (.toByteArray baos)))

;; ---------------------------------------------------------------------------
;; Safe Path Resolution
;; ---------------------------------------------------------------------------

(defn resolve-safe-path
  "Safely resolves req-path against content-root, guarding against path traversal,
   null bytes, and hidden files/directories.
   Returns {:status :ok :file File :relative-path String}
           or {:status :forbidden} or {:status :not-found}."
  [content-root req-path]
  (try
    (let [raw-path (or req-path "/")]
      (if (str/includes? raw-path "\u0000")
        {:status :forbidden}
        (let [decoded (try
                        (java.net.URLDecoder/decode raw-path StandardCharsets/UTF_8)
                        (catch Exception _ nil))]
          (if (or (nil? decoded) (str/includes? decoded "\u0000"))
            {:status :forbidden}
            (let [clean-path (first (str/split decoded #"\?"))
                  segments (remove str/blank? (str/split clean-path #"[/\\]"))]
              (if (some (fn [seg]
                          (or (= seg "..")
                              (and (str/starts-with? seg ".")
                                   (not= seg "."))))
                        segments)
                {:status :forbidden}
                (let [root-file (io/file content-root)]
                  (if-not (.exists root-file)
                    {:status :not-found}
                    (let [root-path (.toRealPath (.toPath root-file) (into-array java.nio.file.LinkOption []))
                          rel-subpath (str/join java.io.File/separator segments)
                          candidate-path (.normalize (.resolve root-path rel-subpath))]
                      (if-not (.startsWith candidate-path root-path)
                        {:status :forbidden}
                        (let [cand-file (.toFile candidate-path)]
                          (if-not (.exists cand-file)
                            {:status :not-found}
                            (let [real-path (.toRealPath candidate-path (into-array java.nio.file.LinkOption []))]
                              (if-not (.startsWith real-path root-path)
                                {:status :forbidden}
                                {:status :ok
                                 :file (.toFile real-path)
                                 :relative-path (str (.relativize root-path real-path))}))))))))))))))
    (catch Exception _
      {:status :not-found})))

;; ---------------------------------------------------------------------------
;; Content Cache & LRU Eviction
;; ---------------------------------------------------------------------------

(defn init-content-cache
  "Initializes the content cache map.
   Options:
     :max-bytes (default 128 MB)
     :max-file-bytes (default 2 MB)"
  ([] (init-content-cache {}))
  ([opts]
   {:entries {}
    :order []
    :current-bytes 0
    :max-bytes (long (or (:max-bytes opts) 134217728))
    :max-file-bytes (long (or (:max-file-bytes opts) 2097152))}))

(defn- cache-get [cache canonical-path mtime size]
  (when-let [entry (get-in cache [:entries canonical-path])]
    (when (and (= (:mtime entry) mtime)
               (= (:size entry) size))
      entry)))

(defn- cache-touch [cache canonical-path]
  (let [order (vec (remove #(= % canonical-path) (:order cache)))]
    (assoc cache :order (conj order canonical-path))))

(defn- cache-put [cache canonical-path entry]
  (let [entry-bytes (or (:cached-bytes entry) 0)
        old-entry (get-in cache [:entries canonical-path])
        old-bytes (or (:cached-bytes old-entry) 0)
        order (vec (remove #(= % canonical-path) (:order cache)))
        new-current (+ (- (:current-bytes cache) old-bytes) entry-bytes)
        c (assoc cache
                 :entries (assoc (:entries cache) canonical-path entry)
                 :order (conj order canonical-path)
                 :current-bytes new-current)]
    (loop [cur c]
      (if (and (> (:current-bytes cur) (:max-bytes cur))
               (> (count (:order cur)) 1))
        (let [oldest (first (:order cur))
              evict-entry (get-in cur [:entries oldest])
              evict-bytes (or (:cached-bytes evict-entry) 0)
              next-c (assoc cur
                            :entries (dissoc (:entries cur) oldest)
                            :order (vec (rest (:order cur)))
                            :current-bytes (max 0 (- (:current-bytes cur) evict-bytes)))]
          (recur next-c))
        cur))))

;; ---------------------------------------------------------------------------
;; Static Request Handler
;; ---------------------------------------------------------------------------

(defn- parse-byte-range [range-header total-size]
  (when (and range-header (str/starts-with? range-header "bytes="))
    (let [spec (subs range-header 6)]
      (cond
        ;; bytes=start-end
        (re-matches #"^(\d+)-(\d+)$" spec)
        (let [[_ s e] (re-matches #"^(\d+)-(\d+)$" spec)
              start (Long/parseLong s)
              end (Long/parseLong e)]
          (when (and (<= start end) (< start total-size))
            [start (min end (dec total-size))]))

        ;; bytes=start-
        (re-matches #"^(\d+)-$" spec)
        (let [[_ s] (re-matches #"^(\d+)-$" spec)
              start (Long/parseLong s)]
          (when (< start total-size)
            [start (dec total-size)]))

        ;; bytes=-suffix
        (re-matches #"^-(\d+)$" spec)
        (let [[_ suf] (re-matches #"^-(\d+)$" spec)
              suffix-len (Long/parseLong suf)]
          (when (pos? suffix-len)
            (let [start (max 0 (- total-size suffix-len))]
              [start (dec total-size)])))))))

(defn serve-static-request
  "Processes a static GET or HEAD request using content cache and zero-copy streaming.
   Supports ETag/304, Range/206, Gzip compression, and Markdown directory listings."
  [config cache-atom request]
  (let [method (:request/method request)]
    (if-not (or (= method :GET) (= method :HEAD))
      {:response/status 405
       :response/headers {"Allow" "GET, HEAD"
                          "Content-Type" "text/plain; charset=utf-8"}
       :response/body "Method Not Allowed\n"}

      (let [content-root (get-in config [:http :content-root] "/var/www/clj-web/public")
            resolved (resolve-safe-path content-root (get-in request [:request/uri :path]))]
        (case (:status resolved)
          :forbidden
          {:response/status 403
           :response/headers {"Content-Type" "text/plain; charset=utf-8"}
           :response/body "Forbidden\n"}

          :not-found
          {:response/status 404
           :response/headers {"Content-Type" "text/plain; charset=utf-8"}
           :response/body "Not Found\n"}

          :ok
          (let [^File file (:file resolved)]
            (if (.isDirectory file)
              ;; Directory: check for index.md or index.html or generate listing
              (let [idx-md (io/file file "index.md")
                    idx-html (io/file file "index.html")]
                (cond
                  (.exists idx-md)
                  (serve-static-request config cache-atom
                                        (assoc-in request [:request/uri :path]
                                                  (str (str/replace-first (get-in request [:request/uri :path]) #"/$" "") "/index.md")))

                  (.exists idx-html)
                  (serve-static-request config cache-atom
                                        (assoc-in request [:request/uri :path]
                                                  (str (str/replace-first (get-in request [:request/uri :path]) #"/$" "") "/index.html")))

                  (get-in config [:http :directory-listing?] true)
                  (let [rel-path (:relative-path resolved)
                        entries (.listFiles file)
                        sorted-entries (sort-by (fn [^File f] [(if (.isDirectory f) 0 1) (.getName f)]) (or entries []))
                        lines (concat
                               [(str "# Index of /" rel-path "\n")]
                               (when (and rel-path (not (str/blank? rel-path)))
                                 ["- [../](../)"])
                               (for [^File f sorted-entries
                                     :let [name (.getName f)
                                           is-dir? (.isDirectory f)
                                           display-name (if is-dir? (str name "/") name)
                                           href (if is-dir? (str name "/") name)]]
                                 (if is-dir?
                                   (str "- [" display-name "](" href ")")
                                   (str "- [" display-name "](" href ") (" (.length f) " bytes)"))))
                        body-str (str/join "\n" lines)
                        body-bytes (.getBytes ^String body-str StandardCharsets/UTF_8)
                        etag (str "\"" (sha256-hex body-bytes) "\"")
                        headers {"Content-Type" "text/markdown; charset=utf-8"
                                 "ETag" etag
                                 "Content-Length" (str (alength body-bytes))
                                 "Cache-Control" "public, max-age=60"}]
                    (if (= method :HEAD)
                      {:response/status 200 :response/headers headers :response/body nil}
                      {:response/status 200 :response/headers headers :response/body body-bytes}))

                  :else
                  {:response/status 403
                   :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                   :response/body "Directory listing disabled\n"}))

              ;; Regular file
              (let [canonical-path (.getCanonicalPath file)
                    mtime (.lastModified file)
                    file-size (.length file)
                    max-file-bytes (or (:max-file-bytes @cache-atom)
                                       (get-in config [:http :cache-max-file-bytes] 2097152))
                    tier1? (<= file-size max-file-bytes)
                    ct (content-type-for-path (.getName file))

                    ;; Cache load or populate
                    entry (if tier1?
                            (if-let [cached (cache-get @cache-atom canonical-path mtime file-size)]
                              (do
                                (swap! cache-atom cache-touch canonical-path)
                                cached)
                              (let [raw-bytes (Files/readAllBytes (.toPath file))
                                    sha256 (sha256-hex raw-bytes)
                                    etag (str "\"" sha256 "\"")
                                    compressible? (compressible-content-type? ct)
                                    gz-bytes (when compressible? (gzip-bytes raw-bytes))
                                    cached-bytes (+ (alength raw-bytes) (if gz-bytes (alength gz-bytes) 0))
                                    new-entry {:tier 1
                                               :raw-bytes raw-bytes
                                               :gzip-bytes gz-bytes
                                               :etag etag
                                               :sha256 sha256
                                               :mtime mtime
                                               :size file-size
                                               :content-type ct
                                               :cached-bytes cached-bytes}]
                                (swap! cache-atom cache-put canonical-path new-entry)
                                new-entry))
                            ;; Tier 2: streaming metadata only
                            (if-let [cached (cache-get @cache-atom canonical-path mtime file-size)]
                              (do
                                (swap! cache-atom cache-touch canonical-path)
                                cached)
                              (let [sha256 (sha256-file file)
                                    etag (str "\"" sha256 "\"")
                                    new-entry {:tier 2
                                               :file file
                                               :etag etag
                                               :sha256 sha256
                                               :mtime mtime
                                               :size file-size
                                               :content-type ct
                                               :cached-bytes 0}]
                                (swap! cache-atom cache-put canonical-path new-entry)
                                new-entry)))

                    etag (:etag entry)
                    inm-header (first (get (:request/headers request) :header/if-none-match))
                    range-header (first (get (:request/headers request) :header/range))]

                ;; 1. Conditional check: If-None-Match
                (if (and inm-header (= (str/trim inm-header) etag))
                  {:response/status 304
                   :response/headers {"ETag" etag
                                      "Cache-Control" "public, max-age=3600"}
                   :response/body nil}

                  ;; 2. HTTP Range request
                  (if range-header
                    (if-let [[start end] (parse-byte-range range-header file-size)]
                      (let [part-len (inc (- end start))
                            headers {"Content-Type" ct
                                     "Content-Range" (str "bytes " start "-" end "/" file-size)
                                     "Accept-Ranges" "bytes"
                                     "Content-Length" (str part-len)
                                     "ETag" etag
                                     "X-Checksum-SHA256" (:sha256 entry)}
                            body (cond
                                   (= method :HEAD) nil
                                   tier1? (Arrays/copyOfRange ^bytes (:raw-bytes entry) (int start) (int (inc end)))
                                   :else {:file file :offset start :length part-len})]
                        {:response/status 206
                         :response/headers headers
                         :response/body body})
                      {:response/status 416
                       :response/headers {"Content-Range" (str "bytes */" file-size)}
                       :response/body nil})

                    ;; 3. Full 200 OK response (with Gzip negotiation)
                    (let [base-headers {"Content-Type" ct
                                        "Accept-Ranges" "bytes"
                                        "ETag" etag
                                        "X-Checksum-SHA256" (:sha256 entry)}
                          ae-header (first (get (:request/headers request) :header/accept-encoding))
                          gzip-accepted? (and ae-header (str/includes? (str/lower-case ae-header) "gzip"))
                          gz-bytes (:gzip-bytes entry)
                          serve-gzip? (and tier1?
                                           gzip-accepted?
                                           gz-bytes
                                           (< (alength ^bytes gz-bytes) file-size))]
                      (if serve-gzip?
                        (let [headers (assoc base-headers
                                             "Content-Encoding" "gzip"
                                             "Vary" "Accept-Encoding"
                                             "Content-Length" (str (alength ^bytes gz-bytes)))]
                          {:response/status 200
                           :response/headers headers
                           :response/body (if (= method :HEAD) nil gz-bytes)})
                        (let [headers (assoc base-headers
                                             "Content-Length" (str file-size))
                              body (cond
                                     (= method :HEAD) nil
                                     tier1? (:raw-bytes entry)
                                     :else {:file file :offset 0 :length file-size})]
                          {:response/status 200
                           :response/headers headers
                           :response/body body})))))))))))))
