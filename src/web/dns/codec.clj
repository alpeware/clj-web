(ns web.dns.codec
  "Pure Clojure RFC 1035 binary packet parser and serializer for DNS wire format.
   Supports standard query/response header flags, label decompression, 0x20 bit
   case preservation, A, AAAA, NS, CNAME, SOA, MX, TXT, CAA record types,
   and UDP truncation (TC=1)."
  (:require [clojure.string :as str])
  (:import [java.io ByteArrayOutputStream DataOutputStream]
           [java.net Inet6Address InetAddress]
           [java.nio.charset StandardCharsets]))

;; ---------------------------------------------------------------------------
;; Constants and Mappings
;; ---------------------------------------------------------------------------

(def type->int
  {:A 1
   :NS 2
   :CNAME 5
   :SOA 6
   :MX 15
   :TXT 16
   :AAAA 28
   :OPT 41
   :ANY 255
   :CAA 257})

(def int->type
  (into {} (map (fn [[k v]] [v k]) type->int)))

(def class->int
  {:IN 1
   :ANY 255})

(def int->class
  (into {} (map (fn [[k v]] [v k]) class->int)))

(def rcode->int
  {:noerror 0
   :formerr 1
   :servfail 2
   :nxdomain 3
   :notimp 4
   :refused 5})

(def int->rcode
  (into {} (map (fn [[k v]] [v k]) rcode->int)))

(defn to-type-int [t]
  (if (integer? t) t (get type->int t 0)))

(defn to-class-int [c]
  (if (integer? c) c (get class->int c 1)))

(defn to-rcode-int [r]
  (if (integer? r) r (get rcode->int r 0)))

;; ---------------------------------------------------------------------------
;; Domain Name Decoder (with loop detection and 0x20 case preservation)
;; ---------------------------------------------------------------------------

(defn- read-ushort [^bytes buf ^long offset]
  (bit-or (bit-shift-left (bit-and (aget buf offset) 0xFF) 8)
          (bit-and (aget buf (inc offset)) 0xFF)))

(defn- read-uint [^bytes buf ^long offset]
  (let [b0 (bit-and (aget buf offset) 0xFF)
        b1 (bit-and (aget buf (+ offset 1)) 0xFF)
        b2 (bit-and (aget buf (+ offset 2)) 0xFF)
        b3 (bit-and (aget buf (+ offset 3)) 0xFF)
        raw (bit-or (bit-shift-left b0 24)
                    (bit-shift-left b1 16)
                    (bit-shift-left b2 8)
                    b3)]
    (Integer/toUnsignedLong (int raw))))

(defn- read-domain-name
  "Reads a domain name from buf starting at start-offset.
   Returns [domain-string next-offset-after-name]."
  [^bytes buf ^long start-offset]
  (let [len (alength buf)]
    (loop [offset start-offset
           labels []
           next-offset nil
           visited #{}
           hops 0]
      (when (or (< offset 0) (>= offset len) (> hops 16))
        (throw (ex-info "Malformed DNS domain name or pointer loop" {:type :dns/formerr :offset offset})))
      (let [b (bit-and (aget buf offset) 0xFF)]
        (cond
          (zero? b)
          [(str/join "." labels) (or next-offset (inc offset))]

          (= (bit-and b 0xC0) 0xC0)
          (do
            (when (>= (inc offset) len)
              (throw (ex-info "Malformed DNS pointer" {:type :dns/formerr :offset offset})))
            (let [ptr (bit-or (bit-shift-left (bit-and b 0x3F) 8)
                              (bit-and (aget buf (inc offset)) 0xFF))]
              (when (or (visited ptr) (< ptr 0) (>= ptr len))
                (throw (ex-info "Invalid DNS pointer loop or out of bounds" {:type :dns/formerr :ptr ptr})))
              (recur ptr
                     labels
                     (or next-offset (+ offset 2))
                     (conj visited ptr)
                     (inc hops))))

          :else
          (let [label-len b
                label-end (+ offset 1 label-len)]
            (when (> label-end len)
              (throw (ex-info "DNS label length exceeds packet boundary" {:type :dns/formerr})))
            (let [label-str (String. buf (inc offset) label-len StandardCharsets/US_ASCII)]
              (recur label-end
                     (conj labels label-str)
                     next-offset
                     visited
                     hops))))))))

;; ---------------------------------------------------------------------------
;; RDATA Decoder
;; ---------------------------------------------------------------------------

(defn- decode-rdata
  [^bytes buf ^long rdata-start ^long rdlength type-kw]
  (let [rdata-end (+ rdata-start rdlength)]
    (case type-kw
      :A
      (if (= rdlength 4)
        (str (bit-and (aget buf rdata-start) 0xFF) "."
             (bit-and (aget buf (+ rdata-start 1)) 0xFF) "."
             (bit-and (aget buf (+ rdata-start 2)) 0xFF) "."
             (bit-and (aget buf (+ rdata-start 3)) 0xFF))
        (throw (ex-info "Invalid A record length" {:type :dns/formerr})))

      :AAAA
      (if (= rdlength 16)
        (let [addr (byte-array 16)]
          (System/arraycopy buf rdata-start addr 0 16)
          (.getHostAddress (Inet6Address/getByAddress addr)))
        (throw (ex-info "Invalid AAAA record length" {:type :dns/formerr})))

      :NS
      (let [[ns-name _] (read-domain-name buf rdata-start)]
        ns-name)

      :CNAME
      (let [[cname _] (read-domain-name buf rdata-start)]
        cname)

      :SOA
      (let [[mname off1] (read-domain-name buf rdata-start)
            [rname off2] (read-domain-name buf off1)]
        (when (> (+ off2 20) rdata-end)
          (throw (ex-info "SOA record truncated" {:type :dns/formerr})))
        {:mname mname
         :rname rname
         :serial (read-uint buf off2)
         :refresh (read-uint buf (+ off2 4))
         :retry (read-uint buf (+ off2 8))
         :expire (read-uint buf (+ off2 12))
         :minimum (read-uint buf (+ off2 16))})

      :MX
      (do
        (when (< rdlength 3)
          (throw (ex-info "MX record too short" {:type :dns/formerr})))
        (let [pref (read-ushort buf rdata-start)
              [exchange _] (read-domain-name buf (+ rdata-start 2))]
          {:preference pref :exchange exchange}))

      :TXT
      (loop [pos rdata-start
             txt-vec []]
        (if (>= pos rdata-end)
          txt-vec
          (let [c-len (bit-and (aget buf pos) 0xFF)
                next-pos (+ pos 1 c-len)]
            (when (> next-pos rdata-end)
              (throw (ex-info "TXT chunk exceeds RDATA bounds" {:type :dns/formerr})))
            (let [chunk-str (String. buf (inc pos) c-len StandardCharsets/UTF_8)]
              (recur next-pos (conj txt-vec chunk-str))))))

      :CAA
      (do
        (when (< rdlength 2)
          (throw (ex-info "CAA record too short" {:type :dns/formerr})))
        (let [flags (bit-and (aget buf rdata-start) 0xFF)
              tag-len (bit-and (aget buf (inc rdata-start)) 0xFF)
              tag-end (+ rdata-start 2 tag-len)]
          (when (> tag-end rdata-end)
            (throw (ex-info "CAA tag exceeds RDATA length" {:type :dns/formerr})))
          (let [tag (String. buf (+ rdata-start 2) tag-len StandardCharsets/US_ASCII)
                val-len (- rdata-end tag-end)
                val (String. buf tag-end val-len StandardCharsets/UTF_8)]
            {:flags flags :tag tag :value val})))

      ;; Fallback: raw byte array
      (let [raw (byte-array rdlength)]
        (System/arraycopy buf rdata-start raw 0 rdlength)
        raw))))

;; ---------------------------------------------------------------------------
;; Packet Decoder
;; ---------------------------------------------------------------------------

(defn decode-packet
  "Decodes an RFC 1035 binary DNS packet into a Clojure map.
   Throws ex-info with {:type :dns/formerr} on malformed input."
  [^bytes buf]
  (when (or (nil? buf) (< (alength buf) 12))
    (throw (ex-info "Packet too short for DNS header (min 12 bytes)" {:type :dns/formerr})))
  (let [id (read-ushort buf 0)
        b2 (bit-and (aget buf 2) 0xFF)
        qr? (not (zero? (bit-and b2 0x80)))
        opcode (bit-shift-right (bit-and b2 0x78) 3)
        aa? (not (zero? (bit-and b2 0x04)))
        tc? (not (zero? (bit-and b2 0x02)))
        rd? (not (zero? (bit-and b2 0x01)))
        b3 (bit-and (aget buf 3) 0xFF)
        ra? (not (zero? (bit-and b3 0x80)))
        z (bit-shift-right (bit-and b3 0x70) 4)
        rcode-val (bit-and b3 0x0F)
        rcode (get int->rcode rcode-val rcode-val)
        qdcount (read-ushort buf 4)
        ancount (read-ushort buf 6)
        nscount (read-ushort buf 8)
        arcount (read-ushort buf 10)
        len (alength buf)]

    ;; Parse questions
    (loop [i 0
           offset 12
           questions []]
      (if (>= i qdcount)
        ;; Parse resource records: answers, authority, additional
        (let [parse-rrs (fn [count start-offset]
                          (loop [j 0
                                 cur-offset start-offset
                                 rrs []]
                            (if (>= j count)
                              [rrs cur-offset]
                              (let [[name next-off] (read-domain-name buf cur-offset)]
                                (when (> (+ next-off 10) len)
                                  (throw (ex-info "RR header truncated" {:type :dns/formerr})))
                                (let [t-int (read-ushort buf next-off)
                                      c-int (read-ushort buf (+ next-off 2))
                                      ttl (read-uint buf (+ next-off 4))
                                      rdlen (read-ushort buf (+ next-off 8))
                                      rd-start (+ next-off 10)
                                      rd-end (+ rd-start rdlen)]
                                  (when (> rd-end len)
                                    (throw (ex-info "RDATA truncated" {:type :dns/formerr})))
                                  (let [t-kw (get int->type t-int t-int)
                                        rdata (decode-rdata buf rd-start rdlen t-kw)]
                                    (recur (inc j)
                                           rd-end
                                           (conj rrs {:name name
                                                      :type t-kw
                                                      :class (get int->class c-int c-int)
                                                      :ttl ttl
                                                      :rdata rdata}))))))))
              [answers off-after-ans] (parse-rrs ancount offset)
              [authority off-after-ns] (parse-rrs nscount off-after-ans)
              [additional _off-final] (parse-rrs arcount off-after-ns)]
          {:id id
           :qr? qr?
           :opcode opcode
           :aa? aa?
           :tc? tc?
           :rd? rd?
           :ra? ra?
           :z z
           :rcode rcode
           :qdcount qdcount
           :ancount ancount
           :nscount nscount
           :arcount arcount
           :questions questions
           :answers answers
           :authority authority
           :additional additional})

        (let [[qname next-off] (read-domain-name buf offset)]
          (when (> (+ next-off 4) len)
            (throw (ex-info "Question truncated" {:type :dns/formerr})))
          (let [qtype-int (read-ushort buf next-off)
                qclass-int (read-ushort buf (+ next-off 2))]
            (recur (inc i)
                   (+ next-off 4)
                   (conj questions {:qname qname
                                    :qname-lower (str/lower-case qname)
                                    :qtype (get int->type qtype-int qtype-int)
                                    :qclass (get int->class qclass-int qclass-int)}))))))))

;; ---------------------------------------------------------------------------
;; Domain Name Encoder (with RFC 1035 pointer compression & 0x20 case preservation)
;; ---------------------------------------------------------------------------

(defn- write-domain-name
  "Encodes domain name into ByteArrayOutputStream with pointer compression.
   Preserves ASCII character casing of the labels."
  ([^ByteArrayOutputStream bos comp-map-atom ^String name-str]
   (write-domain-name bos comp-map-atom name-str 0))
  ([^ByteArrayOutputStream bos comp-map-atom ^String name-str base-offset]
   (let [labels (if (or (nil? name-str) (str/blank? name-str) (= name-str "."))
                  []
                  (str/split name-str #"\."))
         write-labels (fn write-labels [rem-labels]
                        (if (empty? rem-labels)
                          (.write bos 0)
                          (let [suffix (str/lower-case (str/join "." rem-labels))
                                curr-pos (+ (long base-offset) (.size bos))]
                            (if-let [offset (get @comp-map-atom suffix)]
                              (do
                                (.write bos (unchecked-byte (bit-or 0xC0 (bit-shift-right offset 8))))
                                (.write bos (unchecked-byte (bit-and offset 0xFF))))
                              (let [lbl (first rem-labels)
                                    lbl-bytes (.getBytes ^String lbl StandardCharsets/US_ASCII)]
                                (when (< curr-pos 16384)
                                  (swap! comp-map-atom assoc suffix curr-pos))
                                (.write bos (count lbl-bytes))
                                (.write bos lbl-bytes 0 (count lbl-bytes))
                                (write-labels (rest rem-labels)))))))]
     (write-labels labels))))

;; ---------------------------------------------------------------------------
;; RDATA Encoder
;; ---------------------------------------------------------------------------

(defn- encode-rdata
  [^ByteArrayOutputStream bos comp-map-atom type-kw rdata base-offset]
  (case type-kw
    :A
    (let [addr (InetAddress/getByName (str rdata))]
      (.write bos (.getAddress addr)))

    :AAAA
    (let [addr (InetAddress/getByName (str rdata))]
      (.write bos (.getAddress addr)))

    :NS
    (write-domain-name bos comp-map-atom (str rdata) base-offset)

    :CNAME
    (write-domain-name bos comp-map-atom (str rdata) base-offset)

    :SOA
    (let [{:keys [mname rname serial refresh retry expire minimum]} rdata
          dos (DataOutputStream. bos)]
      (write-domain-name bos comp-map-atom (str mname) base-offset)
      (write-domain-name bos comp-map-atom (str rname) base-offset)
      (.writeInt dos (int serial))
      (.writeInt dos (int refresh))
      (.writeInt dos (int retry))
      (.writeInt dos (int expire))
      (.writeInt dos (int minimum))
      (.flush dos))

    :MX
    (let [{:keys [preference exchange]} rdata
          dos (DataOutputStream. bos)]
      (.writeShort dos (int (or preference 0)))
      (.flush dos)
      (write-domain-name bos comp-map-atom (str exchange) base-offset))

    :TXT
    (let [chunks (cond
                   (vector? rdata) rdata
                   (coll? rdata) (vec rdata)
                   :else [(str rdata)])]
      (doseq [chunk chunks]
        (let [chunk-bytes (.getBytes ^String (str chunk) StandardCharsets/UTF_8)
              total-len (count chunk-bytes)]
          (loop [offset 0]
            (when (< offset total-len)
              (let [chunk-sz (min 255 (- total-len offset))]
                (.write bos (unchecked-byte chunk-sz))
                (.write bos chunk-bytes offset chunk-sz)
                (recur (+ offset chunk-sz))))))))

    :CAA
    (let [{:keys [flags tag value]} rdata
          tag-bytes (.getBytes ^String (str tag) StandardCharsets/US_ASCII)
          val-bytes (.getBytes ^String (str value) StandardCharsets/UTF_8)]
      (.write bos (unchecked-byte (or flags 0)))
      (.write bos (unchecked-byte (count tag-bytes)))
      (.write bos tag-bytes 0 (count tag-bytes))
      (.write bos val-bytes 0 (count val-bytes)))

    ;; Raw byte array fallback
    (when (bytes? rdata)
      (.write bos ^bytes rdata 0 (alength ^bytes rdata)))))

;; ---------------------------------------------------------------------------
;; Packet Encoder
;; ---------------------------------------------------------------------------

(defn- encode-packet-raw
  [pkt comp-map-atom]
  (let [bos (ByteArrayOutputStream.)
        dos (DataOutputStream. bos)
        id (int (or (:id pkt) 0))
        qr-bit (if (:qr? pkt) 0x80 0)
        opcode-bits (bit-shift-left (bit-and (int (or (:opcode pkt) 0)) 0x0F) 3)
        aa-bit (if (:aa? pkt) 0x04 0)
        tc-bit (if (:tc? pkt) 0x02 0)
        rd-bit (if (:rd? pkt) 0x01 0)
        b2 (bit-or qr-bit opcode-bits aa-bit tc-bit rd-bit)
        ra-bit (if (:ra? pkt) 0x80 0)
        z-bits (bit-shift-left (bit-and (int (or (:z pkt) 0)) 0x07) 4)
        rcode-bits (bit-and (to-rcode-int (or (:rcode pkt) :noerror)) 0x0F)
        b3 (bit-or ra-bit z-bits rcode-bits)
        questions (vec (or (:questions pkt) []))
        answers (vec (or (:answers pkt) []))
        authority (vec (or (:authority pkt) []))
        additional (vec (or (:additional pkt) []))]

    (.writeShort dos id)
    (.writeByte dos b2)
    (.writeByte dos b3)
    (.writeShort dos (count questions))
    (.writeShort dos (count answers))
    (.writeShort dos (count authority))
    (.writeShort dos (count additional))
    (.flush dos)

    ;; Questions
    (doseq [q questions]
      (write-domain-name bos comp-map-atom (or (:qname q) "") 0)
      (.writeShort dos (to-type-int (:qtype q)))
      (.writeShort dos (to-class-int (:qclass q)))
      (.flush dos))

    ;; Resource records helper
    (let [write-rr (fn [rr]
                     (write-domain-name bos comp-map-atom (or (:name rr) "") 0)
                     (let [t-kw (:type rr)
                           t-int (to-type-int t-kw)
                           c-int (to-class-int (:class rr))
                           ttl (long (or (:ttl rr) 60))
                           base-offset (+ (.size bos) 10)
                           rdata-bos (ByteArrayOutputStream.)]
                       (encode-rdata rdata-bos comp-map-atom t-kw (:rdata rr) base-offset)
                       (.writeShort dos t-int)
                       (.writeShort dos c-int)
                       (.writeInt dos (int ttl))
                       (.writeShort dos (.size rdata-bos))
                       (.flush dos)
                       (.write bos (.toByteArray rdata-bos))))]
      (doseq [rr answers] (write-rr rr))
      (doseq [rr authority] (write-rr rr))
      (doseq [rr additional] (write-rr rr)))

    (.toByteArray bos)))

(defn encode-packet
  "Encodes a DNS packet map into an RFC 1035 wire format byte array.
   Accepts optional options map:
     :max-bytes (default 65535, typically 512 for UDP)
   When max-bytes is specified and the response exceeds max-bytes, cleanly
   sets :tc? true (TC=1) and truncates answers/authority/additional sections."
  ([pkt] (encode-packet pkt nil))
  ([pkt opts]
   (let [max-bytes (long (or (:max-bytes opts) 65535))
         comp-map (atom {})
         raw-bytes (encode-packet-raw pkt comp-map)]
     (if (<= (alength raw-bytes) max-bytes)
       raw-bytes
       ;; Packet exceeds max-bytes (e.g. 512-byte UDP limit):
       ;; cleanly set TC=1 and truncate answer/authority/additional sections
       (let [truncated-pkt (assoc pkt
                                  :tc? true
                                  :answers []
                                  :authority []
                                  :additional [])]
         (encode-packet-raw truncated-pkt (atom {})))))))
