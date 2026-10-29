(ns web.dns.server
  "Thin Java NIO UDP and Virtual-Thread TCP DNS server on port 53.
   Applies per-subnet RRL rate limiting on UDP, executes pure authoritative
   queries via web.dns.resolver, and supports RFC 1035 TCP fallback."
  (:require [web.dns.codec :as codec]
            [web.dns.resolver :as resolver]
            [web.http.ratelimit :as rl])
  (:import [java.io BufferedInputStream BufferedOutputStream DataInputStream DataOutputStream]
           [java.net InetSocketAddress ServerSocket SocketException StandardSocketOptions]
           [java.nio ByteBuffer]
           [java.nio.channels AsynchronousCloseException ClosedByInterruptException ClosedChannelException DatagramChannel]
           [java.util.concurrent Executors]
           [java.util.concurrent.atomic AtomicBoolean]))

(defn start-dns-server!
  "Starts UDP and TCP DNS listeners using config and cluster-state-atom.
   Returns server map containing channel, socket, ports, and stop-fn."
  [config cluster-state-atom]
  (let [bind-host (get-in config [:dns :bind-ip] "0.0.0.0")
        bind-port (int (get-in config [:dns :port] 53))
        running? (AtomicBoolean. true)
        limiter-atom (atom (rl/init-limiter {:capacity 40.0 :refill-per-sec 20.0}))

        ;; 1. UDP DatagramChannel
        udp-channel (DatagramChannel/open)
        _ (.setOption udp-channel StandardSocketOptions/SO_REUSEADDR true)
        _ (.bind udp-channel (InetSocketAddress. ^String bind-host bind-port))
        bound-udp-port (.getPort ^InetSocketAddress (.getLocalAddress udp-channel))

        ;; 2. TCP ServerSocket
        tcp-socket (ServerSocket.)
        _ (.setReuseAddress tcp-socket true)
        _ (if (zero? bind-port)
            (try
              (.bind tcp-socket (InetSocketAddress. ^String bind-host bound-udp-port))
              (catch Exception _
                (.bind tcp-socket (InetSocketAddress. ^String bind-host 0))))
            (.bind tcp-socket (InetSocketAddress. ^String bind-host bind-port)))
        bound-tcp-port (.getLocalPort tcp-socket)
        tcp-executor (Executors/newVirtualThreadPerTaskExecutor)

        ;; UDP worker loop
        udp-thread
        (-> (Thread/ofVirtual)
            (.name "clj-web-dns-udp")
            (.start
             (fn []
               (let [buf (ByteBuffer/allocate 4096)]
                 (while (.get running?)
                   (try
                     (.clear buf)
                     (when-let [client-addr (.receive udp-channel buf)]
                       (let [len (.position buf)]
                         (.flip buf)
                         (let [req-bytes (byte-array len)]
                           (.get buf req-bytes)
                           (let [client-ip (if (instance? InetSocketAddress client-addr)
                                             (.getHostAddress (.getAddress ^InetSocketAddress client-addr))
                                             (str client-addr))
                                 subnet-key (rl/ip->subnet-key client-ip)
                                 now-ms (System/currentTimeMillis)
                                 allowed? (atom true)]
                             (swap! limiter-atom
                                    (fn [st]
                                      (let [res (rl/check-and-consume st subnet-key 1.0 now-ms)]
                                        (reset! allowed? (:allowed? res))
                                        (:state res))))
                             (when @allowed?
                               (try
                                 (let [query-pkt (codec/decode-packet req-bytes)
                                       cluster-st (if (instance? clojure.lang.IDeref cluster-state-atom)
                                                    @cluster-state-atom
                                                    cluster-state-atom)
                                       resp-pkt (resolver/resolve-query config cluster-st query-pkt)
                                       resp-bytes (codec/encode-packet resp-pkt {:max-bytes 512})]
                                   (.send udp-channel (ByteBuffer/wrap resp-bytes) client-addr))
                                 (catch Exception e
                                   (when-let [id (:id (ex-data e))]
                                     (try
                                       (let [err-resp (codec/encode-packet {:id id
                                                                            :qr? true
                                                                            :opcode 0
                                                                            :aa? false
                                                                            :tc? false
                                                                            :rd? false
                                                                            :ra? false
                                                                            :rcode :formerr
                                                                            :questions []})]
                                         (.send udp-channel (ByteBuffer/wrap err-resp) client-addr))
                                       (catch Exception _ nil))))))))))
                     (catch ClosedChannelException _ (.set running? false))
                     (catch ClosedByInterruptException _ (.set running? false))
                     (catch AsynchronousCloseException _ (.set running? false))
                     (catch SocketException _ (.set running? false))
                     (catch Exception _ nil)))))))

        ;; TCP accept loop
        tcp-thread
        (-> (Thread/ofVirtual)
            (.name "clj-web-dns-tcp-accept")
            (.start
             (fn []
               (while (.get running?)
                 (try
                   (let [client (.accept tcp-socket)]
                     (.submit tcp-executor
                              ^Runnable
                              (fn []
                                (try
                                  (.setSoTimeout client 5000)
                                  (with-open [in (DataInputStream. (BufferedInputStream. (.getInputStream client)))
                                              out (DataOutputStream. (BufferedOutputStream. (.getOutputStream client)))]
                                    (let [len (.readUnsignedShort in)
                                          buf (byte-array len)]
                                      (.readFully in buf)
                                      (let [query-pkt (codec/decode-packet buf)
                                            cluster-st (if (instance? clojure.lang.IDeref cluster-state-atom)
                                                         @cluster-state-atom
                                                         cluster-state-atom)
                                            resp-pkt (resolver/resolve-query config cluster-st query-pkt)
                                            resp-bytes (codec/encode-packet resp-pkt {:max-bytes 65535})]
                                        (.writeShort out (alength resp-bytes))
                                        (.write out resp-bytes 0 (alength resp-bytes))
                                        (.flush out))))
                                  (catch Exception _ nil)
                                  (finally
                                    (try (.close client) (catch Exception _ nil)))))))
                   (catch SocketException _ (.set running? false))
                   (catch Exception _ nil))))))

        stop-fn (fn []
                  (.set running? false)
                  (try (.close udp-channel) (catch Exception _ nil))
                  (try (.close tcp-socket) (catch Exception _ nil))
                  (try (.shutdownNow tcp-executor) (catch Exception _ nil)))]

    {:udp-channel udp-channel
     :udp-port bound-udp-port
     :tcp-socket tcp-socket
     :tcp-port bound-tcp-port
     :tcp-executor tcp-executor
     :udp-thread udp-thread
     :tcp-thread tcp-thread
     :limiter-atom limiter-atom
     :running? running?
     :stop-fn stop-fn}))

(defn stop-dns-server!
  "Stops the DNS server and cleanly closes all sockets and threads."
  [server]
  (when-let [stop-fn (:stop-fn server)]
    (stop-fn))
  server)
