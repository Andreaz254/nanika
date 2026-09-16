package com.example.tunnel.engine;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Userspace "tun2socks": reads raw IPv4 packets coming out of the TUN device, terminates TCP
 * locally and relays each TCP connection over an {@link UpstreamStream}; answers DNS (UDP/53) by
 * forwarding queries over a TCP stream. Everything else (other UDP, ICMP, IPv6) is dropped.
 *
 * Usage: call {@link #start()}, feed every packet read from the TUN to {@link #onPacket},
 * call {@link #shutdown()} when done. onPacket must be called from a single thread.
 */
public final class PacketEngine {
    public interface Logger { void log(String msg); }

    public static final class Config {
        public int mtu = 1500;
        /** Upstream resolver the DNS queries are sent to (through the tunnel, over TCP/53). */
        public String dnsUpstream = "8.8.8.8";
        /** Answer AAAA queries with an empty answer so apps stay on IPv4 (IPv6 is not tunnelled). */
        public boolean suppressAaaa = true;
        public int maxFlows = 2048;
    }

    private final PacketSink sink;
    private final UpstreamConnector connector;
    private final Config cfg;
    private final Logger logger;
    private final ConcurrentHashMap<FlowKey, TcpFlow> flows = new ConcurrentHashMap<FlowKey, TcpFlow>();
    private final DnsTunnel dns;
    private final Object sinkLock = new Object();
    private ScheduledExecutorService timer;
    private volatile boolean running;
    private long droppedUdp, droppedOther, sinkErrors;

    public PacketEngine(PacketSink sink, UpstreamConnector connector, Config cfg, Logger logger) {
        this.sink = sink;
        this.connector = connector;
        this.cfg = cfg;
        this.logger = logger;
        this.dns = new DnsTunnel(this, connector, cfg.dnsUpstream, cfg.suppressAaaa);
    }

    public void start() {
        running = true;
        timer = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "engine-timer");
                t.setDaemon(true);
                return t;
            }
        });
        timer.scheduleWithFixedDelay(new Runnable() {
            @Override public void run() {
                try {
                    long t = System.nanoTime() / 1000000L;
                    for (TcpFlow f : flows.values()) f.tick(t);
                    dns.tick(t);
                } catch (Throwable e) {
                    log("timer error: " + e);
                }
            }
        }, 100, 100, TimeUnit.MILLISECONDS);
    }

    public void shutdown() {
        running = false;
        if (timer != null) timer.shutdownNow();
        for (TcpFlow f : flows.values()) f.abort(false);
        flows.clear();
        dns.shutdown();
    }

    public int activeFlows() { return flows.size(); }

    /** Debug: one line per live TCP flow. */
    public String dump() {
        StringBuilder sb = new StringBuilder();
        for (TcpFlow f : flows.values()) sb.append(f).append('\n');
        return sb.toString();
    }

    // ------------------------------------------------------------------ accessors for flows

    int mtu() { return cfg.mtu; }
    UpstreamConnector connector() { return connector; }

    void log(String m) { if (logger != null) logger.log(m); }

    void send(byte[] pkt) {
        if (!running) return;
        synchronized (sinkLock) {
            try {
                sink.write(pkt, 0, pkt.length);
            } catch (IOException e) {
                if (sinkErrors++ < 5) log("TUN write failed: " + e.getMessage());
            }
        }
    }

    void sendUdp(int srcIp, int srcPort, int dstIp, int dstPort, byte[] payload) {
        send(Packets.udp(srcIp, dstIp, srcPort, dstPort, payload, 0, payload.length));
    }

    void remove(TcpFlow f) { flows.remove(f.key, f); }

    void schedule(Runnable r, long delayMs) {
        ScheduledExecutorService t = timer;
        if (t == null || !running) return;
        try {
            t.schedule(r, delayMs, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException ignored) {
            // shutting down
        }
    }

    // ------------------------------------------------------------------ packet input

    public void onPacket(byte[] p, int len) {
        try {
            handle(p, len);
        } catch (RuntimeException e) {
            log("packet error: " + e);
        }
    }

    private void handle(byte[] p, int len) {
        if (len < 20 || (p[0] >> 4) != 4) {                 // IPv6 and junk are dropped
            droppedOther++;
            return;
        }
        int ihl = (p[0] & 0x0F) * 4;
        int total = Math.min(Ip.u16(p, 2), len);
        if (ihl < 20 || total < ihl) return;
        if ((Ip.u16(p, 6) & 0x3FFF) != 0) return;           // fragments are not supported
        int proto = p[9] & 0xFF;
        int src = Ip.i32(p, 12), dst = Ip.i32(p, 16);
        if (proto == 6) tcp(p, ihl, total, src, dst);
        else if (proto == 17) udp(p, ihl, total, src, dst);
        else droppedOther++;
    }

    private void tcp(byte[] p, int ihl, int total, int src, int dst) {
        if (total < ihl + 20) return;
        int sport = Ip.u16(p, ihl), dport = Ip.u16(p, ihl + 2);
        int seq = Ip.i32(p, ihl + 4), ack = Ip.i32(p, ihl + 8);
        int dataOff = ((p[ihl + 12] & 0xF0) >> 4) * 4;
        int flags = p[ihl + 13] & 0x3F;
        int wnd = Ip.u16(p, ihl + 14);
        if (dataOff < 20 || ihl + dataOff > total) return;
        int payOff = ihl + dataOff, payLen = total - payOff;

        FlowKey key = new FlowKey(src, sport, dst, dport);
        TcpFlow flow = flows.get(key);
        boolean syn = (flags & TcpFlow.SYN) != 0 && (flags & TcpFlow.ACK) == 0;

        if (flow != null && syn && (flow.isClosed() || flow.clientIsn() != seq)) {
            flow.abort(false);                               // port reused by a new connection
            flows.remove(key, flow);
            flow = null;
        }
        if (flow == null) {
            if (syn) {
                if (flows.size() >= cfg.maxFlows) {
                    log("too many flows, refusing " + key);
                    replyRst(src, dst, sport, dport, seq, ack, flags, payLen);
                    return;
                }
                int mss = 0;
                for (int o = ihl + 20; o + 1 < ihl + dataOff; ) {   // parse TCP options for MSS
                    int kind = p[o] & 0xFF;
                    if (kind == 0) break;
                    if (kind == 1) { o++; continue; }
                    int l = p[o + 1] & 0xFF;
                    if (l < 2) break;
                    if (kind == 2 && l == 4 && o + 3 < ihl + dataOff) mss = Ip.u16(p, o + 2);
                    o += l;
                }
                TcpFlow nf = new TcpFlow(this, key);
                flows.put(key, nf);
                nf.start(seq, wnd, mss);
            } else {
                replyRst(src, dst, sport, dport, seq, ack, flags, payLen);
            }
            return;
        }
        flow.onSegment(seq, ack, flags, wnd, p, payOff, payLen);
    }

    /** RFC 793 reset for a segment that belongs to no connection. */
    private void replyRst(int src, int dst, int sport, int dport, int seq, int ack, int flags, int payLen) {
        if ((flags & TcpFlow.RST) != 0) return;
        if ((flags & TcpFlow.ACK) != 0) {
            send(Packets.tcp(dst, src, dport, sport, ack, 0, TcpFlow.RST, 0, 0, null, 0, 0));
        } else {
            int a = seq + payLen + ((flags & TcpFlow.SYN) != 0 ? 1 : 0) + ((flags & TcpFlow.FIN) != 0 ? 1 : 0);
            send(Packets.tcp(dst, src, dport, sport, 0, a, TcpFlow.RST | TcpFlow.ACK, 0, 0, null, 0, 0));
        }
    }

    private void udp(byte[] p, int ihl, int total, int src, int dst) {
        if (total < ihl + 8) return;
        int sport = Ip.u16(p, ihl), dport = Ip.u16(p, ihl + 2);
        int ulen = Ip.u16(p, ihl + 4);
        int payLen = Math.min(ulen, total - ihl) - 8;
        if (payLen < 0) return;
        if (dport == 53) {
            dns.query(src, sport, dst, p, ihl + 8, payLen);
        } else {
            if (droppedUdp++ == 0) log("non-DNS UDP is not tunnelled (dropped), e.g. to " + Ip.str(dst) + ":" + dport);
        }
    }
}
