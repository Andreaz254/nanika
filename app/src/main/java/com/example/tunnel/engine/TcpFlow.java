package com.example.tunnel.engine;

import java.util.Random;

/**
 * One TCP connection made by an Android app. We play the role of the remote server toward
 * the phone's TCP stack, and relay the byte stream to an {@link UpstreamStream}.
 *
 * Deliberately simple TCP: no window scaling, SACK or timestamps, go-back-N retransmission.
 * That is sufficient because the "link" is the local TUN device (loss-free and in-order);
 * the retransmit logic only exists to survive the rare dropped packet.
 *
 * Every public/package method is synchronized on the flow. Upstream callbacks arrive on
 * foreign threads; the packet thread and the timer thread also call in.
 */
final class TcpFlow implements UpstreamListener {
    static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

    private static final int WIN_MAX = 65535;
    private static final int SEND_BUF_MAX = 512 * 1024;
    private static final long CONNECT_TIMEOUT_MS = 15000;
    private static final long LINGER_MS = 3000;
    private static final Random RND = new Random();

    private enum State { CONNECTING, SYN_RCVD, ESTABLISHED, CLOSED }

    private final PacketEngine eng;
    final FlowKey key;
    private final int clientIp, serverIp, clientPort, serverPort;

    private State state = State.CONNECTING;
    private UpstreamStream up;

    private int clientIsn;
    private int iss;
    private int rcvNxt;              // next sequence number expected from the phone
    private int sndUna, sndNxt, sndMax;
    private int peerWnd;
    private int mss;

    // bytes [sndUna, sndUna+sbLen) that we have received from upstream but the phone has not acked yet
    private byte[] sb = new byte[8192];
    private int sbOff, sbLen;

    private boolean clientFin;       // phone sent FIN
    private boolean finWanted;       // upstream finished: send FIN after the data
    private boolean finSentOnce;
    private boolean finAcked;

    private int lastAdvWin = WIN_MAX;
    private boolean windowCheckPending;
    private int retries, synRetries, dupAcks;
    private long createdAt, lastProgress, lastActivity, closedAt;

    TcpFlow(PacketEngine eng, FlowKey key) {
        this.eng = eng;
        this.key = key;
        this.clientIp = key.clientIp;
        this.serverIp = key.serverIp;
        this.clientPort = key.clientPort;
        this.serverPort = key.serverPort;
    }

    private static long now() { return System.nanoTime() / 1000000L; }

    int clientIsn() { return clientIsn; }

    synchronized boolean isClosed() { return state == State.CLOSED; }

    // ---------------------------------------------------------------- lifecycle

    /** Called by the engine for the SYN that creates this flow. */
    synchronized void start(int synSeq, int synWindow, int clientMss) {
        clientIsn = synSeq;
        rcvNxt = synSeq + 1;
        peerWnd = synWindow;
        int ours = eng.mtu() - 40;
        int m = clientMss > 0 ? clientMss : 536;
        mss = Math.max(100, Math.min(m, ours));
        iss = RND.nextInt();
        createdAt = lastProgress = lastActivity = now();
        try {
            up = eng.connector().open(Ip.str(serverIp), serverPort, this);
        } catch (RuntimeException e) {
            eng.log("connect error " + Ip.str(serverIp) + ":" + serverPort + ": " + e);
            rstForSyn();
            closeInternal(true);
        }
    }

    private void rstForSyn() {
        eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, 0, clientIsn + 1, RST | ACK, 0, 0, null, 0, 0));
    }

    private void sendSynAck() {
        state = State.SYN_RCVD;
        sndUna = sndNxt = sndMax = iss + 1;
        lastProgress = now();
        eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, iss, rcvNxt, SYN | ACK, window(), mss, null, 0, 0));
    }

    // ---------------------------------------------------------------- upstream callbacks

    @Override
    public synchronized void onOpen() {
        if (state == State.CONNECTING) sendSynAck();
    }

    @Override
    public void onData(byte[] b, int off, int len) {
        synchronized (this) {
            while (state != State.CLOSED && sbLen >= SEND_BUF_MAX) {
                try {
                    wait(250);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            if (state == State.CLOSED) return;
            sbAppend(b, off, len);
            lastActivity = now();
            pump(false);
        }
    }

    @Override
    public synchronized void onClosed(boolean error) {
        if (state == State.CLOSED) return;
        if (state == State.CONNECTING) {
            // upstream could not be reached: behave like "connection refused"
            rstForSyn();
            closeInternal(true);
            return;
        }
        if (error) {
            abort(true);
            return;
        }
        finWanted = true;
        lastActivity = now();
        pump(false);
        checkDone();
    }

    // ---------------------------------------------------------------- packets from the phone

    synchronized void onSegment(int seq, int ack, int flags, int wnd, byte[] pkt, int payOff, int payLen) {
        lastActivity = now();

        if (state == State.CLOSED) {
            if ((flags & RST) == 0 && (payLen > 0 || (flags & (FIN | SYN)) != 0)) sendAck();
            return;
        }
        if ((flags & RST) != 0) {
            closeInternal(true);
            return;
        }
        if ((flags & SYN) != 0) {                 // retransmitted SYN
            if (state == State.SYN_RCVD) sendSynAck();
            return;
        }
        if (state == State.CONNECTING) return;     // nothing sensible to do until upstream is open

        if ((flags & ACK) != 0) {
            if (state == State.SYN_RCVD) {
                if (ack != iss + 1) {
                    eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, ack, 0, RST, 0, 0, null, 0, 0));
                    return;
                }
                state = State.ESTABLISHED;
                peerWnd = wnd;
                lastProgress = now();
            }
            processAck(ack, wnd, payLen == 0 && (flags & FIN) == 0);
        } else if (state == State.SYN_RCVD) {
            return;
        }

        boolean needAck = false;
        if (payLen > 0 || (flags & FIN) != 0) {
            needAck = true;
            int skip = rcvNxt - seq;               // >0: part of this segment is a retransmission
            if (skip >= 0) {                       // in order (or overlapping); skip<0 => out of order => dup ACK
                if (skip < payLen) {
                    int n = payLen - skip;
                    if (up != null) up.write(pkt, payOff + skip, n);
                    rcvNxt += n;
                }
                if (!oooList.isEmpty()) drainOoo();
                if ((flags & FIN) != 0 && !clientFin && seq + payLen == rcvNxt) {
                    clientFin = true;
                    rcvNxt++;
                    if (up != null) up.closeWrite();
                }
            } else if (payLen > 0) {
                stashOoo(seq, pkt, payOff, payLen);    // a hole before this segment: keep it for when the hole fills
            }
        }
        else if (seq - rcvNxt != 0) needAck = true;   // keepalive / zero-window probe (old seq): must be answered
        if (needAck) sendAck();
        checkDone();
    }

    private void processAck(int ack, int wnd, boolean pureAck) {
        int oldWnd = peerWnd;
        peerWnd = wnd;
        int acked = ack - sndUna;
        if (acked == 0 && pureAck && wnd == oldWnd && sndNxt != sndUna) {
            // duplicate ACK: the phone saw a gap. Three in a row => fast retransmit (go-back-N).
            if (++dupAcks == 3) {
                sndNxt = sndUna;
                lastProgress = now();
            }
        }
        if (acked > 0 && ack - sndMax <= 0) {
            dupAcks = 0;
            int dataAcked = Math.min(acked, sbLen);   // anything beyond the data is our FIN
            sbConsume(dataAcked);
            sndUna = ack;
            if (sndNxt - sndUna < 0) sndNxt = sndUna;
            lastProgress = now();
            retries = 0;
            if (finWanted && finSentOnce && sbLen == 0 && sndUna == sndMax) finAcked = true;
            notifyAll();                               // wake an upstream reader waiting for buffer space
        }
        pump(false);
    }

    // ---------------------------------------------------------------- sending to the phone

    /** Send as much buffered upstream data as the phone's window allows, then FIN if due. */
    private void pump(boolean probe) {
        if (state != State.ESTABLISHED) return;
        while (true) {
            int inflight = sndNxt - sndUna;
            int sentData = Math.min(inflight, sbLen);
            int unsent = sbLen - sentData;
            if (unsent <= 0) break;
            int wnd = peerWnd - inflight;
            if (wnd <= 0) {
                if (!probe) break;
                wnd = 1;
                probe = false;
            }
            int n = Math.min(Math.min(unsent, wnd), mss);
            int flags = ACK | (n == unsent ? PSH : 0);
            if (inflight == 0) lastProgress = now();
            int w = window();
            eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, flags, w, 0,
                    sb, sbOff + sentData, n));
            noteWindow(w);
            sndNxt += n;
            if (sndNxt - sndMax > 0) sndMax = sndNxt;
        }
        if (finWanted && (sndNxt - sndUna) == sbLen) {     // all data sent, FIN not yet
            if (sbLen == 0) lastProgress = now();
            int w = window();
            eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, FIN | ACK, w, 0, null, 0, 0));
            noteWindow(w);
            sndNxt++;
            if (sndNxt - sndMax > 0) sndMax = sndNxt;
            finSentOnce = true;
        }
    }

    private void sendAck() {
        int w = window();
        noteWindow(w);
        eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, ACK, w, 0, null, 0, 0));
    }

    /**
     * Remember what we advertised. If we closed the window (upstream is slower than the phone), poll
     * every few ms so the window update goes out as soon as the upstream has drained, instead of
     * waiting for the coarse housekeeping timer.
     */
    private void noteWindow(int w) {
        lastAdvWin = w;
        if (w < mss && !windowCheckPending && state == State.ESTABLISHED) {
            windowCheckPending = true;
            eng.schedule(windowCheck, 3);
        }
    }

    private final Runnable windowCheck = new Runnable() {
        @Override public void run() {
            synchronized (TcpFlow.this) {
                windowCheckPending = false;
                if (state != State.ESTABLISHED || lastAdvWin >= mss) return;
                if (window() >= mss) sendAck();
                else noteWindow(lastAdvWin);
            }
        }
    };

    private int window() {
        int pend = up == null ? 0 : up.pendingBytes();
        int w = WIN_MAX - pend;
        if (w < mss) return 0;
        return Math.min(w, WIN_MAX);
    }

    // ---------------------------------------------------------------- teardown

    synchronized void abort(boolean sendRst) {
        if (state == State.CLOSED) return;
        if (sendRst && state != State.CONNECTING) {
            eng.send(Packets.tcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, RST | ACK, 0, 0, null, 0, 0));
        }
        closeInternal(true);
    }

    private void checkDone() {
        if (state == State.ESTABLISHED && finAcked && clientFin) closeInternal(false);
    }

    private void closeInternal(boolean removeNow) {
        state = State.CLOSED;
        closedAt = now();
        sbLen = 0;
        sbOff = 0;
        oooList.clear();
        oooBytes = 0;
        if (sb.length > 65536) sb = new byte[8192];
        UpstreamStream u = up;
        if (u != null) u.close();
        notifyAll();
        if (removeNow) eng.remove(this);
    }

    // ---------------------------------------------------------------- timers

    synchronized void tick(long t) {
        switch (state) {
            case CONNECTING:
                if (t - createdAt > CONNECT_TIMEOUT_MS) {
                    rstForSyn();
                    closeInternal(true);
                }
                break;
            case SYN_RCVD:
                if (t - lastProgress > 1000) {
                    if (++synRetries > 5) abort(true);
                    else sendSynAck();
                }
                break;
            case ESTABLISHED:
                if (lastAdvWin < mss && window() >= mss) sendAck();            // window update
                int flight = sndNxt - sndUna;
                if (flight > 0) {
                    long rto = Math.min(8000L, 200L << Math.min(retries, 5));
                    if (t - lastProgress >= rto) {
                        if (peerWnd > 0 && ++retries > 12) {
                            abort(true);
                            return;
                        }
                        lastProgress = t;
                        sndNxt = sndUna;                                         // go-back-N
                        pump(false);
                    }
                } else if (sbLen > 0 && peerWnd == 0 && t - lastProgress >= 500) {
                    lastProgress = t;
                    pump(true);                                                  // zero-window probe
                }
                long idleLimit = (clientFin || finWanted) ? 30000L : 300000L;
                if (t - lastActivity > idleLimit) abort(true);
                break;
            case CLOSED:
                if (t - closedAt > LINGER_MS) eng.remove(this);
                break;
            default:
                break;
        }
    }

    // ---------------------------------------------------------------- out-of-order reassembly

    private static final class Ooo {
        final int seq;
        final byte[] data;
        Ooo(int seq, byte[] data) { this.seq = seq; this.data = data; }
    }

    private static final int OOO_MAX_BYTES = 128 * 1024;
    private final java.util.ArrayList<Ooo> oooList = new java.util.ArrayList<Ooo>();
    private int oooBytes;

    private void stashOoo(int seq, byte[] pkt, int off, int len) {
        if (seq - rcvNxt > 65535 || oooBytes + len > OOO_MAX_BYTES) return;   // outside window / too much
        for (Ooo o : oooList) if (o.seq == seq && o.data.length >= len) return; // already have it
        byte[] c = new byte[len];
        System.arraycopy(pkt, off, c, 0, len);
        oooList.add(new Ooo(seq, c));
        oooBytes += len;
    }

    private void drainOoo() {
        boolean progress = true;
        while (progress && !oooList.isEmpty()) {
            progress = false;
            for (java.util.Iterator<Ooo> it = oooList.iterator(); it.hasNext(); ) {
                Ooo o = it.next();
                int skip = rcvNxt - o.seq;
                if (skip < 0) continue;                               // still a gap before this one
                it.remove();
                oooBytes -= o.data.length;
                if (skip < o.data.length) {
                    int n = o.data.length - skip;
                    if (up != null) up.write(o.data, skip, n);
                    rcvNxt += n;
                    progress = true;
                }
            }
        }
    }

    @Override
    public synchronized String toString() {
        return key + " state=" + state + " rcvNxt=" + (rcvNxt - clientIsn) + " sndUna=" + (sndUna - iss) + " sndNxt=" + (sndNxt - iss)
                + " sbLen=" + sbLen + " peerWnd=" + peerWnd + " advWin=" + lastAdvWin + " clientFin=" + clientFin
                + " finWanted=" + finWanted + " finSent=" + finSentOnce + " finAcked=" + finAcked
                + " up.pending=" + (up == null ? -1 : up.pendingBytes()) + " retries=" + retries;
    }

    // ---------------------------------------------------------------- send buffer

    private void sbAppend(byte[] b, int off, int len) {
        if (sbOff + sbLen + len > sb.length) {
            if (sbLen + len <= sb.length) {
                System.arraycopy(sb, sbOff, sb, 0, sbLen);
                sbOff = 0;
            } else {
                byte[] n = new byte[Math.max(sb.length * 2, sbLen + len)];
                System.arraycopy(sb, sbOff, n, 0, sbLen);
                sb = n;
                sbOff = 0;
            }
        }
        System.arraycopy(b, off, sb, sbOff + sbLen, len);
        sbLen += len;
    }

    private void sbConsume(int n) {
        sbOff += n;
        sbLen -= n;
        if (sbLen == 0) {
            sbOff = 0;
            if (sb.length > 262144) sb = new byte[8192];
        }
    }
}
