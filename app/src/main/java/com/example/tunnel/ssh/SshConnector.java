package com.example.tunnel.ssh;

import com.example.tunnel.TunnelState;
import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;
import com.example.tunnel.protocol.ProtocolConfig;
import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SSH tunnel for the packet engine: ONE SSH session (over {@link SshWsTransport}), and one "direct-tcpip"
 * channel per TCP flow - exactly what `ssh -D` / `ssh -L` do on the server side.
 * The session is created on first use, kept alive, and re-created on demand if it drops.
 */
public final class SshConnector implements UpstreamConnector, Closeable {
    private static final int CONNECT_TIMEOUT_MS = 25000;
    private static final int CHANNEL_TIMEOUT_MS = 15000;
    private static final int KEEPALIVE_SECONDS = 20;
    private static final long FAIL_COOLDOWN_MS = 3000;

    private final ProtocolConfig cfg;
    private final SshWsTransport.Settings settings = new SshWsTransport.Settings();
    private final ExecutorService pool = Executors.newCachedThreadPool(new ThreadFactory() {
        private final AtomicInteger n = new AtomicInteger();
        @Override public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "ssh-io-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        }
    });
    private final Object sessionLock = new Object();
    private final AtomicInteger channelLogs = new AtomicInteger();
    private ScheduledExecutorService keepalive;               // guarded by sessionLock
    private Session session;                                  // guarded by sessionLock
    private IOException lastFailure;                          // guarded by sessionLock
    private long lastFailureAt;                               // guarded by sessionLock
    private volatile Session live;
    private volatile SshWsTransport connecting;
    private volatile boolean closed;

    public SshConnector(ProtocolConfig cfg) {
        this.cfg = cfg;
        settings.proxyHost = cfg.proxyHost;
        settings.proxyPort = cfg.proxyPort;
        settings.tls = cfg.tls;
        settings.sni = cfg.sni;
        settings.insecure = cfg.insecureTls;
        settings.payload = cfg.payload;
        settings.sshHost = cfg.sshHost;
        settings.sshPort = cfg.sshPort;
        settings.wsFraming = cfg.wsFraming;
        settings.socketFactory = cfg.socketFactory;
    }

    // ------------------------------------------------------------------ UpstreamConnector

    @Override
    public UpstreamStream open(String destIp, int port, UpstreamListener listener) {
        final Stream s = new Stream(destIp, port, listener);
        try {
            pool.execute(s);
        } catch (RejectedExecutionException e) {
            new Thread(new Runnable() {
                @Override public void run() { s.finish(true); }
            }).start();
        }
        return s;
    }

    /** Non-blocking: the SSH session and the worker threads are torn down in the background. */
    @Override
    public void close() {
        closed = true;
        SshWsTransport c = connecting;
        if (c != null) c.close();                              // aborts a connect that is still in progress
        new Thread(new Runnable() {
            @Override public void run() {
                synchronized (sessionLock) { dropSessionLocked(); }
                pool.shutdownNow();
                ScheduledExecutorService k;
                synchronized (sessionLock) { k = keepalive; keepalive = null; }
                if (k != null) k.shutdownNow();
            }
        }, "ssh-close").start();
    }

    // ------------------------------------------------------------------ session handling

    private Session session() throws IOException {
        synchronized (sessionLock) {
            if (closed) throw new IOException("SSH tunnel is closed");
            if (session != null) {
                if (session.isConnected()) return session;
                TunnelState.log("SSH: session was lost - reconnecting");
                dropSessionLocked();
            }
            if (lastFailure != null && System.currentTimeMillis() - lastFailureAt < FAIL_COOLDOWN_MS) {
                throw new IOException(lastFailure.getMessage(), lastFailure);
            }
            try {
                Session s = connectNew();
                session = s;
                live = s;
                lastFailure = null;
                startKeepAliveLocked();
                return s;
            } catch (IOException e) {
                lastFailure = e;
                lastFailureAt = System.currentTimeMillis();
                throw e;
            }
        }
    }

    private void dropSessionLocked() {
        Session s = session;
        session = null;
        live = null;
        if (s != null) {
            try { s.disconnect(); } catch (Throwable ignored) { }
        }
    }

    private void invalidate(Session s) {
        synchronized (sessionLock) {
            if (session == s) dropSessionLocked();
        }
    }

    private Session connectNew() throws IOException {
        SshWsTransport transport = new SshWsTransport(settings);
        connecting = transport;
        try {
            JSch jsch = new JSch();
            String host = cfg.sshHost != null && !cfg.sshHost.isEmpty() ? cfg.sshHost : cfg.proxyHost;
            Session sess = jsch.getSession(cfg.sshUser, host, cfg.sshPort);
            sess.setPassword(cfg.sshPassword);
            sess.setUserInfo(new PasswordInfo(cfg.sshPassword));
            sess.setConfig("StrictHostKeyChecking", "no");        // there is no known_hosts on the phone
            sess.setConfig("PreferredAuthentications", "password,keyboard-interactive");
            sess.setConfig("max_input_buffer_size", "4194304");   // per-channel receive buffer (grows on demand)
            sess.setProxy(transport);

            TunnelState.log("SSH: opening the tunnel and logging in as " + cfg.sshUser + " ...");
            sess.connect(CONNECT_TIMEOUT_MS);
            if (closed) {
                sess.disconnect();
                throw new IOException("SSH tunnel is closed");
            }
            TunnelState.log("SSH: logged in");
            return sess;
        } catch (JSchException e) {
            transport.close();
            throw new IOException(describe(e), e);
        } finally {
            connecting = null;
        }
    }

    private static String describe(JSchException e) {
        String m = e.getMessage() == null ? e.toString() : e.getMessage();
        if (m.startsWith("Session.connect: ")) m = m.substring("Session.connect: ".length());
        if (m.contains("Auth fail") || m.contains("Auth cancel")) {
            return "SSH login failed - wrong username or password (or password login is disabled on the server)";
        }
        Throwable c = e.getCause();
        if (c != null && c.getMessage() != null && !m.contains(c.getMessage())) m += " (" + c.getMessage() + ")";
        if (m.contains("invalid server's version String") || m.contains("invalid server")) {
            m += " - the proxy did not hand the connection to an SSH server; check the payload and proxy host/port";
        } else if (m.contains("Algorithm negotiation fail")) {
            m += " - client and server share no SSH algorithm";
        }
        return "SSH: " + m;
    }

    private void startKeepAliveLocked() {
        if (keepalive != null) return;
        ScheduledExecutorService k = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "ssh-keepalive");
                t.setDaemon(true);
                return t;
            }
        });
        keepalive = k;
        k.scheduleWithFixedDelay(new Runnable() {
            @Override public void run() {
                Session s = live;
                if (s == null || !s.isConnected()) return;
                try {
                    s.sendKeepAliveMsg();
                } catch (Throwable t) {
                    TunnelState.log("SSH: keep-alive failed (" + t.getMessage() + ") - dropping the session");
                    try { s.disconnect(); } catch (Throwable ignored) { }
                }
            }
        }, KEEPALIVE_SECONDS, KEEPALIVE_SECONDS, TimeUnit.SECONDS);
    }

    /** Answers password and keyboard-interactive prompts with the saved password. */
    private static final class PasswordInfo implements UserInfo, UIKeyboardInteractive {
        private final String password;
        PasswordInfo(String password) { this.password = password; }
        @Override public String getPassphrase() { return null; }
        @Override public String getPassword() { return password; }
        @Override public boolean promptPassword(String message) { return true; }
        @Override public boolean promptPassphrase(String message) { return false; }
        @Override public boolean promptYesNo(String message) { return true; }
        @Override public void showMessage(String message) { TunnelState.logBanner(message); }
        @Override public String[] promptKeyboardInteractive(String dest, String name, String instruction,
                                                            String[] prompt, boolean[] echo) {
            String[] answers = new String[prompt == null ? 0 : prompt.length];
            Arrays.fill(answers, password);
            return answers;
        }
    }

    // ------------------------------------------------------------------ one TCP flow = one channel

    private final class Stream implements UpstreamStream, Runnable {
        /** Queue marker: "everything before me is written, now send SSH EOF" (client half-close). */
        private final byte[] EOF = new byte[0];
        private final String destIp;
        private final int port;
        private final UpstreamListener listener;
        private final ArrayDeque<byte[]> queue = new ArrayDeque<byte[]>();   // also the lock for the next 2 fields
        private boolean draining;
        private boolean ready;
        private final AtomicInteger pending = new AtomicInteger();
        private final AtomicBoolean finished = new AtomicBoolean();
        private volatile ChannelDirectTCPIP channel;
        private volatile OutputStream out;
        private volatile boolean closed;

        Stream(String destIp, int port, UpstreamListener listener) {
            this.destIp = destIp;
            this.port = port;
            this.listener = listener;
        }

        void finish(boolean error) {
            if (finished.compareAndSet(false, true)) listener.onClosed(error);
        }

        private void fail(String why) {
            if (channelLogs.incrementAndGet() <= 25) {
                TunnelState.log("SSH error for " + destIp + ":" + port + ": " + why);
            }
            close();
            finish(true);
        }

        @Override
        public void run() {
            ChannelDirectTCPIP c = null;
            try {
                InputStream in = null;
                OutputStream o = null;
                for (int attempt = 0; attempt < 2 && c == null; attempt++) {
                    Session sess = session();
                    if (closed) { finish(false); return; }
                    try {
                        ChannelDirectTCPIP cc = (ChannelDirectTCPIP) sess.openChannel("direct-tcpip");
                        cc.setHost(destIp);
                        cc.setPort(port);
                        in = cc.getInputStream();
                        o = cc.getOutputStream();
                        cc.connect(CHANNEL_TIMEOUT_MS);
                        c = cc;
                    } catch (JSchException e) {
                        String m = String.valueOf(e.getMessage());
                        boolean sessionDown = !sess.isConnected() || m.contains("session is down");
                        if (sessionDown && attempt == 0) { invalidate(sess); continue; }   // reconnect once
                        throw e;
                    }
                }
                if (c == null) throw new IOException("could not open an SSH channel");
                channel = c;
                out = o;
                if (closed) { disconnectAsync(c); finish(false); return; }
                synchronized (queue) { ready = true; }
                listener.onOpen();
                kick();

                byte[] buf = new byte[16384];
                int n;
                try {
                    while (!closed && (n = in.read(buf)) >= 0) {
                        if (n > 0) listener.onData(buf, 0, n);
                    }
                    finish(false);
                } catch (IOException e) {
                    boolean clean = closed || c.isEOF() || c.isClosed();
                    finish(!clean);
                }
            } catch (JSchException e) {
                fail("server refused " + destIp + ":" + port + " (" + e.getMessage() + ")");
            } catch (IOException e) {
                fail(e.getMessage());
            } catch (RuntimeException e) {
                fail(e.toString());
            } finally {
                closed = true;
                if (c != null) disconnectAsync(c);
            }
        }

        // ---- UpstreamStream (called by the packet engine)

        @Override
        public void write(byte[] data, int off, int len) {
            if (closed || len <= 0) return;
            byte[] copy = Arrays.copyOfRange(data, off, off + len);
            synchronized (queue) {
                queue.add(copy);
                pending.addAndGet(len);
            }
            kick();
        }

        private void kick() {
            synchronized (queue) {
                if (!ready || draining || queue.isEmpty() || closed) return;
                draining = true;
            }
            try {
                pool.execute(new Runnable() {
                    @Override public void run() { drain(); }
                });
            } catch (RejectedExecutionException e) {
                synchronized (queue) { draining = false; }
            }
        }

        /** Runs on the pool: JSch's output stream blocks while the server's window is full, the engine must not. */
        private void drain() {
            OutputStream o = out;
            try {
                while (true) {
                    byte[] chunk;
                    synchronized (queue) {
                        chunk = closed ? null : queue.poll();
                        if (chunk == null) { draining = false; return; }
                    }
                    if (chunk == EOF) {
                        o.close();                    // JSch flushes, then sends SSH_MSG_CHANNEL_EOF (read side stays open)
                        continue;
                    }
                    o.write(chunk);
                    o.flush();
                    pending.addAndGet(-chunk.length);
                }
            } catch (IOException e) {
                if (!closed) fail("write failed: " + e.getMessage());
            } catch (RuntimeException e) {
                if (!closed) fail("write failed: " + e);
            }
        }

        @Override public int pendingBytes() { return Math.max(0, pending.get()); }

        @Override
        public void closeWrite() {
            if (closed) return;
            synchronized (queue) { queue.add(EOF); }      // ordered after every pending write
            kick();
        }

        @Override
        public void close() {
            if (closed) return;
            closed = true;
            synchronized (queue) {
                queue.clear();
                pending.set(0);
            }
            ChannelDirectTCPIP c = channel;
            if (c != null) disconnectAsync(c);       // never block the engine thread on the SSH socket
        }

        private void disconnectAsync(final ChannelDirectTCPIP c) {
            try {
                pool.execute(new Runnable() {
                    @Override public void run() {
                        try { c.disconnect(); } catch (Throwable ignored) { }
                    }
                });
            } catch (RejectedExecutionException e) {
                // pool is shut down: the session is being torn down anyway
            }
        }
    }
}
