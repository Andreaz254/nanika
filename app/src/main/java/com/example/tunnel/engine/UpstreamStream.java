package com.example.tunnel.engine;

/** One outbound byte stream (for the real app: one VLESS-over-WebSocket connection). */
public interface UpstreamStream {
    /** Queue data for the upstream. Must NOT block. Implementations must copy the bytes. */
    void write(byte[] data, int off, int len);

    /** Bytes accepted by write() that have not yet been flushed upstream (used for flow control). */
    int pendingBytes();

    /** Client finished sending (TCP FIN). May be a no-op if the transport has no half-close. */
    void closeWrite();

    /** Close the stream completely. Idempotent. */
    void close();
}
