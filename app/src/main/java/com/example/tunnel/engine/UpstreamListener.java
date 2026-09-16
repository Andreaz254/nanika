package com.example.tunnel.engine;

public interface UpstreamListener {
    /** The upstream is connected and ready to carry data. Called at most once. */
    void onOpen();

    /**
     * Data arrived from upstream. MAY block (this is how back-pressure reaches the
     * upstream reader) but must not be called concurrently for one stream.
     */
    void onData(byte[] data, int off, int len);

    /** Upstream finished. error=false: clean EOF. error=true: connect failure / reset. Called once. */
    void onClosed(boolean error);
}
