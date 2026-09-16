package com.example.tunnel.engine;

import java.io.IOException;

/** Where finished IP packets are written (the TUN device). */
public interface PacketSink {
    void write(byte[] buf, int off, int len) throws IOException;
}
