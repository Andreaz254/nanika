package okhttp3; public interface WebSocket { boolean send(okio.ByteString b); boolean close(int c,String r); void cancel(); long queueSize(); }
