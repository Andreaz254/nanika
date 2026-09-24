package okhttp3; public class OkHttpClient { public Hook hook; public interface Hook { WebSocket create(Request r, WebSocketListener l); }
  public WebSocket newWebSocket(Request r, WebSocketListener l){ return hook.create(r,l);} }
