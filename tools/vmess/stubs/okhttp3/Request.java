package okhttp3; public class Request { public String url; public java.util.Map<String,String> h=new java.util.HashMap<>();
  public static class Builder { Request r=new Request(); public Builder url(String u){r.url=u;return this;} public Builder header(String k,String v){r.h.put(k,v);return this;} public Request build(){return r;} } }
