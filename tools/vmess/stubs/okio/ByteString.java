package okio;
public final class ByteString { private final byte[] b; private ByteString(byte[] b){this.b=b;}
  public static ByteString of(byte[] d){return new ByteString(d.clone());}
  public static ByteString of(byte[] d,int o,int l){return new ByteString(java.util.Arrays.copyOfRange(d,o,o+l));}
  public byte[] toByteArray(){return b.clone();} }
