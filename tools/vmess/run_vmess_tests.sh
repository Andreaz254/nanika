#!/bin/sh
# VMess tests. Needs only a JDK and python3 with the `cryptography` package. No Android SDK, network or root.
#   1) Java codec vs. an independent Python implementation of the VMess AEAD server side
#   2) the real VmessWsConnector against an in-JVM fake VMess server (OkHttp replaced by tiny stubs)
set -e
cd "$(dirname "$0")/../.."
OUT=$(mktemp -d); T=app/src/main/java/com/example/tunnel
JAVAC="javac"; command -v javac >/dev/null 2>&1 || JAVAC="java -m jdk.compiler/com.sun.tools.javac.Main"
$JAVAC -source 8 -target 8 -Xlint:-options -d "$OUT/a" $T/vmess/VmessCodec.java tools/vmess/VmessVectors.java
echo "== Java codec vs independent Python implementation =="; python3 tools/vmess/verify_vmess.py "$OUT/a"
$JAVAC -source 8 -target 8 -Xlint:-options -d "$OUT/b" tools/vmess/stubs/okio/*.java tools/vmess/stubs/okhttp3/*.java \
  tools/vmess/stubs/com/example/tunnel/TunnelState.java $T/engine/Upstream*.java $T/protocol/*.java $T/vless/*.java $T/vmess/*.java tools/vmess/ConnectorTest.java
echo "== VmessWsConnector vs fake VMess server =="; java -cp "$OUT/b" com.example.tunnel.vmess.ConnectorTest
