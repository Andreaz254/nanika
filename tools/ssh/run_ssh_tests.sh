#!/bin/sh
# SSH protocol tests: the real SshConnector (JSch) against a real SSH server (paramiko) behind HTTP-upgrade /
# TLS+SNI / WebSocket-frame front ends. Needs: JDK, python3 + paramiko, openssl, and the JSch jar.
#   JSCH_JAR=/path/to/jsch.jar sh tools/ssh/run_ssh_tests.sh        (default: /usr/share/java/jsch.jar)
set -e
cd "$(dirname "$0")/../.."
JSCH_JAR="${JSCH_JAR:-/usr/share/java/jsch.jar}"
OUT=$(mktemp -d); T=app/src/main/java/com/example/tunnel
JAVAC="javac"; command -v javac >/dev/null 2>&1 || JAVAC="java -m jdk.compiler/com.sun.tools.javac.Main"
$JAVAC -source 8 -target 8 -Xlint:-options -cp "$JSCH_JAR" -d "$OUT/c" \
  tools/vmess/stubs/okio/*.java tools/vmess/stubs/okhttp3/*.java tools/vmess/stubs/com/example/tunnel/TunnelState.java \
  $T/engine/Upstream*.java $T/protocol/*.java $T/vless/*.java $T/vmess/*.java $T/ssh/*.java tools/ssh/SshTests.java
python3 tools/ssh/ssh_test_server.py "$OUT/srv" 2>"$OUT/server.err" &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 1 100); do [ -f "$OUT/srv/ports.json" ] && break; sleep 0.1; done
[ -f "$OUT/srv/ports.json" ] || { echo "test server did not start"; cat "$OUT/server.err"; exit 1; }
java -cp "$OUT/c:$JSCH_JAR" SshTests "$OUT/srv"
