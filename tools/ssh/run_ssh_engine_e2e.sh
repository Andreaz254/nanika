#!/bin/sh
# The 13 packet-engine checks (kernel TCP stack via a TUN device, needs root) with the SSH connector as upstream:
#   apps -> TUN -> PacketEngine -> SshConnector -> [plain|TLS+SNI] HTTP-upgrade proxy -> SSH server -> target
#   JSCH_JAR=/path/jsch.jar sh tools/ssh/run_ssh_engine_e2e.sh [plain|tls]
set -e
cd "$(dirname "$0")/../.."
MODE="${1:-plain}"
JSCH_JAR="${JSCH_JAR:-/usr/share/java/jsch.jar}"
OUT=$(mktemp -d); T=app/src/main/java/com/example/tunnel
JAVAC="javac"; command -v javac >/dev/null 2>&1 || JAVAC="java -m jdk.compiler/com.sun.tools.javac.Main"
$JAVAC -source 8 -target 8 -Xlint:-options -cp "$JSCH_JAR" -d "$OUT/c" \
  tools/vmess/stubs/okio/*.java tools/vmess/stubs/okhttp3/*.java tools/vmess/stubs/com/example/tunnel/TunnelState.java \
  $T/engine/*.java $T/protocol/*.java $T/vless/*.java $T/vmess/*.java $T/ssh/*.java tools/ssh/SshEngineHarness.java
python3 tools/ssh/ssh_test_server.py "$OUT/srv" 2>"$OUT/server.err" &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 1 100); do [ -f "$OUT/srv/ports.json" ] && break; sleep 0.1; done
PORT=$(python3 -c "import json;print(json.load(open('$OUT/srv/ports.json'))['$MODE'])")
TLS=0; [ "$MODE" = tls ] && TLS=1
E2E_HARNESS_CLASS=SshEngineHarness E2E_CLASSPATH_EXTRA=":$OUT/c:$JSCH_JAR" E2E_HARNESS_ARGS="proxy=$PORT tls=$TLS" \
  python3 tools/e2e/e2e_test.py "$OUT/c" "$OUT/c"
