#!/bin/sh
# Runs the pure-Java engine tests on a Linux machine. Needs: a JDK (javac), python3, and root
# (the e2e test creates a TUN device). No Android SDK or network access required.
#   sh tools/e2e/run_tests.sh            # clean link
#   LOSS=0.005 BIG_MB=4 sh tools/e2e/run_tests.sh   # 0.5% packet loss in both directions
set -e
cd "$(dirname "$0")/../.."
OUT=$(mktemp -d)
JAVAC="javac"; command -v javac >/dev/null 2>&1 || JAVAC="java -m jdk.compiler/com.sun.tools.javac.Main"
# VlessWsConnector needs OkHttp / TunnelState: compiled against the tiny stubs from tools/vmess/stubs
$JAVAC -source 8 -target 8 -Xlint:-options -d "$OUT/engine" tools/vmess/stubs/okio/*.java tools/vmess/stubs/okhttp3/*.java \
  tools/vmess/stubs/com/example/tunnel/TunnelState.java app/src/main/java/com/example/tunnel/engine/*.java \
  app/src/main/java/com/example/tunnel/vless/VlessCodec.java app/src/main/java/com/example/tunnel/vless/VlessWsConnector.java
$JAVAC -source 8 -target 8 -Xlint:-options -cp "$OUT/engine" -d "$OUT/tests" tools/e2e/E2EHarness.java tools/e2e/VlessTest.java
echo "== VLESS framing =="; java -cp "$OUT/engine:$OUT/tests" VlessTest
echo "== TCP/DNS engine vs. the real kernel TCP stack (TUN) =="; python3 tools/e2e/e2e_test.py "$OUT/engine" "$OUT/tests"
