#!/usr/bin/env bash
# End-to-end smoke test of astp-server and astp-client with real TUN
# devices: two network namespaces joined by a veth pair stand in for two
# machines. Needs root, /dev/net/tun, iproute2, openssl and ping.
#
#   scripts/vpn-netns-smoke.sh [h2|h3]      (default: both)
#
# BIN_DIR points at the binaries (default target/debug).
set -euo pipefail

BIN_DIR=${BIN_DIR:-target/debug}
SERVER=$BIN_DIR/astp-server
CLIENT=$BIN_DIR/astp-client
TRANSPORTS=${1:-"h2 h3"}
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 2; }
for t in ip openssl ping; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 2; }; done
[ -x "$SERVER" ] && [ -x "$CLIENT" ] || { echo "build first: cargo build -p astp-server -p astp-client" >&2; exit 2; }

WORK=$(mktemp -d)
SRV=astp-smoke-srv
CLI=astp-smoke-cli
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    ip netns del "$SRV" 2>/dev/null || true
    ip netns del "$CLI" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- PKI: a private CA and a P-256 leaf for astp.test -------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key" 2>/dev/null
openssl req -x509 -new -key "$WORK/ca.key" -subj "/CN=astp smoke CA" -days 2 -out "$WORK/ca.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/key.ec" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.ec" -out "$WORK/key.pem"
openssl req -new -key "$WORK/key.pem" -subj "/CN=astp.test" -out "$WORK/leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:astp.test\n' > "$WORK/san.ext"
openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 2 -extfile "$WORK/san.ext" -out "$WORK/cert.pem" 2>/dev/null

SECRET=$("$SERVER" keygen | sed -n 's/^secret *= "\(.*\)"$/\1/p')
SPATH=$("$SERVER" keygen | sed -n 's/^session_path = "\(.*\)"$/\1/p')

# --- two "machines" -------------------------------------------------------
ip netns add "$SRV"
ip netns add "$CLI"
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns "$SRV"
ip link set veth-cli netns "$CLI"
ip -n "$SRV" addr add 192.0.2.1/24 dev veth-srv
ip -n "$CLI" addr add 192.0.2.2/24 dev veth-cli
for ns in "$SRV" "$CLI"; do ip -n "$ns" link set lo up; done
ip -n "$SRV" link set veth-srv up
ip -n "$CLI" link set veth-cli up

cat > "$WORK/server.toml" <<TOML
[server]
listen_tcp = "192.0.2.1:443"
listen_quic = "192.0.2.1:443"
session_path = "$SPATH"
log_level = "info"
[tls]
cert_file = "$WORK/cert.pem"
key_file = "$WORK/key.pem"
[tunnel]
address4 = "10.77.0.1/24"
routes = ["0.0.0.0/0"]
[[clients]]
name = "smoke"
secret = "$SECRET"
address4 = "10.77.0.2"
TOML

ip netns exec "$SRV" "$SERVER" check --config "$WORK/server.toml"
ip netns exec "$SRV" "$SERVER" run --config "$WORK/server.toml" >"$WORK/server.log" 2>&1 &
PIDS+=($!)

wait_for() { # file pattern seconds
    for _ in $(seq 1 $(( $3 * 10 ))); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "timed out waiting for '$2' in $1:" >&2
    cat "$1" >&2
    return 1
}
wait_for "$WORK/server.log" "listening" 10

status=0
for t in $TRANSPORTS; do
    cat > "$WORK/client-$t.toml" <<TOML
[client]
server = "192.0.2.1:443"
tls_server_name = "astp.test"
ca_file = "$WORK/ca.pem"
transport = "$t"
session_path = "$SPATH"
secret = "$SECRET"
TOML
    ip netns exec "$CLI" "$CLIENT" --config "$WORK/client-$t.toml" >"$WORK/client-$t.log" 2>&1 &
    cpid=$!
    PIDS+=($cpid)
    wait_for "$WORK/client-$t.log" "session up" 15
    # Default route through the tunnel, server reachable around it.
    ip -n "$CLI" route | grep -q "0.0.0.0/1 dev astp0" || { echo "$t: no tunnel route" >&2; status=1; }
    if ip netns exec "$CLI" ping -c 3 -W 2 10.77.0.1 >"$WORK/ping-$t.log" 2>&1 \
        && ip netns exec "$SRV" ping -c 3 -W 2 10.77.0.2 >>"$WORK/ping-$t.log" 2>&1; then
        echo "$t: OK (client <-> server through the tunnel)"
    else
        echo "$t: FAILED" >&2
        cat "$WORK/ping-$t.log" "$WORK/client-$t.log" "$WORK/server.log" >&2
        status=1
    fi
    kill "$cpid"; wait "$cpid" 2>/dev/null || true
    # The client removed its routes on exit.
    if ip -n "$CLI" route | grep -q "0.0.0.0/1"; then echo "$t: routes left behind" >&2; status=1; fi
done
exit $status
