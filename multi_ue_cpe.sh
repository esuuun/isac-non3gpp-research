#!/usr/bin/env bash
set -e

# =============================================================
# Multi-UE CPE Simulation Script (Thesis Architecture)
# =============================================================
#
# Network topology:
#
#   192.168.0.140  CPE/OAI host          192.168.0.202  FlexRIC host
#   ────────────────────────────         ──────────────────────────────
#   nr-uesoftmodem (CPE, IMSI_1)         nearRT-RIC
#   oaitun_ue1  (10.60.0.x)             
#   br-ue/br-ueN (192.168.N.1)
#     ├─ ue1 (192.168.N.100)             192.168.0.140  CU-CP :8890
#     └─ ue2 (192.168.N.101)             CU-UP :8888
#              │                         MySQL: cpe_ue_context, ue_context
#              │ POST /api/cpe_handover → CU updates routing
#              ▼
#   same oaitun_ue1 path → CU → DU_1 or DU_2 based on IP_active
#
# Key thesis architecture:
#   - xApp/CU DHCP assigns per-CPE LAN IPs, e.g. 192.168.N.100-200
#   - DHCP relay on CPE forwards DHCP discover through GTP tunnel to CU
#   - CU tracks CPE_UE via MAC → assigns same IP on reconnect (IP continuity)
#   - Handover = CU updates CPE_UE path/TEID context in MySQL and CU-UP
#   - No VXLAN / ru2_forwarder needed (CU handles all routing)

# =============================================================
# Config
# =============================================================

OAI_IF="${OAI_IF:-oaitun_ue1}"          # CPE 5G TUN interface

# Per-CPE LAN selection:
#   CPE_LAN_ID=1 -> br-ue  / 192.168.1.1/24 / 192.168.1.0/24
#   CPE_LAN_ID=2 -> br-ue2 / 192.168.2.1/24 / 192.168.2.0/24
# If CPE_LAN_ID is not set, start/list/register derive it from oaitun_ue1
# last octet (10.60.0.x -> 192.168.x.0/24), falling back to 1.
CPE_LAN_ID="${CPE_LAN_ID:-}"
BR_NAME="${BR_NAME:-}"
BR_IP="${BR_IP:-}"
SUBNET="${SUBNET:-}"
TABLE_NAME="${TABLE_NAME:-}"
TABLE_ID="${TABLE_ID:-}"
CPE_NAT_CHAIN="${CPE_NAT_CHAIN:-}"

CU_IP="${CU_IP:-192.168.0.140}"          # CU host IP
XAPP_IP="${XAPP_IP:-192.168.0.202}"      # FlexRIC/xApp DHCP host
XAPP_PORT="${XAPP_PORT:-8083}"

# CPE_UE handover registration on CU-CP.
# IMSI generated as: CPE_IMSI_BASE + UE index - 1
CPE_HO_URL="${CPE_HO_URL:-http://${CU_IP}:8890/api/cpe_handover}"
CPE_IMSI_BASE="${CPE_IMSI_BASE:-}"
CPE_NAT_PORT_BASE="${CPE_NAT_PORT_BASE:-12345}"
AUTO_CPE_HO_REGISTER="${AUTO_CPE_HO_REGISTER:-1}"
CPE_TIME_CSV_APPEND="${CPE_TIME_CSV_APPEND:-}"
CPE_TIME_RUN_ID="${CPE_TIME_RUN_ID:-}"
CPE_DHCP_TIMEOUT_SEC="${CPE_DHCP_TIMEOUT_SEC:-15}"
# DHCP client used to acquire the lease in each UE namespace:
#   dhclient (default) — ISC dhclient, full dhclient-script hooks (slower startup)
#   udhcpc            — busybox udhcpc + minimal handler (much faster acquisition)
CPE_DHCP_CLIENT="${CPE_DHCP_CLIENT:-dhclient}"
# Measure the DHCP transaction on the wire (DISCOVER→ACK via tcpdump)
# instead of the dhclient/udhcpc process wall-clock (which includes process startup,
# dhclient-script hooks, etc.). The wall-clock value is still logged for comparison.
CPE_DHCP_CAPTURE="${CPE_DHCP_CAPTURE:-1}"
CPE_DHCP_CAPTURE_IF="${CPE_DHCP_CAPTURE_IF:-}"   # capture iface; empty = auto (namespace veth<N>n)
CPE_HO_LAST_POST_MS=0
CPE_HO_LAST_POST_STATUS="skip"

function now_ms() {
    date +%s%3N
}

function elapsed_ms() {
    local START_MS="$1"
    local END_MS="$2"
    echo "$((END_MS - START_MS))"
}

function fmt_ms() {
    local MS="$1"
    awk -v ms="$MS" 'BEGIN { printf "%.3fs", ms / 1000 }'
}

# Parse tcpdump text and print the DISCOVER→ACK time in integer ms (empty if not found).
# First "Request from" packet = DISCOVER, last "Reply" packet = ACK (one transaction
# per capture window). Robust across tcpdump versions (no -v message-type parsing).
function dhcp_discover_to_ack_ms() {
    local TCPDUMP_TXT="$1"
    awk '
        $1 ~ /^[0-9]+\.[0-9]+$/ {
            if (($0 ~ /Request from/ || $0 ~ /BOOTP\/DHCP, Request/) && first == "") first = $1
            if ($0 ~ /Reply/ || $0 ~ /BOOTP\/DHCP, Reply/)                           last  = $1
        }
        END { if (first != "" && last != "") printf("%.0f\n", (last - first) * 1000) }
    ' "$TCPDUMP_TXT"
}

function cpe_time_csv_append() {
    local NS="$1"
    local IDX="$2"
    local UE_IP="$3"
    local DHCP_MS="$4"
    local POST_MS="$5"
    local TOTAL_MS="$6"
    local POST_STATUS="$7"

    if [ -z "$CPE_TIME_CSV_APPEND" ]; then
        return 0
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$CPE_TIME_RUN_ID" "$NS" "$IDX" "$UE_IP" "$DHCP_MS" "$POST_MS" "$TOTAL_MS" "$POST_STATUS" "$(date -Iseconds)" \
        >> "$CPE_TIME_CSV_APPEND"
}

function cpe_outer_ip() {
    ip -4 addr show dev "$OAI_IF" 2>/dev/null \
        | grep -oP 'inet \K[\d.]+' | head -1
}

function cpe_outer_subnet() {
    local OUTER_IP
    OUTER_IP=$(cpe_outer_ip)
    if [ -z "$OUTER_IP" ]; then
        echo ""
        return
    fi

    echo "$OUTER_IP" | awk -F. '{printf "%s.%s.%s.0/24\n", $1, $2, $3}'
}

function derive_cpe_lan_id() {
    if [ -n "$CPE_LAN_ID" ]; then
        echo "$CPE_LAN_ID"
        return
    fi

    local OUTER_IP
    OUTER_IP=$(cpe_outer_ip)
    if [ -n "$OUTER_IP" ]; then
        local LAST_OCTET
        LAST_OCTET=$(echo "$OUTER_IP" | awk -F. '{print $4}')
        if [ -n "$LAST_OCTET" ] && [ "$LAST_OCTET" -ge 1 ] 2>/dev/null && [ "$LAST_OCTET" -le 254 ] 2>/dev/null; then
            echo "$LAST_OCTET"
            return
        fi
    fi

    echo "1"
}

function configure_cpe_lan() {
    local LAN_ID
    LAN_ID=$(derive_cpe_lan_id)
    CPE_LAN_ID="$LAN_ID"

    if [ -z "$BR_NAME" ]; then
        if [ "$LAN_ID" = "1" ]; then
            BR_NAME="br-ue"
        else
            BR_NAME="br-ue${LAN_ID}"
        fi
    fi
    BR_IP=${BR_IP:-192.168.${LAN_ID}.1/24}
    SUBNET=${SUBNET:-192.168.${LAN_ID}.0/24}
    CPE_IMSI_BASE=${CPE_IMSI_BASE:-$((208930000000000 + LAN_ID * 1000000000))}
    if [ -z "$TABLE_NAME" ]; then
        if [ "$LAN_ID" = "1" ]; then
            TABLE_NAME="ueclient"
        else
            TABLE_NAME="ueclient${LAN_ID}"
        fi
    fi
    TABLE_ID=${TABLE_ID:-$((100 + LAN_ID - 1))}
    if [ -z "$CPE_NAT_CHAIN" ]; then
        if [ "$LAN_ID" = "1" ]; then
            CPE_NAT_CHAIN="CPE_UE_NAT"
        else
            CPE_NAT_CHAIN="CPE_UE_NAT_${LAN_ID}"
        fi
    fi
}

function cpe_imsi_for_index() {
    local IDX="$1"
    printf "%015d" "$((CPE_IMSI_BASE + IDX - 1))"
}

function cpe_nat_port_for_index() {
    local IDX="$1"
    echo "$((CPE_NAT_PORT_BASE + IDX - 1))"
}

function cpe_mac_for_index() {
    local IDX="$1"
    printf "02:ce:%02x:00:%02x:%02x" "$CPE_LAN_ID" "$((IDX / 256))" "$((IDX % 256))"
}

function post_cpe_handover() {
    local IDX="$1"
    local INNER_IP="$2"
    local OUTER_IP
    CPE_HO_LAST_POST_MS=0
    CPE_HO_LAST_POST_STATUS="fail"
    OUTER_IP=$(cpe_outer_ip)

    if [ -z "$OUTER_IP" ]; then
        echo "[WARN] CPE HO: cannot read $OAI_IF IPv4 address, skip POST for ue$IDX"
        return 1
    fi

    local IMSI
    local NAT_PORT
    IMSI=$(cpe_imsi_for_index "$IDX")
    NAT_PORT=$(cpe_nat_port_for_index "$IDX")

    local JSON
    JSON=$(printf '{"imsi":"%s","cpe_outer_ip":"%s","cpe_nat_port":%u,"cpe_inner_ip":"%s"}' \
                  "$IMSI" "$OUTER_IP" "$NAT_PORT" "$INNER_IP")

    echo "[CPE HO] ue$IDX: POST $CPE_HO_URL"
    echo "         imsi=$IMSI outer=$OUTER_IP port=$NAT_PORT inner=$INNER_IP"

    local RESP
    local POST_START_MS
    local POST_END_MS
    POST_START_MS=$(now_ms)
    RESP=$(curl -s -m 3 -X POST "$CPE_HO_URL" \
           -H "Content-Type: application/json" \
           -d "$JSON" || true)
    POST_END_MS=$(now_ms)
    CPE_HO_LAST_POST_MS=$(elapsed_ms "$POST_START_MS" "$POST_END_MS")

    if echo "$RESP" | grep -q '"status":"ok"'; then
        CPE_HO_LAST_POST_STATUS="ok"
        echo "[CPE HO] ue$IDX: registered ($RESP) post_time=$(fmt_ms "$CPE_HO_LAST_POST_MS")"
        return 0
    fi

    echo "[WARN] CPE HO: POST failed for ue$IDX post_time=$(fmt_ms "$CPE_HO_LAST_POST_MS") response='$RESP'"
    return 1
}

# =============================================================
# ensure_bridge
# =============================================================
function ensure_bridge() {
    if ! ip link show $BR_NAME >/dev/null 2>&1; then
        sudo ip link add name $BR_NAME type bridge
    fi
    sudo ip link set $BR_NAME up
    local BR_ADDR
    BR_ADDR="${BR_IP%/*}"
    if ! ip -4 addr show dev $BR_NAME | grep -q "$BR_ADDR"; then
        sudo ip addr flush dev $BR_NAME 2>/dev/null || true
        sudo ip addr add $BR_IP dev $BR_NAME
    fi
}

# =============================================================
# start <count>
#   Creates UE namespaces that get IPs from CU's DHCP server
#   via DHCP relay through the GTP tunnel.
#
#   xApp assigns: 192.168.N.100, 192.168.N.101, ...
# =============================================================
function start_ue() {
    local NUM=${1:-1}

    if ! ip link show $OAI_IF >/dev/null 2>&1; then
        echo "[ERROR] $OAI_IF not found. Start OAI UE softmodem first."
        exit 1
    fi

    configure_cpe_lan

    echo "[+] CPE LAN ID: $CPE_LAN_ID (outer=$(cpe_outer_ip), subnet=$SUBNET, imsi_base=$CPE_IMSI_BASE)"
    echo "[+] Setting up bridge $BR_NAME ($BR_IP)..."
    ensure_bridge

    echo "[+] Enabling IP forwarding..."
    sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sudo sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
    sudo sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null
    sudo sysctl -w net.ipv4.conf.$OAI_IF.send_redirects=0 >/dev/null 2>&1 || true
    sudo sysctl -w net.ipv4.conf.$BR_NAME.send_redirects=0 >/dev/null 2>&1 || true

    # Route to CU DHCP subnet via GTP (needed for dhcrelay to reach CU)
    # The CPE LAN subnet is on br-ue/br-ueN — do NOT add via oaitun_ue1 (causes routing loop:
    # CU→DU→OAI UE→oaitun_ue1→GTP uplink→CU→LBO→DU→loop)
    # The bridge address makes the kernel add $SUBNET dev $BR_NAME automatically.

    # Policy routing: CPE_UE traffic → oaitun_ue1
    if ! grep -q "$TABLE_NAME" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "$TABLE_ID $TABLE_NAME" | sudo tee -a /etc/iproute2/rt_tables
    fi
    # Anti-loop: packets coming back from CU on oaitun_ue1 and destined to the
    # local CPE LAN must be delivered to the bridge, not routed back into oaitun_ue1.
    sudo ip rule del to $SUBNET lookup main priority 40 2>/dev/null || true
    sudo ip rule add to $SUBNET lookup main priority 40 2>/dev/null || true
    sudo ip rule del iif $OAI_IF to $SUBNET lookup main priority 50 2>/dev/null || true
    sudo ip rule add iif $OAI_IF to $SUBNET lookup main priority 50 2>/dev/null || true
    sudo ip route del $SUBNET dev $OAI_IF 2>/dev/null || true
    sudo ip route replace $SUBNET dev $BR_NAME

    sudo ip route add default dev $OAI_IF table $TABLE_NAME 2>/dev/null || true
    sudo ip route add $SUBNET  dev $BR_NAME table $TABLE_NAME 2>/dev/null || true
    sudo ip rule  add from $SUBNET table $TABLE_NAME priority 100 2>/dev/null || true

    # Allow forwarding between the CPE bridge and oaitun_ue1
    sudo iptables -A FORWARD -i $BR_NAME -o $OAI_IF -j ACCEPT 2>/dev/null || true
    sudo iptables -A FORWARD -i $OAI_IF -o $BR_NAME -j ACCEPT 2>/dev/null || true

    local OAI_SUBNET
    OAI_SUBNET=$(cpe_outer_subnet)
    OAI_SUBNET=${OAI_SUBNET:-10.60.0.0/24}

    # MASQUERADE for external traffic only. Keep the CPE LAN IP visible when talking
    # to local CPE LAN or 10.60.0.x UEs so CU can apply local-switch correctly.
    # Use a small chain because iptables-nft rejects multiple -d matches in one rule.
    sudo iptables -t nat -D POSTROUTING -s $SUBNET ! -d $SUBNET -o $OAI_IF -j MASQUERADE 2>/dev/null || true
    sudo iptables -t nat -D POSTROUTING -s $SUBNET -o $OAI_IF -j $CPE_NAT_CHAIN 2>/dev/null || true
    sudo iptables -t nat -F $CPE_NAT_CHAIN 2>/dev/null || sudo iptables -t nat -N $CPE_NAT_CHAIN
    sudo iptables -t nat -A $CPE_NAT_CHAIN -d $SUBNET -j RETURN
    sudo iptables -t nat -A $CPE_NAT_CHAIN -d $OAI_SUBNET -j RETURN
    sudo iptables -t nat -A $CPE_NAT_CHAIN -j MASQUERADE
    sudo iptables -t nat -A POSTROUTING -s $SUBNET -o $OAI_IF -j $CPE_NAT_CHAIN

    # DHCP relay: CPE bridge (L2 bridge) → xApp DHCP server (192.168.0.202)
    # Note: relay uses ens18 (Ethernet), NOT oaitun_ue1 (TUN).
    # xApp DHCP server should assign addresses from this CPE LAN subnet and
    # write the resulting cpe_inner_ip to CU MySQL.
    sudo pkill dhcrelay 2>/dev/null || true
    sudo pkill dnsmasq 2>/dev/null || true
    sleep 0.5
    # Clear old root-owned log files
    sudo rm -f /tmp/dhcrelay.log /tmp/dhclient_ue*.log
    sudo touch /tmp/dhcrelay.log && sudo chmod 666 /tmp/dhcrelay.log

    # --- pre-flight checks ---
    echo "[CHECK] Pinging xApp host $XAPP_IP ..."
    if ! ping -c 1 -W 1 $XAPP_IP >/dev/null 2>&1; then
        echo "[WARN]  $XAPP_IP unreachable. Check network."
    else
        echo "[OK]    $XAPP_IP reachable"
        if command -v nmap >/dev/null 2>&1; then
            nmap -sU -p 67 $XAPP_IP --open 2>/dev/null | grep -q "67/udp open" && \
                echo "[OK]    $XAPP_IP:67/udp open (xApp DHCP running)" || \
                echo "[WARN]  $XAPP_IP:67/udp not detected. Start: sudo ./xapp_dhcp_server"
        else
            echo "[INFO]  Make sure xApp DHCP server is running on $XAPP_IP: sudo ./xapp_dhcp_server"
        fi
    fi

    # Detect uplink interface (the one with the default route)
    UPLINK=$(ip route show default | awk '/default/{print $5; exit}')
    UPLINK=${UPLINK:-ens18}
    echo "[+] Starting dhcrelay: $BR_NAME (downstream) ↔ $UPLINK (upstream) → xApp DHCP ($XAPP_IP)..."
    # Use -id/-iu to explicitly separate client-facing and server-facing interfaces.
    # dhcrelay 4.4.1 requires this; without it, server replies on the uplink are ignored.
    # Keep the same relay interfaces as the debug command, but detach the process
    # so "start" can finish instead of staying tied to the terminal.
    if dhcrelay --help 2>&1 | grep -q "\-id"; then
        sudo nohup setsid dhcrelay -id "$BR_NAME" -iu "$UPLINK" "$XAPP_IP" \
            > /tmp/dhcrelay.log 2>&1 &
    else
        sudo nohup setsid dhcrelay -i "$BR_NAME" -i "$UPLINK" "$XAPP_IP" \
            > /tmp/dhcrelay.log 2>&1 &
    fi
    RELAY_PID=$!
    echo "[+] dhcrelay PID: $RELAY_PID"
    sleep 2

    # Verify relay started and show first log lines
    echo "[dhcrelay log]"
    cat /tmp/dhcrelay.log 2>/dev/null || echo "  (no log yet)"

    if grep -q "exiting\|error\|Error" /tmp/dhcrelay.log 2>/dev/null; then
        echo "[ERROR] dhcrelay failed. Full log:"
        cat /tmp/dhcrelay.log
        exit 1
    fi

    local TOTAL_DHCP_MS=0
    local TOTAL_POST_MS=0
    local TOTAL_ONLINE_MS=0
    local ONLINE_OK_COUNT=0

    # --- DHCP client selection (CPE_DHCP_CLIENT=dhclient|udhcpc) ---
    local UDHCPC_SCRIPT="/tmp/udhcpc_min.script"
    local UDHCPC_BIN=""
    if [ "$CPE_DHCP_CLIENT" = "udhcpc" ]; then
        if command -v udhcpc >/dev/null 2>&1; then
            UDHCPC_BIN="udhcpc"
        elif command -v busybox >/dev/null 2>&1; then
            UDHCPC_BIN="busybox udhcpc"
        else
            echo "[ERROR] CPE_DHCP_CLIENT=udhcpc but neither udhcpc nor busybox found."
            echo "        Install: sudo apt install -y busybox"
            exit 1
        fi
        # Minimal lease handler: only set the address (CPE LANs are /24).
        # Skips resolv.conf / NTP / hook processing that makes ISC dhclient slow.
        sudo tee "$UDHCPC_SCRIPT" >/dev/null <<'EOF'
#!/bin/sh
case "$1" in
    bound|renew)
        ip addr flush dev "$interface" 2>/dev/null
        ip addr add "$ip/24" dev "$interface"
        [ -n "$router" ] && ip route replace default via "$router" dev "$interface" 2>/dev/null
        ;;
esac
exit 0
EOF
        sudo chmod 755 "$UDHCPC_SCRIPT"
        echo "[+] DHCP client: $UDHCPC_BIN (fast path), handler=$UDHCPC_SCRIPT"
    else
        echo "[+] DHCP client: dhclient (default)"
    fi

    # Create namespaces — get IPs via xApp DHCP server
    for i in $(seq 1 $NUM); do
        NS="ue${i}"
        VETH_HOST="veth${i}h"
        VETH_NS="veth${i}n"
        UE_MAC=$(cpe_mac_for_index "$i")

        echo "[*] Creating namespace $NS..."
        sudo ip netns del $NS 2>/dev/null || true
        sudo ip netns add $NS
        sudo ip link del $VETH_HOST 2>/dev/null || true
        sudo ip link add $VETH_HOST type veth peer name $VETH_NS
        sudo ip link set $VETH_NS netns $NS
        sudo ip netns exec $NS ip link set dev $VETH_NS address "$UE_MAC"
        sudo ip link set $VETH_HOST master $BR_NAME
        sudo ip link set $VETH_HOST up
        sudo ip netns exec $NS ip link set lo up
        sudo ip netns exec $NS ip link set $VETH_NS up

        echo "[*] $NS: requesting IP from xApp DHCP server ($XAPP_IP) mac=$UE_MAC..."
        sudo rm -f /tmp/dhclient_${NS}.log
        sudo touch /tmp/dhclient_${NS}.log && sudo chmod 666 /tmp/dhclient_${NS}.log
        local UE_ONLINE_START_MS
        local IP_ACQUIRED_MS
        local DHCP_MS
        local DHCP_WALL_MS
        local DHCLIENT_EXIT
        local POST_MS
        local UE_ONLINE_END_MS
        local UE_ONLINE_MS
        local CAP_IF="${CPE_DHCP_CAPTURE_IF:-$VETH_NS}"
        local CAP_DESC="$CAP_IF"
        local TCPDUMP_LOG="/tmp/tcpdump_${NS}.log"
        local PCAP="/tmp/dhcp_${NS}.pcap"
        local TCPDUMP_TXT="/tmp/dhcp_${NS}.txt"
        local TCPDUMP_PID=""
        if [ "$CPE_DHCP_CAPTURE" = "1" ]; then
            sudo rm -f "$PCAP"
            sudo rm -f "$TCPDUMP_TXT"
            sudo rm -f "$TCPDUMP_LOG"
            sudo touch "$TCPDUMP_TXT" && sudo chmod 666 "$TCPDUMP_TXT"
            sudo touch "$TCPDUMP_LOG" && sudo chmod 666 "$TCPDUMP_LOG"
            if [ -z "$CPE_DHCP_CAPTURE_IF" ]; then
                CAP_DESC="$NS/$VETH_NS"
                sudo ip netns exec "$NS" tcpdump -l -nn -tt -i "$VETH_NS" 'port 67 or port 68' \
                    > "$TCPDUMP_TXT" 2> "$TCPDUMP_LOG" &
            else
                sudo tcpdump -l -nn -tt -i "$CAP_IF" 'port 67 or port 68' \
                    > "$TCPDUMP_TXT" 2> "$TCPDUMP_LOG" &
            fi
            TCPDUMP_PID=$!
            sleep 0.3   # let tcpdump attach before the client sends DISCOVER
        fi
        UE_ONLINE_START_MS=$(now_ms)

        set +e
        if [ "$CPE_DHCP_CLIENT" = "udhcpc" ]; then
            # -q quit after lease, -n exit if none, -f foreground, -t/-T fast retry
            sudo timeout "$CPE_DHCP_TIMEOUT_SEC" \
                ip netns exec $NS $UDHCPC_BIN -i $VETH_NS -q -n -f -t 5 -T 1 -s "$UDHCPC_SCRIPT" \
                > /tmp/dhclient_${NS}.log 2>&1
        else
            sudo timeout "$CPE_DHCP_TIMEOUT_SEC" \
                ip netns exec $NS dhclient -1 -v $VETH_NS \
                > /tmp/dhclient_${NS}.log 2>&1
        fi
        DHCLIENT_EXIT=$?
        set -e
        IP_ACQUIRED_MS=$(now_ms)
        DHCP_WALL_MS=$(elapsed_ms "$UE_ONLINE_START_MS" "$IP_ACQUIRED_MS")
        DHCP_MS=""
        # Use on-wire DISCOVER→ACK time so DHCP latency excludes client startup.
        if [ -n "$TCPDUMP_PID" ]; then
            sleep 0.2
            sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true
            wait "$TCPDUMP_PID" 2>/dev/null || true
            local WIRE_MS
            WIRE_MS=$(dhcp_discover_to_ack_ms "$TCPDUMP_TXT")
            if [ -n "$WIRE_MS" ]; then
                DHCP_MS="$WIRE_MS"
            else
                echo "[WARN] $NS: no DISCOVER→ACK found in $TCPDUMP_TXT (capture iface $CAP_DESC correct?); metric row will be skipped"
                echo "--- tcpdump packets ---"
                cat "$TCPDUMP_TXT" 2>/dev/null || true
                echo "--- tcpdump log ---"
                cat "$TCPDUMP_LOG" 2>/dev/null || true
            fi
        else
            DHCP_MS="$DHCP_WALL_MS"
            echo "[WARN] $NS: CPE_DHCP_CAPTURE=0, using wall-clock DHCP time"
        fi

        local UE_IP
        UE_IP=$(sudo ip netns exec $NS ip -4 addr show dev $VETH_NS 2>/dev/null \
                | grep -oP 'inet \K[\d.]+' | grep -v 127 | head -1)
        if [ -n "$UE_IP" ]; then
            if [ -n "$DHCP_MS" ]; then
                echo "[OK] $NS: IP = $UE_IP (from xApp DHCP at $XAPP_IP) discover_to_ack=$(fmt_ms "$DHCP_MS") wall=$(fmt_ms "$DHCP_WALL_MS")"
            else
                echo "[OK] $NS: IP = $UE_IP (from xApp DHCP at $XAPP_IP) discover_to_ack=missing wall=$(fmt_ms "$DHCP_WALL_MS")"
            fi
            if ! echo "$UE_IP" | grep -q "^192\\.168\\.${CPE_LAN_ID}\\."; then
                echo "[WARN] $NS: IP does not match expected LAN $SUBNET."
                echo "       Update xApp DHCP scope/relay mapping for CPE_LAN_ID=$CPE_LAN_ID."
            fi
            if [ "$AUTO_CPE_HO_REGISTER" = "1" ]; then
                post_cpe_handover "$i" "$UE_IP" || true
                POST_MS="$CPE_HO_LAST_POST_MS"
                UE_ONLINE_END_MS=$(now_ms)
                local WALL_TOTAL_MS
                WALL_TOTAL_MS=$(elapsed_ms "$UE_ONLINE_START_MS" "$UE_ONLINE_END_MS")
                if [ -n "$DHCP_MS" ]; then
                    UE_ONLINE_MS=$((DHCP_MS + POST_MS))
                    TOTAL_DHCP_MS=$((TOTAL_DHCP_MS + DHCP_MS))
                    TOTAL_POST_MS=$((TOTAL_POST_MS + POST_MS))
                    TOTAL_ONLINE_MS=$((TOTAL_ONLINE_MS + UE_ONLINE_MS))
                    ONLINE_OK_COUNT=$((ONLINE_OK_COUNT + 1))
                    cpe_time_csv_append "$NS" "$i" "$UE_IP" "$DHCP_MS" "$POST_MS" "$UE_ONLINE_MS" "$CPE_HO_LAST_POST_STATUS"
                    echo "[TIME] $NS: discover_to_ack=$(fmt_ms "$DHCP_MS") (client_wall=$(fmt_ms "$DHCP_WALL_MS")) post_to_cu=$(fmt_ms "$POST_MS") total_metric=$(fmt_ms "$UE_ONLINE_MS") wall_total=$(fmt_ms "$WALL_TOTAL_MS") post_status=$CPE_HO_LAST_POST_STATUS"
                    if [ "$DHCP_MS" -gt 1000 ]; then
                        echo "[WARN] $NS: DHCP took $(fmt_ms "$DHCP_MS"); likely retransmission or delayed relay/server response."
                        echo "--- dhclient log (slow DHCP, last 20 lines) ---"
                        tail -20 /tmp/dhclient_${NS}.log 2>/dev/null
                    fi
                else
                    echo "[TIME] $NS: discover_to_ack=missing (client_wall=$(fmt_ms "$DHCP_WALL_MS")) post_to_cu=$(fmt_ms "$POST_MS") total_metric=skip wall_total=$(fmt_ms "$WALL_TOTAL_MS") post_status=$CPE_HO_LAST_POST_STATUS"
                fi
            else
                echo "[INFO] CPE HO auto-register disabled (AUTO_CPE_HO_REGISTER=0)"
                if [ -n "$DHCP_MS" ]; then
                    echo "[TIME] $NS: discover_to_ack=$(fmt_ms "$DHCP_MS") (client_wall=$(fmt_ms "$DHCP_WALL_MS")) post_to_cu=skip total_metric=skip"
                else
                    echo "[TIME] $NS: discover_to_ack=missing (client_wall=$(fmt_ms "$DHCP_WALL_MS")) post_to_cu=skip total_metric=skip"
                fi
            fi
        else
            echo "[WARN] $NS: No IP received. dhclient_exit=$DHCLIENT_EXIT dhcp_wait=$(fmt_ms "$DHCP_WALL_MS")"
            echo "--- dhclient log (last 10 lines) ---"
            tail -10 /tmp/dhclient_${NS}.log 2>/dev/null
            echo "--- dhcrelay log (last 10 lines) ---"
            tail -10 /tmp/dhcrelay.log 2>/dev/null
            echo "--- Debug tips ---"
            echo "  1. xApp DHCP running on $XAPP_IP?  ps aux | grep xapp_dhcp"
            echo "  2. dhcrelay relaying?  cat /tmp/dhcrelay.log"
            echo "  3. $BR_NAME up?        ip addr show $BR_NAME"
        fi
    done

    if [ "$ONLINE_OK_COUNT" -gt 0 ]; then
        echo "[TIME] summary: ue_count=$ONLINE_OK_COUNT total_dhcp=$(fmt_ms "$TOTAL_DHCP_MS") total_post=$(fmt_ms "$TOTAL_POST_MS") total_metric=$(fmt_ms "$TOTAL_ONLINE_MS") avg_metric=$(fmt_ms "$((TOTAL_ONLINE_MS / ONLINE_OK_COUNT))")"
    fi

    echo "[OK] Done. Use 'list' to view UE IPs."
    echo "     Expected: 192.168.${CPE_LAN_ID}.100, 192.168.${CPE_LAN_ID}.101, ..."
    echo "     CPE HO IMSI base: $CPE_IMSI_BASE (override with CPE_IMSI_BASE=...)"
}

# =============================================================
# list
# =============================================================
function list_ue() {
    configure_cpe_lan
    echo "=== Active UE namespaces ==="
    echo "CPE_LAN_ID=$CPE_LAN_ID BR=$BR_NAME SUBNET=$SUBNET IMSI_BASE=$CPE_IMSI_BASE"
    for NS in $(ip netns list | awk '{print $1}' | grep -E '^ue[0-9]+' || true); do
        local UE_IP
        UE_IP=$(sudo ip netns exec $NS ip -4 addr show 2>/dev/null \
                | grep -oP 'inet \K[\d.]+' | grep -v 127 | head -1)
        local IDX
        IDX=$(echo "$NS" | grep -oP '^ue\K[0-9]+')
        if [ -n "$IDX" ]; then
            echo "[$NS] IP=$UE_IP IMSI=$(cpe_imsi_for_index "$IDX") NAT_PORT=$(cpe_nat_port_for_index "$IDX")"
        else
            echo "[$NS] IP=$UE_IP"
        fi
    done
    echo "==========================="
}

# =============================================================
# handover_register <ns|all>
#   POST CPE_UE entries to CU-CP /api/cpe_handover.
# =============================================================
function handover_register_ue() {
    local TARGET="${1:-all}"

    if ! ip link show "$OAI_IF" >/dev/null 2>&1; then
        echo "[ERROR] $OAI_IF not found. Start CPE host nr-uesoftmodem first."
        exit 1
    fi

    configure_cpe_lan

    local OUTER_IP
    OUTER_IP=$(cpe_outer_ip)
    if [ -z "$OUTER_IP" ]; then
        echo "[ERROR] $OAI_IF has no IPv4 address."
        exit 1
    fi

    local NAMESPACES
    if [ "$TARGET" = "all" ]; then
        NAMESPACES=$(ip netns list | awk '{print $1}' | grep -E '^ue[0-9]+' | sort -V || true)
    else
        NAMESPACES="$TARGET"
    fi

    if [ -z "$NAMESPACES" ]; then
        echo "[WARN] No UE namespaces found."
        return 0
    fi

    for NS in $NAMESPACES; do
        local IDX
        IDX=$(echo "$NS" | grep -oP '^ue\K[0-9]+')
        if [ -z "$IDX" ]; then
            echo "[WARN] Skip non-standard namespace '$NS' (expected ue<N>)"
            continue
        fi

        local UE_IP
        UE_IP=$(sudo ip netns exec "$NS" ip -4 addr show 2>/dev/null \
                | grep -oP 'inet \K[\d.]+' | grep -v 127 | head -1)
        if [ -z "$UE_IP" ]; then
            echo "[WARN] $NS has no IPv4 address, skip."
            continue
        fi

        post_cpe_handover "$IDX" "$UE_IP" || true
    done
}

# =============================================================
# stop
# =============================================================
function stop_ue() {
    configure_cpe_lan
    echo "[+] Stopping..."
    echo "[+] CPE_LAN_ID=$CPE_LAN_ID BR=$BR_NAME SUBNET=$SUBNET IMSI_BASE=$CPE_IMSI_BASE"
    sudo pkill dnsmasq 2>/dev/null || true
    sudo pkill dhcrelay 2>/dev/null || true

    for NS in $(ip netns list | awk '{print $1}' | grep -E '^ue[0-9]+' || true); do
        sudo ip netns exec $NS dhclient -r 2>/dev/null || true
        sudo ip netns del $NS || true
    done
    for V in $(ip -o link show | awk -F: '{print $2}' | tr -d ' ' | grep -E '^veth[0-9]+h' || true); do
        sudo ip link del $V 2>/dev/null || true
    done

    sudo ip rule  del from $SUBNET table $TABLE_NAME 2>/dev/null || true
    sudo ip rule  del to $SUBNET lookup main priority 40 2>/dev/null || true
    sudo ip rule  del iif $OAI_IF to $SUBNET lookup main priority 50 2>/dev/null || true
    sudo ip route flush table $TABLE_NAME 2>/dev/null || true
    sudo ip route del $SUBNET dev $OAI_IF 2>/dev/null || true

    sudo iptables -D FORWARD -i $BR_NAME -o $OAI_IF -j ACCEPT 2>/dev/null || true
    sudo iptables -D FORWARD -i $OAI_IF -o $BR_NAME -j ACCEPT 2>/dev/null || true

    local OAI_SUBNET
    OAI_SUBNET=$(cpe_outer_subnet)
    OAI_SUBNET=${OAI_SUBNET:-10.60.0.0/24}
    sudo iptables -t nat -D POSTROUTING -s $SUBNET ! -d $SUBNET -o $OAI_IF -j MASQUERADE 2>/dev/null || true
    sudo iptables -t nat -D POSTROUTING -s $SUBNET -o $OAI_IF -j $CPE_NAT_CHAIN 2>/dev/null || true
    sudo iptables -t nat -F $CPE_NAT_CHAIN 2>/dev/null || true
    sudo iptables -t nat -X $CPE_NAT_CHAIN 2>/dev/null || true

    sudo ip addr flush dev $BR_NAME 2>/dev/null || true
    sudo ip link set $BR_NAME down 2>/dev/null || true
    sudo ip link del $BR_NAME 2>/dev/null || true

    echo "[OK] Cleaned up."
}

# =============================================================
# dhcrelay_setup
#   Install and configure dhcrelay if not present
# =============================================================
function setup_dhcrelay() {
    configure_cpe_lan
    if ! command -v dhcrelay >/dev/null 2>&1; then
        echo "[+] Installing isc-dhcp-relay..."
        sudo apt install -y isc-dhcp-relay
    fi

    # Stop auto-start service if it exists (we control it manually)
    sudo systemctl stop isc-dhcp-relay 2>/dev/null || true
    sudo systemctl disable isc-dhcp-relay 2>/dev/null || true

    echo "[OK] dhcrelay ready."
    echo ""
    echo "Next: start xApp DHCP server on $XAPP_IP:"
    echo "  scp xapp_dhcp_server.c ubuntu@$XAPP_IP:~/"
    echo "  ssh ubuntu@$XAPP_IP 'sudo apt install -y libcurl4-openssl-dev && gcc xapp_dhcp_server.c -o xapp_dhcp_server -lcurl'"
    echo "  ssh ubuntu@$XAPP_IP 'sudo ./xapp_dhcp_server'"
    echo ""
    echo "Then: CPE_LAN_ID=$CPE_LAN_ID $0 start 2"
}

# =============================================================
# handback [ns|all]
#   Reverse handover: switch CPE_UE(s) back to CPE path.
#
#   Unlike handover TO RU (needs RACH/RRC/DRB setup), handover BACK
#   only needs to update the routing table:
#     active_path = CPE_UE_PATH_CPE (0)
#   CU-CP re-registers the entry with default active_path=CPE and
#   syncs immediately to CU-UP. Next DL packet already uses CPE path.
#
#   Usage:
#     ./multi_ue_cpe.sh handback          # restore all namespaces
#     ./multi_ue_cpe.sh handback ue1      # restore a specific namespace
# =============================================================
function handback_ue() {
    local TARGET="${1:-all}"
    echo "[HANDBACK] Switching CPE_UE(s) ($TARGET) back to CPE path..."
    handover_register_ue "$TARGET"
    echo "[HANDBACK] Done. active_path=CPE — traffic now routes via CPE host."
}

# =============================================================
# Main dispatcher
# =============================================================
case "$1" in
    start)
        [ -z "$2" ] && { echo "Usage: $0 start <num>"; exit 1; }
        start_ue "$2"
        ;;
    list)
        list_ue
        ;;
    stop)
        stop_ue
        ;;
    setup)
        setup_dhcrelay
        ;;
    handover-register|ho-register|cpe-ho)
        handover_register_ue "${2:-all}"
        ;;
    handback|restore-cpe)
        handback_ue "${2:-all}"
        ;;
    *)
        configure_cpe_lan
        echo "Usage:"
        echo "  $0 setup                         Install dhcrelay"
        echo "  $0 start <num>                   Create UE namespaces (DHCP from CU)"
        echo "  $0 list                          Show UE IPs (192.168.N.x)"
        echo "  $0 stop                          Remove all UE namespaces"
        echo "  $0 handover-register [ns|all]    POST CPE_UE handover entries to CU-CP (HO to RU)"
        echo "  $0 handback          [ns|all]    Switch CPE_UE back to CPE path (no RRC needed)"
        echo "  $0 restore-cpe ue1              # restore a specific CPE_UE to CPE path"
        echo ""
        echo "Flow:"
        echo "  1. sudo $0 setup              # install dhcrelay"
        echo "  2. sudo $0 start 2            # create ue1, ue2 → get IPs from CU DHCP"
        echo "  3. $0 list                    # show 192.168.N.100, 192.168.N.101"
        echo "  4. $0 handover-register all   # register CPE_UEs with CU-CP (active_path=CPE)"
        echo "  5. $0 handback all            # switch back to CPE path (table update only)"
        echo ""
        echo "  curl -s http://$CU_IP:8890/api/cpe_table   # CU-CP table"
        echo "  curl -s http://$CU_IP:8888/cpe_ue/table    # CU-UP table"
        echo ""
        echo "CPE HO env:"
        echo "  CPE_LAN_ID=${CPE_LAN_ID:-auto}       # 10.60.0.x -> 192.168.x.0/24"
        echo "  OAI_IF=$OAI_IF"
        echo "  BR_NAME=${BR_NAME:-auto}"
        echo "  BR_IP=${BR_IP:-auto}"
        echo "  SUBNET=${SUBNET:-auto}"
        echo "  CPE_HO_URL=$CPE_HO_URL"
        echo "  CPE_IMSI_BASE=$CPE_IMSI_BASE"
        echo "  CPE_NAT_PORT_BASE=$CPE_NAT_PORT_BASE"
        echo "  AUTO_CPE_HO_REGISTER=$AUTO_CPE_HO_REGISTER"
        echo "  CPE_TIME_CSV_APPEND=$CPE_TIME_CSV_APPEND"
        echo "  CPE_TIME_RUN_ID=$CPE_TIME_RUN_ID"
        echo "  CPE_DHCP_TIMEOUT_SEC=$CPE_DHCP_TIMEOUT_SEC"
        echo "  CPE_DHCP_CLIENT=$CPE_DHCP_CLIENT       # dhclient (default) | udhcpc (fast)"
        echo "  CPE_DHCP_CAPTURE=$CPE_DHCP_CAPTURE          # 1=measure DISCOVER→ACK on wire | 0=process wall-clock"
        echo "  CPE_DHCP_CAPTURE_IF=${CPE_DHCP_CAPTURE_IF:-auto}   # capture iface (default: namespace veth<N>n)"
        ;;
esac
