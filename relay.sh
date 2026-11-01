#!/bin/sh
set -e
XREG_IP="${XREG_IP:-$(getent hosts wraith-bom.xreg.site | awk '{print $1; exit}')}"
echo "relaying udp/443 -> ${XREG_IP}:443"

sysctl -w net.ipv4.ip_forward=1 || true
sysctl -w net.netfilter.nf_conntrack_udp_timeout=1800 || true
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=1800 || true

iptables -t nat -A PREROUTING  -p udp --dport 443 -j DNAT --to-destination "${XREG_IP}:443"
iptables -t nat -A POSTROUTING -p udp -d "${XREG_IP}" --dport 443 -j MASQUERADE

exec node backend/server.js
