#!/bin/bash
# Start the BNG lab after a reboot: lab wiring (et2500-lab-up.sh) plus the
# bng-lab transient service with PPPoE (CHAP/PAP via RADIUS) and the XDP
# data plane. Stop with: systemctl stop bng-lab.service
set -euo pipefail

# Site settings (RADIUS servers) stay out of git
[ -f /etc/bng/lab.env ] && . /etc/bng/lab.env
: "${RADIUS_SERVERS:?set RADIUS_SERVERS (host:port) in /etc/bng/lab.env}"

bash /root/et2500-lab-up.sh

systemctl stop bng-lab.service 2>/dev/null || true

# Deeper RX rings (default 256 drops ~0.05% at 1 Mpps per port in bursts).
# Set before XDP is attached: resizing reopens the port.
for p in Ethernet12 Ethernet13; do
    ethtool -G "$p" rx 4096
    # Lab only: BNG Blaster session traffic uses UDP port 0, which the NIC
    # parser flags (NIX errcode 0x13) and the driver drops. rx-all passes
    # frames with parse errors on (FCS errors too), so not for production.
    ethtool -K "$p" rx-all on
done
systemctl reset-failed bng-lab.service 2>/dev/null || true

# CGNAT=1 bash /root/bng-lab-start.sh puts PPPoE subscribers behind CGNAT in
# the XDP data plane (lab pool 198.18.0.0/24, RFC 2544 benchmarking space:
# 254 addresses x 63 blocks of 1024 ports)
NAT_ARGS=()
if [ "${CGNAT:-0}" = 1 ]; then
  mkdir -p /var/log/bng
  NAT_ARGS=(--nat-enabled --nat-public-ips 198.18.0.0/24 --nat-ports-per-sub 1024
            --nat-log-enabled --nat-bulk-logging --nat-log-path /var/log/bng/nat.log)
fi
# IPOE_XDP=1: DHCP (IPoE) subscribers are forwarded in XDP too
if [ "${IPOE_XDP:-0}" = 1 ]; then
  NAT_ARGS+=(--ipoe-xdp)
fi
# IPV6=1: dual stack, per-subscriber WAN /64 (SLAAC) and a delegated /64
# (lab prefixes from 2001:db8::/32, documentation space)
if [ "${IPV6:-0}" = 1 ]; then
  NAT_ARGS+=(--ipv6-wan-pool 2001:db8:100::/40 --ipv6-pd-pool 2001:db8:200::/40
             --ipv6-pd-length 64 --ipv6-dns 2001:4860:4860::8888,2001:4860:4860::8844)
fi

# The control plane lives on CPU0 with management; packets on CPUs 1-7
# (et2500-tune.sh below)
systemd-run --unit=bng-lab --working-directory=/root/bng -p CPUAffinity=0 /root/bng/bin/bng run \
  --interface Ethernet12.3001 --xdp-interface Ethernet12 --xdp-mode native \
  --bpf-path /root/bng/bpf/dhcp_fastpath.bpf.o --config /nonexistent \
  --server-ip 100.64.0.1 --pool-network 100.64.0.0/16 --pool-gateway 100.64.0.1 \
  --pool-dns 8.8.8.8,8.8.4.4 --metrics-addr 127.0.0.1:9090 --log-level debug \
  --pppoe-enabled --pppoe-interface Ethernet12.3001 --pppoe-auth-type both \
  --pppoe-xdp-uplinks Ethernet13 --pppoe-bpf-path /root/bng/bpf/pppoe_dataplane.bpf.o \
  --radius-enabled --radius-servers "$RADIUS_SERVERS" --radius-secret-file /etc/bng/radius-secret \
  --radius-acct-interim 5m --coa-enabled --coa-listen :3799 "${NAT_ARGS[@]}"

sleep 3
systemctl is-active bng-lab.service
bash /root/et2500-tune.sh
