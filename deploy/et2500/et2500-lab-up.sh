#!/bin/bash
# ET2500 <-> BNG Blaster lab wiring for the eBPF BNG (non-persistent; gone after reboot).
#   Ethernet12.3001  access (IPoE, VLAN 3001 tagged via switch)  100.64.0.1/16 = subscriber gateway
#   Ethernet13       network (untagged)                          10.0.0.1/24   (Blaster = 10.0.0.2)
#                                                                2001:db8:ffff::1/64 (Blaster = ::2)
# Usage: et2500-lab-up.sh [down]
ACC=Ethernet12
NET=Ethernet13
VID=3001
SUB=$ACC.$VID

lab_rules() {   # $1 = -I or -D
    # Only needed while Docker sets the FORWARD policy to DROP
    command -v iptables > /dev/null || return 0
    iptables "$1" FORWARD -i "$SUB" -o "$NET" -m comment --comment bng-lab -j ACCEPT
    iptables "$1" FORWARD -i "$NET" -o "$SUB" -m comment --comment bng-lab -j ACCEPT
}

if [ "${1:-up}" = down ]; then
    pkill -x bng
    while command -v iptables > /dev/null && iptables -S FORWARD | grep -q bng-lab; do lab_rules -D 2>/dev/null || break; done
    ip link del "$SUB" 2>/dev/null
    ethtool -K "$ACC" rxvlan on
    ip addr flush dev "$NET"
    sysctl -qw net.ipv4.ip_forward=0
    sysctl -qw net.ipv6.conf.all.forwarding=0
    echo "lab down"
    exit 0
fi

set -e
# No IOMMU translation for the two data ports: every packet sent with
# XDP_REDIRECT is DMA-mapped and unmapped, and translation (even lazy) costs
# ~10-40% of the packet CPU. The domain can only change with the driver
# unbound, so this goes first; the interfaces come back with the same names.
for ifc in "$ACC" "$NET"; do
    dev=$(basename "$(readlink "/sys/class/net/$ifc/device")")
    grp="/sys/bus/pci/devices/$dev/iommu_group/type"
    [ "$(cat "$grp")" = identity ] && continue
    echo "$dev" > /sys/bus/pci/drivers/rvu_nicpf/unbind
    echo identity > "$grp"
    echo "$dev" > /sys/bus/pci/drivers/rvu_nicpf/bind
    for i in $(seq 1 50); do [ -e "/sys/class/net/$ifc" ] && break; sleep 0.2; done
done
ip link set "$ACC" up
# Keep VLAN tags in the frame so XDP on the physical port sees them
# (bng run --xdp-interface $ACC); the VLAN subinterface still works.
# rvu_nicpf quirk: after a NIC re-init it keeps stripping tags from unicast
# frames even with rxvlan off; toggling on->off while up clears that.
ethtool -K "$ACC" rxvlan on > /dev/null
ethtool -K "$ACC" rxvlan off > /dev/null
ip link set "$NET" up
ip link show "$SUB" >/dev/null 2>&1 || ip link add link "$ACC" name "$SUB" type vlan id "$VID"
ip link set "$SUB" up
ip addr replace 100.64.0.1/16 dev "$SUB"
ip addr replace 10.0.0.1/24 dev "$NET"
ip -6 addr replace 2001:db8:ffff::1/64 dev "$NET"
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
# Docker sets the FORWARD policy to DROP; allow only the lab path
if command -v iptables > /dev/null; then
    iptables -S FORWARD | grep -q bng-lab || lab_rules -I
fi

echo "--- links"
ip -br link show "$ACC"; ip -br link show "$NET"; ip -br addr show "$SUB"; ip -br addr show "$NET"
for i in "$ACC" "$NET"; do echo "$i: $(ethtool "$i" | grep -E 'Speed|Link detected' | xargs)"; done
echo "ip_forward=$(sysctl -n net.ipv4.ip_forward) ipv6 forwarding=$(sysctl -n net.ipv6.conf.all.forwarding)"
command -v iptables > /dev/null && iptables -S FORWARD | grep bng-lab || true
