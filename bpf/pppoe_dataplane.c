/* PPPoE Data Plane - XDP Programs
 *
 * pppoe_upstream: tail-called from dhcp_fastpath_prog on the access port for
 * PPPoE session frames (EtherType 0x8864). IPv4 from a known session is
 * decapsulated and either
 *   - redirected straight to an uplink (XDP_REDIRECT) when the FIB has a
 *     route and neighbour for it and the uplink is in pppoe_tx_ports, or
 *   - handed to the kernel as a plain (VLAN-tagged) IPv4 frame, which then
 *     arrives on the VLAN subinterface and is routed normally. This covers
 *     unresolved neighbours, local destinations, TTL expiry and MTU issues.
 * Control traffic (LCP, PAP/CHAP, IPCP, ...) and unknown sessions go to
 * userspace unchanged.
 *
 * pppoe_downstream: attached to uplink ports. IPv4 addressed to a session is
 * encapsulated in PPPoE (+ 802.1Q tag) and redirected to the access port.
 *
 * Supports untagged and single-tagged (802.1Q / 802.1ad) access ports.
 * QinQ and uplink-side VLANs are left to the kernel.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_PPP_SES 0x8864
#define PPP_IP        0x0021

#define VLAN_VID_MASK 0x0FFF
#define MAX_PPPOE_SESSIONS 65536

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

/* PPPoE session header followed by the PPP protocol field */
struct pppoe_hdr {
	__u8   ver_type;   /* 0x11 */
	__u8   code;       /* 0 for session data */
	__be16 session_id;
	__be16 length;     /* PPP protocol + payload */
	__be16 ppp_proto;
} __attribute__((packed));

/* ========================================================================
 * Maps (filled by pkg/ebpf/pppoe.go)
 * ======================================================================== */

/* Upstream: (client MAC, session ID, VLAN) -> session */
struct pppoe_up_key {
	__u8   client_mac[ETH_ALEN];
	__be16 session_id;
	__u16  vlan_id;      /* outer VLAN ID as seen on the access port, 0 = untagged */
	__u16  _pad;
};

struct pppoe_up_val {
	__be32 client_ip;    /* only this source address is accepted */
	__u32  fib_ifindex;  /* L3 interface the session lives on, for FIB lookups */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, struct pppoe_up_key);
	__type(value, struct pppoe_up_val);
} pppoe_up SEC(".maps");

/* Downstream: client IPv4 -> session */
struct pppoe_down_val {
	__u8   client_mac[ETH_ALEN];
	__u8   server_mac[ETH_ALEN];
	__be16 session_id;
	__u16  vlan_id;      /* 0 = untagged */
	__u32  tx_ifindex;   /* access port */
	__u16  mru;          /* peer MRU: largest PPP payload the client accepts */
	__u16  _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, __be32);
	__type(value, struct pppoe_down_val);
} pppoe_down SEC(".maps");

/* Uplinks that may receive XDP_REDIRECT (they run pppoe_downstream in
 * driver mode, so their driver has XDP transmit queues set up) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} pppoe_tx_ports SEC(".maps");

/* Statistics (indices must match pkg/ebpf/pppoe.go) */
enum {
	PPPOE_STAT_UP_REDIRECT = 0,  /* decapsulated, redirected to an uplink */
	PPPOE_STAT_UP_KERNEL,        /* decapsulated, passed to the kernel */
	PPPOE_STAT_UP_CONTROL,       /* non-IPv4 PPP, passed to userspace */
	PPPOE_STAT_UP_NO_SESSION,    /* unknown session, passed to userspace */
	PPPOE_STAT_UP_SPOOFED,       /* wrong source address, dropped */
	PPPOE_STAT_DOWN_REDIRECT,    /* encapsulated, redirected to access */
	PPPOE_STAT_DOWN_TOO_BIG,     /* larger than the peer MRU, dropped */
	PPPOE_STAT_DOWN_KERNEL,      /* TTL expiring, passed to the kernel */
	PPPOE_STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PPPOE_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} pppoe_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&pppoe_stats, &idx);
	if (v)
		*v += 1;
}

/* RFC 1624 incremental checksum update for a TTL decrement */
static __always_inline void ip_decrease_ttl(struct iphdr *ip)
{
	__u32 check = (__u32)ip->check;
	check += (__u32)bpf_htons(0x0100);
	ip->check = (__sum16)(check + (check >= 0xFFFF));
	ip->ttl--;
}

/* ========================================================================
 * Upstream (access port, tail-called from dhcp_fastpath_prog)
 * ======================================================================== */

/* l2_len is a compile-time constant at each call site (14 or 18), which
 * keeps every packet offset below constant for the verifier. */
static __always_inline int handle_upstream(struct xdp_md *ctx, const __u32 l2_len, __u16 vlan_id)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	struct pppoe_hdr *ph = data + l2_len;
	if ((void *)(ph + 1) > data_end)
		return XDP_PASS;
	if (ph->ver_type != 0x11 || ph->code != 0)
		return XDP_PASS;
	if (ph->ppp_proto != bpf_htons(PPP_IP)) {
		stat_inc(PPPOE_STAT_UP_CONTROL);
		return XDP_PASS;
	}

	struct pppoe_up_key key = {
		.session_id = ph->session_id,
		.vlan_id = vlan_id,
	};
	__builtin_memcpy(key.client_mac, eth->h_source, ETH_ALEN);

	struct pppoe_up_val *sess = bpf_map_lookup_elem(&pppoe_up, &key);
	if (!sess) {
		stat_inc(PPPOE_STAT_UP_NO_SESSION);
		return XDP_PASS;
	}

	struct iphdr *ip = (void *)(ph + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_DROP;
	if (ip->version != 4 || ip->saddr != sess->client_ip) {
		stat_inc(PPPOE_STAT_UP_SPOOFED);
		return XDP_DROP;
	}

	/* Fast forwarding: route lookup in the kernel FIB */
	struct bpf_fib_lookup fib = {};
	int redirect = 0;
	if (ip->ttl > 1) {
		fib.family = AF_INET;
		fib.tos = ip->tos;
		fib.l4_protocol = ip->protocol;
		fib.tot_len = bpf_ntohs(ip->tot_len);
		fib.ipv4_src = ip->saddr;
		fib.ipv4_dst = ip->daddr;
		fib.ifindex = sess->fib_ifindex;

		if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) == BPF_FIB_LKUP_RET_SUCCESS &&
		    bpf_map_lookup_elem(&pppoe_tx_ports, &fib.ifindex))
			redirect = 1;
	}

	if (redirect) {
		ip_decrease_ttl(ip);

		/* Drop L2 + PPPoE and write a fresh Ethernet header for the uplink */
		if (bpf_xdp_adjust_head(ctx, (int)(l2_len + sizeof(struct pppoe_hdr) - sizeof(struct ethhdr))))
			return XDP_DROP;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return XDP_DROP;
		__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
		eth->h_proto = bpf_htons(ETH_P_IP);

		stat_inc(PPPOE_STAT_UP_REDIRECT);
		return bpf_redirect(fib.ifindex, 0);
	}

	/* Kernel path: keep Ethernet (+ VLAN) header, drop PPPoE/PPP */
	__u8 l2[sizeof(struct ethhdr) + sizeof(struct vlan_hdr)];
	if ((void *)eth + l2_len > data_end)
		return XDP_PASS;
	__builtin_memcpy(l2, eth, l2_len);

	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct pppoe_hdr)))
		return XDP_DROP;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + l2_len > data_end)
		return XDP_DROP;
	__builtin_memcpy(data, l2, l2_len);
	/* The EtherType just before the IP header becomes IPv4 */
	*(__be16 *)(data + l2_len - 2) = bpf_htons(ETH_P_IP);

	stat_inc(PPPOE_STAT_UP_KERNEL);
	return XDP_PASS;
}

SEC("xdp")
int pppoe_upstream(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_PPP_SES))
		return handle_upstream(ctx, sizeof(struct ethhdr), 0);

	if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;
		if (vh->h_vlan_encapsulated_proto == bpf_htons(ETH_P_PPP_SES))
			return handle_upstream(ctx, sizeof(struct ethhdr) + sizeof(struct vlan_hdr),
			                       bpf_ntohs(vh->h_vlan_TCI) & VLAN_VID_MASK);
	}

	return XDP_PASS;
}

/* ========================================================================
 * Downstream (uplink ports)
 * ======================================================================== */

/* tagged is a compile-time constant at each call site, so the headroom
 * grown in front of the existing Ethernet header (VLAN tag + PPPoE/PPP) is
 * constant too. */
static __always_inline int handle_downstream(struct xdp_md *ctx, struct pppoe_down_val *sess,
                                             __u16 ip_len, const int tagged)
{
	const int grow = (tagged ? sizeof(struct vlan_hdr) : 0) + sizeof(struct pppoe_hdr);

	if (bpf_xdp_adjust_head(ctx, -grow))
		return XDP_DROP;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct pppoe_hdr *ph = (void *)(eth + 1) + (tagged ? sizeof(struct vlan_hdr) : 0);
	if ((void *)(ph + 1) > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_dest, sess->client_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, sess->server_mac, ETH_ALEN);
	if (tagged) {
		struct vlan_hdr *vh = (void *)(eth + 1);
		eth->h_proto = bpf_htons(ETH_P_8021Q);
		vh->h_vlan_TCI = bpf_htons(sess->vlan_id & VLAN_VID_MASK);
		vh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_PPP_SES);
	} else {
		eth->h_proto = bpf_htons(ETH_P_PPP_SES);
	}

	ph->ver_type = 0x11;
	ph->code = 0;
	ph->session_id = sess->session_id;
	ph->length = bpf_htons(ip_len + 2);
	ph->ppp_proto = bpf_htons(PPP_IP);

	stat_inc(PPPOE_STAT_DOWN_REDIRECT);
	return bpf_redirect(sess->tx_ifindex, 0);
}

SEC("xdp")
int pppoe_downstream(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	__be32 daddr = ip->daddr;
	struct pppoe_down_val *sess = bpf_map_lookup_elem(&pppoe_down, &daddr);
	if (!sess)
		return XDP_PASS;

	/* Let the kernel answer with ICMP Time Exceeded */
	if (ip->ttl <= 1) {
		stat_inc(PPPOE_STAT_DOWN_KERNEL);
		return XDP_PASS;
	}

	__u16 ip_len = bpf_ntohs(ip->tot_len);
	if (ip_len > sess->mru) {
		stat_inc(PPPOE_STAT_DOWN_TOO_BIG);
		return XDP_DROP;
	}

	ip_decrease_ttl(ip);

	if (sess->vlan_id)
		return handle_downstream(ctx, sess, ip_len, 1);
	return handle_downstream(ctx, sess, ip_len, 0);
}

char _license[] SEC("license") = "GPL";
