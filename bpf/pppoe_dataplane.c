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
 * ipoe_upstream: tail-called from dhcp_fastpath_prog for IPv4 that is not a
 * DHCP request. IPoE subscribers (DHCP leases) are forwarded like PPPoE
 * sessions, minus the PPPoE header; pppoe_downstream handles both.
 *
 * Subscribers with a CGNAT port block (nat_subs) are translated on the way:
 * see the CGNAT section below.
 *
 * IPv6 (dual stack) follows the same paths. A subscriber owns prefixes
 * (WAN /64, delegated prefix) in sub6, which checks their source address
 * upstream and finds them downstream; IPv6 control traffic (link-local or
 * multicast: RS, DHCPv6, ND) goes to userspace unchanged. Counters and rate
 * limits are shared with the subscriber's IPv4.
 *
 * Supports untagged and single-tagged (802.1Q / 802.1ad) access ports.
 * QinQ and uplink-side VLANs are left to the kernel.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#define NSEC_PER_SEC 1000000000ULL

#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_PPP_SES 0x8864
#define PPP_IP        0x0021
#define PPP_IPV6      0x0057

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
	__u16  mru;          /* peer MRU: largest PPP payload the client accepts
	                      * (IPoE: the access MTU) */
	__u16  flags;        /* DOWN_F_* */
};

#define DOWN_F_IPOE 0x0001   /* IPoE subscriber: Ethernet (+ VLAN), no PPPoE */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, __be32);
	__type(value, struct pppoe_down_val);
} pppoe_down SEC(".maps");

/* Data plane settings (single entry, set by userspace) */
#define DP_F_IPOE_LEASE_ONLY 0x0001  /* IPv4 from hosts without a lease only
                                      * reaches nat_bypass destinations */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} dp_flags SEC(".maps");

static __always_inline int dp_flag(__u32 flag)
{
	__u32 key = 0;
	__u32 *v = bpf_map_lookup_elem(&dp_flags, &key);
	return v && (*v & flag);
}

/* IPoE upstream: (client MAC, VLAN) -> subscriber; reuses pppoe_up_val */
struct ipoe_up_key {
	__u8  client_mac[ETH_ALEN];
	__u16 vlan_id;       /* outer VLAN ID on the access port, 0 = untagged */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, struct ipoe_up_key);
	__type(value, struct pppoe_up_val);
} ipoe_up SEC(".maps");

/* IPv6 prefixes of subscribers -> their IPv4 address (the key of
 * pppoe_down, pppoe_policy and pppoe_sess_stats) */
struct sub6_key {
	__u32 prefixlen;
	__u8  addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 2 * MAX_PPPOE_SESSIONS);
	__type(key, struct sub6_key);
	__type(value, __be32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sub6 SEC(".maps");

static __always_inline __be32 *sub6_owner(const struct in6_addr *addr)
{
	struct sub6_key k = { .prefixlen = 128 };
	__builtin_memcpy(k.addr, addr, 16);
	return bpf_map_lookup_elem(&sub6, &k);
}

/* Link-local or multicast destination, or link-local source: for the
 * BNG's control plane (RS, DHCPv6, ND), not to be forwarded */
static __always_inline int ipv6_is_control(const struct ipv6hdr *ip6)
{
	const __u8 *d = ip6->daddr.in6_u.u6_addr8;
	const __u8 *s = ip6->saddr.in6_u.u6_addr8;
	return d[0] == 0xff || (d[0] == 0xfe && (d[1] & 0xc0) == 0x80) ||
	       (s[0] == 0xfe && (s[1] & 0xc0) == 0x80);
}

/* Per-session rate limits (RADIUS / CoA): client IPv4 -> policy.
 * Rates are bytes per second, 0 = unlimited. Only userspace writes this
 * map, so a CoA never races with the counters below. */
struct pppoe_policy {
	__u64 up_rate;       /* from the client */
	__u64 down_rate;     /* to the client */
	__u32 up_burst;      /* bucket size, bytes */
	__u32 down_burst;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, __be32);
	__type(value, struct pppoe_policy);
} pppoe_policy SEC(".maps");

/* Per-session counters (RADIUS accounting) and policer state: client IPv4 ->
 * stats. Userspace creates a zeroed entry when the session comes up and only
 * reads it afterwards. The token buckets are under a spin lock because one
 * session's flows can be spread over several CPUs. */
struct pppoe_sess_stats {
	struct bpf_spin_lock lock;
	__u32 _pad;
	__u64 up_tokens;
	__u64 up_last_ns;
	__u64 down_tokens;
	__u64 down_last_ns;
	__u64 up_packets;    /* forwarded from the client */
	__u64 up_bytes;      /* IP bytes */
	__u64 down_packets;  /* forwarded to the client */
	__u64 down_bytes;
	__u64 up_dropped;    /* over the rate limit */
	__u64 down_dropped;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, __be32);
	__type(value, struct pppoe_sess_stats);
} pppoe_sess_stats SEC(".maps");

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
	PPPOE_STAT_UP_POLICED,       /* over the session's upload limit, dropped */
	PPPOE_STAT_DOWN_POLICED,     /* over the session's download limit, dropped */
	PPPOE_STAT_NAT_OUT,          /* source translated to a public address */
	PPPOE_STAT_NAT_IN,           /* destination translated to a subscriber */
	PPPOE_STAT_NAT_NEW,          /* mappings created */
	PPPOE_STAT_NAT_EXHAUSTED,    /* no free port in the block, dropped */
	PPPOE_STAT_NAT_NO_MAPPING,   /* to a public address without a mapping, dropped */
	PPPOE_STAT_NAT_UNSUPPORTED,  /* IP options, protocol or ICMP type not translated, dropped */
	PPPOE_STAT_NAT_FRAG_MISS,    /* fragment ahead of its first fragment, dropped */
	PPPOE_STAT_NAT_ICMP_ERROR,   /* ICMP errors translated (counted in nat_in too) */
	PPPOE_STAT_IPOE_UP_REDIRECT, /* IPoE, redirected to an uplink */
	PPPOE_STAT_IPOE_UP_KERNEL,   /* IPoE, passed to the kernel */
	PPPOE_STAT_IPOE_UP_NO_SESSION, /* IPoE from an unknown MAC/VLAN, passed to the kernel */
	PPPOE_STAT_IPOE_UP_SPOOFED,  /* IPoE with a wrong source address, dropped */
	PPPOE_STAT_IPOE_DOWN_REDIRECT, /* to an IPoE subscriber, redirected to access */
	PPPOE_STAT_IPOE_UP_UNLEASED, /* IPoE without a lease to a forwarded destination, dropped */
	PPPOE_STAT_UP6_REDIRECT,     /* IPv6 from a subscriber, redirected to an uplink */
	PPPOE_STAT_UP6_KERNEL,       /* IPv6 from a subscriber, passed to the kernel */
	PPPOE_STAT_UP6_CONTROL,      /* IPv6 control (link-local/multicast), to userspace */
	PPPOE_STAT_UP6_SPOOFED,      /* IPv6 from outside the subscriber's prefixes, dropped */
	PPPOE_STAT_DOWN6_REDIRECT,   /* IPv6 to a subscriber, redirected to access */
	PPPOE_STAT_DOWN6_TOO_BIG,    /* IPv6 larger than the peer MRU/MTU, dropped */
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

/* Token bucket in bytes. Returns 1 if a packet of len bytes conforms. The
 * refill interval is capped at one second, which bounds elapsed * rate well
 * inside 64 bits up to 100 Gbit/s. */
static __always_inline int police(struct pppoe_sess_stats *st, __u64 *tokens, __u64 *last,
                                  __u64 rate, __u32 burst, __u32 len, __u64 now)
{
	int ok = 0;

	bpf_spin_lock(&st->lock);
	__u64 elapsed = now - *last;
	if (elapsed > NSEC_PER_SEC)
		elapsed = NSEC_PER_SEC;
	__u64 t = *tokens + elapsed * rate / NSEC_PER_SEC;
	if (t > burst)
		t = burst;
	if (t >= len) {
		t -= len;
		ok = 1;
	}
	*tokens = t;
	*last = now;
	bpf_spin_unlock(&st->lock);
	return ok;
}

/* Rate limit and count one IPv4 packet of a session. up is a compile-time
 * constant at each call site. Returns 0 if the packet must be dropped. */
static __always_inline int session_account(__be32 client_ip, const int up, __u32 len)
{
	struct pppoe_sess_stats *st = bpf_map_lookup_elem(&pppoe_sess_stats, &client_ip);
	if (!st)
		return 1;

	struct pppoe_policy *pol = bpf_map_lookup_elem(&pppoe_policy, &client_ip);
	if (pol) {
		__u64 rate = up ? pol->up_rate : pol->down_rate;
		if (rate) {
			__u64 now = bpf_ktime_get_ns();
			int ok = up ? police(st, &st->up_tokens, &st->up_last_ns, rate, pol->up_burst, len, now)
			            : police(st, &st->down_tokens, &st->down_last_ns, rate, pol->down_burst, len, now);
			if (!ok) {
				__sync_fetch_and_add(up ? &st->up_dropped : &st->down_dropped, 1);
				return 0;
			}
		}
	}

	if (up) {
		__sync_fetch_and_add(&st->up_packets, 1);
		__sync_fetch_and_add(&st->up_bytes, len);
	} else {
		__sync_fetch_and_add(&st->down_packets, 1);
		__sync_fetch_and_add(&st->down_bytes, len);
	}
	return 1;
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
 * CGNAT (NAT44, RFC 6888) for sessions with a private address
 *
 * Endpoint-independent mapping and filtering (RFC 4787, RFC 5382): a
 * subscriber's (address, port, protocol) maps to one public port, used for
 * every destination, and anyone may send back to it. Each subscriber owns a
 * block of ports on one public address (port block allocation; userspace
 * assigns and logs the blocks), and mappings are created here from that
 * block. ICMP echo uses the identifier as its port.
 *
 * Mappings carry the generation of the block they were made from. When a
 * session ends only its nat_subs entry goes, which makes its mappings stale:
 * they are never used again, are replaced as soon as their port or private
 * address is reused, and are deleted by the userspace sweep along with idle
 * mappings.
 * ======================================================================== */

#define NAT_MAPPINGS  (1 << 20)  /* default size, userspace can change it */
#define NAT_FRAGMENTS 65536
#define NAT_PROBES    128        /* ports tried for a new mapping */

#define NAT_F_FIN 0x01           /* TCP FIN or RST seen: short timeout */

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

#define CSUM_MANGLED_0 ((__sum16)0xffff)

/* Subscriber (private IPv4) -> port block */
struct nat_sub {
	__be32 public_ip;
	__u16  port_start;   /* host byte order */
	__u16  port_count;
	__u32  gen;          /* block generation, never 0 */
	__u32  _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PPPOE_SESSIONS);
	__type(key, __be32);
	__type(value, struct nat_sub);
} nat_subs SEC(".maps");

/* nat_out: (private address, port, protocol); nat_in: (public address,
 * port, protocol) */
struct nat_key {
	__be32 addr;
	__be16 port;
	__u8   proto;
	__u8   _pad;
};

/* The other side of a mapping: nat_out holds the public address and port,
 * nat_in the private ones */
struct nat_mapping {
	__be32 addr;
	__be16 port;
	__u8   flags;
	__u8   _pad;
	__u32  gen;
	__u32  _pad2;
	__u64  last_seen;    /* bpf_ktime_get_ns() of the last packet this way, 0 = none */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NAT_MAPPINGS);
	__type(key, struct nat_key);
	__type(value, struct nat_mapping);
} nat_out SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NAT_MAPPINGS);
	__type(key, struct nat_key);
	__type(value, struct nat_mapping);
} nat_in SEC(".maps");

/* Public addresses of the pool: traffic to them that has no mapping is
 * dropped instead of being routed back out */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32);
	__type(value, __u32);
} nat_pool_ips SEC(".maps");

/* Destinations reached without translation: the subscribers' own pools
 * (gateway, other subscribers) and whatever else userspace adds */
struct nat_bypass_key {
	__u32  prefixlen;
	__be32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct nat_bypass_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} nat_bypass SEC(".maps");

static __always_inline int nat_bypassed(__be32 daddr)
{
	struct nat_bypass_key k = { .prefixlen = 32, .addr = daddr };
	return bpf_map_lookup_elem(&nat_bypass, &k) != NULL;
}

/* Fragments after the first carry no ports: they follow the address the
 * first fragment was translated to. dir 0 = upstream, 1 = downstream. */
struct nat_frag_key {
	__be32 saddr;
	__be32 daddr;
	__be16 id;
	__u8   proto;
	__u8   dir;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, NAT_FRAGMENTS);
	__type(key, struct nat_frag_key);
	__type(value, __be32);
} nat_frags SEC(".maps");

/* RFC 1624 incremental checksum update: HC' = ~(~HC + ~m + m') */
static __always_inline __sum16 csum_fold32(__u32 s)
{
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__sum16)~s;
}

static __always_inline void csum_replace2(__sum16 *sum, __be16 from, __be16 to)
{
	*sum = csum_fold32((__u16)~*sum + (__u16)~from + (__u32)to);
}

static __always_inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__u32 s = (__u16)~*sum;
	s += (__u16)~(from >> 16) + (__u16)~(from & 0xffff);
	s += (to >> 16) + (to & 0xffff);
	*sum = csum_fold32(s);
}

/* A mapping is usable while its subscriber still holds the same block */
static __always_inline int nat_live(__be32 priv_ip, __u32 gen)
{
	struct nat_sub *ns = bpf_map_lookup_elem(&nat_subs, &priv_ip);
	return ns && ns->gen == gen;
}

static __always_inline void nat_touch(struct nat_mapping *m, __u64 now, int fin, int syn)
{
	/* Only write when needed: the entry is shared between CPUs */
	if (now - m->last_seen > NSEC_PER_SEC)
		m->last_seen = now;
	if (fin && !(m->flags & NAT_F_FIN))
		m->flags |= NAT_F_FIN;
	else if (syn && (m->flags & NAT_F_FIN))
		m->flags &= ~NAT_F_FIN;
}

struct nat_alloc {
	struct nat_key key;       /* public side; the port is being chosen */
	struct nat_mapping val;   /* private side */
	__u32 start;
	__u32 count;
	__u32 first;
	__u32 found;
};

/* bpf_loop callback: try to claim port number i of the probe sequence.
 * BPF_NOEXIST makes the claim atomic between CPUs. */
static int nat_try_port(__u32 i, void *data)
{
	struct nat_alloc *a = data;

	if (!a->count)
		return 1;
	a->key.port = bpf_htons((__u16)(a->start + (a->first + i) % a->count));
	if (!bpf_map_update_elem(&nat_in, &a->key, &a->val, BPF_NOEXIST)) {
		a->found = 1;
		return 1;
	}
	struct nat_mapping *old = bpf_map_lookup_elem(&nat_in, &a->key);
	if (old && !nat_live(old->addr, old->gen)) {
		bpf_map_delete_elem(&nat_in, &a->key);
		if (!bpf_map_update_elem(&nat_in, &a->key, &a->val, BPF_NOEXIST)) {
			a->found = 1;
			return 1;
		}
	}
	return 0;
}

/* Create the mapping for a private (address, port, protocol). The probe
 * starts where the private port falls in the block, so a subscriber keeps
 * its port numbers when the block allows. */
static __always_inline struct nat_mapping *nat_create(struct nat_sub *ns, struct nat_key *ok, __u64 now)
{
	struct nat_alloc a = {
		.key = { .addr = ns->public_ip, .proto = ok->proto },
		.val = { .addr = ok->addr, .port = ok->port, .gen = ns->gen },
		.start = ns->port_start,
		.count = ns->port_count,
	};
	if (!a.count)
		return NULL;
	a.first = bpf_ntohs(ok->port) % a.count;
	bpf_loop(a.count < NAT_PROBES ? a.count : NAT_PROBES, nat_try_port, &a, 0);
	if (!a.found)
		return NULL;

	struct nat_mapping out = {
		.addr = ns->public_ip,
		.port = a.key.port,
		.gen = ns->gen,
		.last_seen = now,
	};
	if (bpf_map_update_elem(&nat_out, ok, &out, BPF_NOEXIST)) {
		/* Another CPU mapped the same source first (or the map is full) */
		bpf_map_delete_elem(&nat_in, &a.key);
		struct nat_mapping *m = bpf_map_lookup_elem(&nat_out, ok);
		return m && m->gen == ns->gen ? m : NULL;
	}
	stat_inc(PPPOE_STAT_NAT_NEW);
	return bpf_map_lookup_elem(&nat_out, ok);
}

/* Source NAT for a packet from subscriber ns, whose IPv4 header is at ip_off
 * (a compile-time constant at the call site). Returns 0 to forward the
 * translated packet, -1 to drop it. */
static __always_inline int nat_upstream(struct xdp_md *ctx, const __u32 ip_off, struct nat_sub *ns)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip = data + ip_off;
	if ((void *)(ip + 1) > data_end)
		return -1;
	if (ip->ihl != 5) {
		stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
		return -1;
	}

	__be32 priv = ip->saddr;
	__u16 frag = bpf_ntohs(ip->frag_off);
	if (frag & IP_OFFSET) {
		struct nat_frag_key fk = {
			.saddr = priv, .daddr = ip->daddr, .id = ip->id, .proto = ip->protocol, .dir = 0,
		};
		__be32 *pub = bpf_map_lookup_elem(&nat_frags, &fk);
		if (!pub) {
			stat_inc(PPPOE_STAT_NAT_FRAG_MISS);
			return -1;
		}
		ip->saddr = *pub;
		csum_replace4(&ip->check, priv, *pub);
		stat_inc(PPPOE_STAT_NAT_OUT);
		return 0;
	}

	struct nat_key ok = { .addr = priv, .proto = ip->protocol };
	int fin = 0, syn = 0;
	void *l4 = ip + 1;
	switch (ip->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *th = l4;
		if ((void *)(th + 1) > data_end)
			return -1;
		ok.port = th->source;
		fin = th->fin | th->rst;
		syn = th->syn & !th->ack;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *uh = l4;
		if ((void *)(uh + 1) > data_end)
			return -1;
		ok.port = uh->source;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *ih = l4;
		if ((void *)(ih + 1) > data_end)
			return -1;
		if (ih->type != ICMP_ECHO) {
			stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
			return -1;
		}
		ok.port = ih->un.echo.id;
		break;
	}
	default:
		stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
		return -1;
	}
	__u8 proto = ok.proto;
	__be16 more = ip->frag_off & bpf_htons(IP_MF);
	__be32 daddr = ip->daddr;
	__be16 id = ip->id;

	__u64 now = bpf_ktime_get_ns();
	struct nat_mapping *m = bpf_map_lookup_elem(&nat_out, &ok);
	if (m && m->gen != ns->gen) {
		bpf_map_delete_elem(&nat_out, &ok);
		m = NULL;
	}
	if (!m)
		m = nat_create(ns, &ok, now);
	if (!m) {
		stat_inc(PPPOE_STAT_NAT_EXHAUSTED);
		return -1;
	}
	nat_touch(m, now, fin, syn);
	__be32 pub = m->addr;
	__be16 pub_port = m->port;

	if (more) {
		struct nat_frag_key fk = { .saddr = priv, .daddr = daddr, .id = id, .proto = proto, .dir = 0 };
		bpf_map_update_elem(&nat_frags, &fk, &pub, BPF_ANY);
	}

	/* Packet pointers again: nat_create ran a callback */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip = data + ip_off;
	if ((void *)(ip + 1) > data_end)
		return -1;
	l4 = ip + 1;
	ip->saddr = pub;
	csum_replace4(&ip->check, priv, pub);

	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = l4;
		if ((void *)(th + 1) > data_end)
			return -1;
		csum_replace4(&th->check, priv, pub);
		csum_replace2(&th->check, th->source, pub_port);
		th->source = pub_port;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = l4;
		if ((void *)(uh + 1) > data_end)
			return -1;
		if (uh->check) {
			csum_replace4(&uh->check, priv, pub);
			csum_replace2(&uh->check, uh->source, pub_port);
			if (!uh->check)
				uh->check = CSUM_MANGLED_0;
		}
		uh->source = pub_port;
	} else {
		struct icmphdr *ih = l4;
		if ((void *)(ih + 1) > data_end)
			return -1;
		csum_replace2(&ih->checksum, ih->un.echo.id, pub_port);
		ih->un.echo.id = pub_port;
	}
	stat_inc(PPPOE_STAT_NAT_OUT);
	return 0;
}

/* Find the live mapping for a public (address, port, protocol) */
static __always_inline struct nat_mapping *nat_lookup_in(__be32 addr, __be16 port, __u8 proto)
{
	struct nat_key ik = { .addr = addr, .port = port, .proto = proto };
	struct nat_mapping *m = bpf_map_lookup_elem(&nat_in, &ik);
	if (m && !nat_live(m->addr, m->gen))
		return NULL;
	return m;
}

/* An ICMP error about a packet we translated on the way out: the quoted
 * packet has the public source, which goes back to the private one along
 * with the outer destination (RFC 5508). Checksums of the quoted headers are
 * kept valid where they are inside the packet. */
static __always_inline int nat_icmp_error(struct iphdr *ip, struct icmphdr *ih, void *data_end)
{
	struct iphdr *inner = (void *)(ih + 1);
	if ((void *)(inner + 1) > data_end)
		return -1;
	if (inner->ihl != 5 || inner->saddr != ip->daddr) {
		stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
		return -1;
	}
	void *l4 = inner + 1;
	if (l4 + 8 > data_end)
		return -1;

	__be16 *portp;
	__sum16 *l4sum = NULL;
	int pseudo = 1;
	switch (inner->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *th = l4;
		portp = &th->source;
		if ((void *)(th + 1) <= data_end)
			l4sum = &th->check;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *uh = l4;
		portp = &uh->source;
		if (uh->check)
			l4sum = &uh->check;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *qh = l4;
		if (qh->type != ICMP_ECHO) {
			stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
			return -1;
		}
		portp = &qh->un.echo.id;
		l4sum = &qh->checksum;
		pseudo = 0;
		break;
	}
	default:
		stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
		return -1;
	}

	__be32 pub = inner->saddr;
	__be16 pub_port = *portp;
	struct nat_mapping *m = nat_lookup_in(pub, pub_port, inner->protocol);
	if (!m) {
		stat_inc(PPPOE_STAT_NAT_NO_MAPPING);
		return -1;
	}
	__be32 priv = m->addr;
	__be16 priv_port = m->port;

	/* Quoted L4 header; the ICMP checksum covers it */
	if (l4sum) {
		__sum16 old = *l4sum;
		if (pseudo)
			csum_replace4(l4sum, pub, priv);
		csum_replace2(l4sum, pub_port, priv_port);
		if (inner->protocol == IPPROTO_UDP && !*l4sum)
			*l4sum = CSUM_MANGLED_0;
		csum_replace2(&ih->checksum, old, *l4sum);
	}
	*portp = priv_port;
	csum_replace2(&ih->checksum, pub_port, priv_port);

	/* Quoted IP header */
	__sum16 old = inner->check;
	inner->saddr = priv;
	csum_replace4(&inner->check, pub, priv);
	csum_replace4(&ih->checksum, pub, priv);
	csum_replace2(&ih->checksum, old, inner->check);

	/* Outer header */
	ip->daddr = priv;
	csum_replace4(&ip->check, pub, priv);
	stat_inc(PPPOE_STAT_NAT_ICMP_ERROR);
	return 0;
}

/* Destination NAT for a packet to a pool address, IPv4 header at ip_off.
 * Returns 0 once the destination is the subscriber's, -1 to drop. */
static __always_inline int nat_downstream(struct xdp_md *ctx, const __u32 ip_off)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip = data + ip_off;
	if ((void *)(ip + 1) > data_end)
		return -1;
	if (ip->ihl != 5) {
		stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
		return -1;
	}

	__be32 pub = ip->daddr;
	__u16 frag = bpf_ntohs(ip->frag_off);
	if (frag & IP_OFFSET) {
		struct nat_frag_key fk = {
			.saddr = ip->saddr, .daddr = pub, .id = ip->id, .proto = ip->protocol, .dir = 1,
		};
		__be32 *priv = bpf_map_lookup_elem(&nat_frags, &fk);
		if (!priv) {
			stat_inc(PPPOE_STAT_NAT_FRAG_MISS);
			return -1;
		}
		ip->daddr = *priv;
		csum_replace4(&ip->check, pub, *priv);
		stat_inc(PPPOE_STAT_NAT_IN);
		return 0;
	}

	void *l4 = ip + 1;
	__be16 *portp;
	__sum16 *l4sum = NULL;
	int pseudo = 1, fin = 0;
	switch (ip->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *th = l4;
		if ((void *)(th + 1) > data_end)
			return -1;
		portp = &th->dest;
		l4sum = &th->check;
		fin = th->fin | th->rst;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *uh = l4;
		if ((void *)(uh + 1) > data_end)
			return -1;
		portp = &uh->dest;
		if (uh->check)
			l4sum = &uh->check;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *ih = l4;
		if ((void *)(ih + 1) > data_end)
			return -1;
		if (ih->type == ICMP_DEST_UNREACH || ih->type == ICMP_TIME_EXCEEDED ||
		    ih->type == ICMP_PARAMETERPROB) {
			if (nat_icmp_error(ip, ih, data_end))
				return -1;
			stat_inc(PPPOE_STAT_NAT_IN);
			return 0;
		}
		if (ih->type != ICMP_ECHOREPLY) {
			stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
			return -1;
		}
		portp = &ih->un.echo.id;
		l4sum = &ih->checksum;
		pseudo = 0;
		break;
	}
	default:
		stat_inc(PPPOE_STAT_NAT_UNSUPPORTED);
		return -1;
	}

	__be16 pub_port = *portp;
	struct nat_mapping *m = nat_lookup_in(pub, pub_port, ip->protocol);
	if (!m) {
		stat_inc(PPPOE_STAT_NAT_NO_MAPPING);
		return -1;
	}
	nat_touch(m, bpf_ktime_get_ns(), fin, 0);
	__be32 priv = m->addr;
	__be16 priv_port = m->port;

	if (ip->frag_off & bpf_htons(IP_MF)) {
		struct nat_frag_key fk = {
			.saddr = ip->saddr, .daddr = pub, .id = ip->id, .proto = ip->protocol, .dir = 1,
		};
		bpf_map_update_elem(&nat_frags, &fk, &priv, BPF_ANY);
	}

	if (l4sum) {
		if (pseudo)
			csum_replace4(l4sum, pub, priv);
		csum_replace2(l4sum, pub_port, priv_port);
		if (ip->protocol == IPPROTO_UDP && !*l4sum)
			*l4sum = CSUM_MANGLED_0;
	}
	*portp = priv_port;
	ip->daddr = priv;
	csum_replace4(&ip->check, pub, priv);
	stat_inc(PPPOE_STAT_NAT_IN);
	return 0;
}

/* ========================================================================
 * Forwarding from subscribers (PPPoE and IPoE)
 * ======================================================================== */

/* CGNAT and FIB forwarding of an IPv4 packet from a subscriber, whose IPv4
 * header is at ip_off (a compile-time constant at each call site). Returns
 * XDP_REDIRECT or XDP_DROP, or -1 when the kernel has to forward it; the
 * packet may have been translated by then, and the caller must re-read its
 * packet pointers. Packets about to expire go to the kernel untranslated,
 * for the ICMP Time Exceeded to reach the subscriber. */
static __always_inline int subscriber_forward(struct xdp_md *ctx, const __u32 ip_off,
                                              __be32 client_ip, __u32 fib_ifindex)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip = data + ip_off;
	if ((void *)(ip + 1) > data_end)
		return XDP_DROP;
	if (ip->ttl <= 1)
		return -1;

	struct nat_sub *ns = bpf_map_lookup_elem(&nat_subs, &client_ip);
	if (ns && !nat_bypassed(ip->daddr)) {
		if (nat_upstream(ctx, ip_off, ns))
			return XDP_DROP;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		ip = data + ip_off;
		if ((void *)(ip + 1) > data_end)
			return XDP_DROP;
	}

	/* Fast forwarding: route lookup in the kernel FIB */
	struct bpf_fib_lookup fib = {
		.family = AF_INET,
		.tos = ip->tos,
		.l4_protocol = ip->protocol,
		.tot_len = bpf_ntohs(ip->tot_len),
		.ipv4_src = ip->saddr,
		.ipv4_dst = ip->daddr,
		.ifindex = fib_ifindex,
	};
	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
	    !bpf_map_lookup_elem(&pppoe_tx_ports, &fib.ifindex))
		return -1;

	ip_decrease_ttl(ip);

	/* Drop the access L2 (+ PPPoE) and write a fresh Ethernet header */
	if (ip_off > sizeof(struct ethhdr) &&
	    bpf_xdp_adjust_head(ctx, (int)(ip_off - sizeof(struct ethhdr))))
		return XDP_DROP;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);
	return bpf_redirect(fib.ifindex, 0);
}

/* FIB forwarding of an IPv6 packet from a subscriber, header at ip_off.
 * Same contract as subscriber_forward. */
static __always_inline int subscriber_forward6(struct xdp_md *ctx, const __u32 ip_off, __u32 fib_ifindex)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6 = data + ip_off;
	if ((void *)(ip6 + 1) > data_end)
		return XDP_DROP;
	if (ip6->hop_limit <= 1)
		return -1;

	struct bpf_fib_lookup fib = {
		.family = AF_INET6,
		.l4_protocol = ip6->nexthdr,
		.tot_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr),
		.ifindex = fib_ifindex,
	};
	fib.flowinfo = *(__be32 *)ip6 & bpf_htonl(0x0FFFFFFF);
	__builtin_memcpy(fib.ipv6_src, &ip6->saddr, 16);
	__builtin_memcpy(fib.ipv6_dst, &ip6->daddr, 16);
	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
	    !bpf_map_lookup_elem(&pppoe_tx_ports, &fib.ifindex))
		return -1;

	ip6->hop_limit--;

	if (ip_off > sizeof(struct ethhdr) &&
	    bpf_xdp_adjust_head(ctx, (int)(ip_off - sizeof(struct ethhdr))))
		return XDP_DROP;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);
	return bpf_redirect(fib.ifindex, 0);
}

/* Hands a PPPoE session frame to the kernel as plain IP: the Ethernet (+
 * VLAN) header stays, the PPPoE/PPP header goes and the EtherType becomes
 * ethertype. The frame then arrives on the VLAN subinterface. */
static __always_inline int pppoe_to_kernel(struct xdp_md *ctx, const __u32 l2_len, __u16 ethertype)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u8 l2[sizeof(struct ethhdr) + sizeof(struct vlan_hdr)];
	if (data + l2_len > data_end)
		return XDP_PASS;
	__builtin_memcpy(l2, data, l2_len);

	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct pppoe_hdr)))
		return XDP_DROP;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + l2_len > data_end)
		return XDP_DROP;
	__builtin_memcpy(data, l2, l2_len);
	*(__be16 *)(data + l2_len - 2) = bpf_htons(ethertype);
	return XDP_PASS;
}

/* Checks, counts and forwards an IPv6 packet of a subscriber (PPPoE or
 * IPoE) whose header is at ip_off. Returns XDP_REDIRECT or XDP_DROP,
 * XDP_PASS for control traffic to userspace (unchanged), or -1 when the
 * kernel must forward it. */
static __always_inline int subscriber_upstream6(struct xdp_md *ctx, const __u32 ip_off,
                                                __be32 client_ip, __u32 fib_ifindex)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6 = data + ip_off;
	if ((void *)(ip6 + 1) > data_end)
		return XDP_DROP;
	if (ip6->version != 6)
		return XDP_DROP;
	if (ipv6_is_control(ip6)) {
		stat_inc(PPPOE_STAT_UP6_CONTROL);
		return XDP_PASS;
	}
	__be32 *owner = sub6_owner(&ip6->saddr);
	if (!owner || *owner != client_ip) {
		stat_inc(PPPOE_STAT_UP6_SPOOFED);
		return XDP_DROP;
	}
	if (!session_account(client_ip, 1, bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr))) {
		stat_inc(PPPOE_STAT_UP_POLICED);
		return XDP_DROP;
	}
	int ret = subscriber_forward6(ctx, ip_off, fib_ifindex);
	if (ret == XDP_REDIRECT)
		stat_inc(PPPOE_STAT_UP6_REDIRECT);
	return ret;
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
	if (ph->ppp_proto != bpf_htons(PPP_IP) && ph->ppp_proto != bpf_htons(PPP_IPV6)) {
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

	if (ph->ppp_proto == bpf_htons(PPP_IPV6)) {
		int ret = subscriber_upstream6(ctx, l2_len + sizeof(struct pppoe_hdr),
		                               sess->client_ip, sess->fib_ifindex);
		if (ret >= 0)
			return ret;
		stat_inc(PPPOE_STAT_UP6_KERNEL);
		return pppoe_to_kernel(ctx, l2_len, ETH_P_IPV6);
	}

	struct iphdr *ip = (void *)(ph + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_DROP;
	if (ip->version != 4 || ip->saddr != sess->client_ip) {
		stat_inc(PPPOE_STAT_UP_SPOOFED);
		return XDP_DROP;
	}

	if (!session_account(sess->client_ip, 1, bpf_ntohs(ip->tot_len))) {
		stat_inc(PPPOE_STAT_UP_POLICED);
		return XDP_DROP;
	}

	int ret = subscriber_forward(ctx, l2_len + sizeof(struct pppoe_hdr), sess->client_ip, sess->fib_ifindex);
	if (ret == XDP_REDIRECT)
		stat_inc(PPPOE_STAT_UP_REDIRECT);
	if (ret >= 0)
		return ret;

	stat_inc(PPPOE_STAT_UP_KERNEL);
	return pppoe_to_kernel(ctx, l2_len, ETH_P_IP);
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
 * IPoE upstream (access port, tail-called from dhcp_fastpath_prog)
 * ======================================================================== */

static __always_inline int handle_ipoe_upstream(struct xdp_md *ctx, const __u32 l2_len, __u16 vlan_id)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + l2_len;
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	struct ipoe_up_key key = { .vlan_id = vlan_id };
	__builtin_memcpy(key.client_mac, eth->h_source, ETH_ALEN);
	struct pppoe_up_val *sess = bpf_map_lookup_elem(&ipoe_up, &key);
	if (!sess) {
		/* No lease (yet, or any more): the kernel must not route this
		 * host to the internet, untranslated */
		if (dp_flag(DP_F_IPOE_LEASE_ONLY) && !nat_bypassed(ip->daddr)) {
			stat_inc(PPPOE_STAT_IPOE_UP_UNLEASED);
			return XDP_DROP;
		}
		stat_inc(PPPOE_STAT_IPOE_UP_NO_SESSION);
		return XDP_PASS;
	}
	if (ip->version != 4 || ip->saddr != sess->client_ip) {
		stat_inc(PPPOE_STAT_IPOE_UP_SPOOFED);
		return XDP_DROP;
	}
	if (!session_account(sess->client_ip, 1, bpf_ntohs(ip->tot_len))) {
		stat_inc(PPPOE_STAT_UP_POLICED);
		return XDP_DROP;
	}

	int ret = subscriber_forward(ctx, l2_len, sess->client_ip, sess->fib_ifindex);
	if (ret == XDP_REDIRECT)
		stat_inc(PPPOE_STAT_IPOE_UP_REDIRECT);
	if (ret >= 0)
		return ret;
	/* The frame is plain (tagged) IPv4 already: the kernel routes it from
	 * the VLAN subinterface */
	stat_inc(PPPOE_STAT_IPOE_UP_KERNEL);
	return XDP_PASS;
}

static __always_inline int handle_ipoe_upstream6(struct xdp_md *ctx, const __u32 l2_len, __u16 vlan_id)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = data + l2_len;
	if ((void *)(ip6 + 1) > data_end)
		return XDP_PASS;
	if (ipv6_is_control(ip6)) {
		stat_inc(PPPOE_STAT_UP6_CONTROL);
		return XDP_PASS;
	}

	struct ipoe_up_key key = { .vlan_id = vlan_id };
	__builtin_memcpy(key.client_mac, eth->h_source, ETH_ALEN);
	struct pppoe_up_val *sess = bpf_map_lookup_elem(&ipoe_up, &key);
	if (!sess) {
		if (dp_flag(DP_F_IPOE_LEASE_ONLY)) {
			stat_inc(PPPOE_STAT_IPOE_UP_UNLEASED);
			return XDP_DROP;
		}
		stat_inc(PPPOE_STAT_IPOE_UP_NO_SESSION);
		return XDP_PASS;
	}

	int ret = subscriber_upstream6(ctx, l2_len, sess->client_ip, sess->fib_ifindex);
	if (ret >= 0)
		return ret;
	stat_inc(PPPOE_STAT_UP6_KERNEL);
	return XDP_PASS;
}

SEC("xdp")
int ipoe_upstream(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return handle_ipoe_upstream(ctx, sizeof(struct ethhdr), 0);
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		return handle_ipoe_upstream6(ctx, sizeof(struct ethhdr), 0);

	if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;
		__u16 vid = bpf_ntohs(vh->h_vlan_TCI) & VLAN_VID_MASK;
		if (vh->h_vlan_encapsulated_proto == bpf_htons(ETH_P_IP))
			return handle_ipoe_upstream(ctx, sizeof(struct ethhdr) + sizeof(struct vlan_hdr), vid);
		if (vh->h_vlan_encapsulated_proto == bpf_htons(ETH_P_IPV6))
			return handle_ipoe_upstream6(ctx, sizeof(struct ethhdr) + sizeof(struct vlan_hdr), vid);
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
                                             __u16 ip_len, const int tagged, const __u16 ppp_proto)
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
	ph->ppp_proto = bpf_htons(ppp_proto);

	stat_inc(ppp_proto == PPP_IP ? PPPOE_STAT_DOWN_REDIRECT : PPPOE_STAT_DOWN6_REDIRECT);
	return bpf_redirect(sess->tx_ifindex, 0);
}

/* IPoE: new Ethernet header (+ 802.1Q tag) towards the subscriber */
static __always_inline int handle_ipoe_downstream(struct xdp_md *ctx, struct pppoe_down_val *sess,
                                                  const int tagged, const __u16 ethertype)
{
	if (tagged && bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
		return XDP_DROP;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) + (tagged ? sizeof(struct vlan_hdr) : 0) > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_dest, sess->client_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, sess->server_mac, ETH_ALEN);
	if (tagged) {
		struct vlan_hdr *vh = (void *)(eth + 1);
		eth->h_proto = bpf_htons(ETH_P_8021Q);
		vh->h_vlan_TCI = bpf_htons(sess->vlan_id & VLAN_VID_MASK);
		vh->h_vlan_encapsulated_proto = bpf_htons(ethertype);
	} else {
		eth->h_proto = bpf_htons(ethertype);
	}

	stat_inc(ethertype == ETH_P_IP ? PPPOE_STAT_IPOE_DOWN_REDIRECT : PPPOE_STAT_DOWN6_REDIRECT);
	return bpf_redirect(sess->tx_ifindex, 0);
}

/* IPv6 to a subscriber prefix: encapsulated towards the subscriber */
static __always_inline int handle_downstream6(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
	if ((void *)(ip6 + 1) > data_end)
		return XDP_PASS;

	__be32 *owner = sub6_owner(&ip6->daddr);
	if (!owner)
		return XDP_PASS;
	__be32 client_ip = *owner;
	struct pppoe_down_val *sess = bpf_map_lookup_elem(&pppoe_down, &client_ip);
	if (!sess)
		return XDP_PASS;

	/* Let the kernel answer with ICMPv6 Time Exceeded */
	if (ip6->hop_limit <= 1) {
		stat_inc(PPPOE_STAT_DOWN_KERNEL);
		return XDP_PASS;
	}
	__u16 len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
	if (len > sess->mru) {
		stat_inc(PPPOE_STAT_DOWN6_TOO_BIG);
		return XDP_DROP;
	}
	if (!session_account(client_ip, 0, len)) {
		stat_inc(PPPOE_STAT_DOWN_POLICED);
		return XDP_DROP;
	}
	ip6->hop_limit--;

	if (sess->flags & DOWN_F_IPOE) {
		if (sess->vlan_id)
			return handle_ipoe_downstream(ctx, sess, 1, ETH_P_IPV6);
		return handle_ipoe_downstream(ctx, sess, 0, ETH_P_IPV6);
	}
	if (sess->vlan_id)
		return handle_downstream(ctx, sess, len, 1, PPP_IPV6);
	return handle_downstream(ctx, sess, len, 0, PPP_IPV6);
}

SEC("xdp")
int pppoe_downstream(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		return handle_downstream6(ctx);
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	__be32 daddr = ip->daddr;
	struct pppoe_down_val *sess = bpf_map_lookup_elem(&pppoe_down, &daddr);
	if (!sess) {
		if (!bpf_map_lookup_elem(&nat_pool_ips, &daddr))
			return XDP_PASS;
		if (ip->ttl <= 1) {
			stat_inc(PPPOE_STAT_DOWN_KERNEL);
			return XDP_PASS;
		}
		if (nat_downstream(ctx, sizeof(struct ethhdr)))
			return XDP_DROP;
		daddr = ip->daddr;
		sess = bpf_map_lookup_elem(&pppoe_down, &daddr);
		if (!sess) {
			stat_inc(PPPOE_STAT_NAT_NO_MAPPING);
			return XDP_DROP;
		}
	}

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

	if (!session_account(daddr, 0, ip_len)) {
		stat_inc(PPPOE_STAT_DOWN_POLICED);
		return XDP_DROP;
	}

	ip_decrease_ttl(ip);

	if (sess->flags & DOWN_F_IPOE) {
		if (sess->vlan_id)
			return handle_ipoe_downstream(ctx, sess, 1, ETH_P_IP);
		return handle_ipoe_downstream(ctx, sess, 0, ETH_P_IP);
	}
	if (sess->vlan_id)
		return handle_downstream(ctx, sess, ip_len, 1, PPP_IP);
	return handle_downstream(ctx, sess, ip_len, 0, PPP_IP);
}

char _license[] SEC("license") = "GPL";
