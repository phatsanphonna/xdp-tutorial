/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

struct
{
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned char[ETH_ALEN]);
	__type(value, unsigned char[ETH_ALEN]);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_params SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline __u16 icmp_checksum_diff(
	__u16 seed,
	struct icmphdr_common *icmphdr_new,
	struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	/* Assignment 1: swap source and destination addresses in the eth.
	 * For simplicity you can use the memcpy macro defined above */
	__u8 src_tmp[ETH_ALEN];

	// Store value in unsigned char array (placeholder)
	memcpy(src_tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, src_tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	/* Assignment 1: swap source and destination addresses in the iphv6dr */
	struct in6_addr source = ipv6->saddr;

	ipv6->saddr = ipv6->daddr;
	ipv6->daddr = source;
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	/* Assignment 1: swap source and destination addresses in the iphdr */
	__be32 source = iphdr->saddr;
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = source;
}

/* Implement packet03/assignment-1 in this section */
SEC("xdp")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply;
	struct icmphdr_common *icmphdr;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP))
	{
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6))
	{
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	}
	else
	{
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO)
	{
		/* Swap IP source and destination */
		bpf_printk("Before swap src IP: %x", bpf_ntohs(iphdr->saddr));
		bpf_printk("Before swap dst IP: %x", bpf_ntohs(iphdr->daddr));
		swap_src_dst_ipv4(iphdr);
		bpf_printk("After swap src IP:  %x", bpf_ntohs(iphdr->saddr));
		bpf_printk("After swap dst IP:  %x", bpf_ntohs(iphdr->daddr));
		echo_reply = ICMP_ECHOREPLY;
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6) && icmp_type == ICMPV6_ECHO_REQUEST)
	{
		/* Swap IPv6 source and destination */
		bpf_printk("Before swap src IPv6: %x", ipv6hdr->saddr.in6_u.u6_addr8);
		swap_src_dst_ipv6(ipv6hdr);
		bpf_printk("After swap src IPv6:  %x", ipv6hdr->daddr.in6_u.u6_addr8);
		echo_reply = ICMPV6_ECHO_REPLY;
	}
	else
	{
		goto out;
	}

	bpf_printk("Before swap src MAC: %s", eth->h_source[5]);
	bpf_printk("Before swap dst MAC: %x", eth->h_dest[5]);

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);

	bpf_printk("After swap src MAC:  %x", eth->h_source[5]);
	bpf_printk("After swap dst MAC:  %x", eth->h_dest[5]);

	/* Assignment 1: patch the packet and update the checksum. You can use
	 * the echo_reply variable defined above to fix the ICMP Type field. */

	bpf_printk("%x", icmphdr->cksum);

	struct icmphdr_common icmphdr_old;
	__u16 old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	bpf_printk("%x", icmphdr->cksum);

	bpf_printk("echo_reply: %d", echo_reply);

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

/* Assignment 2 */
SEC("xdp")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char dst[ETH_ALEN] = {0x92, 0xbf, 0x44, 0x35, 0x82, 0x78}; /* Assignment 2: fill in with the MAC address of the left inner interface */
	unsigned ifindex = 2;												/* Assignment 2: fill in with the ifindex of the left interface */

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Assignment 2: set a proper destination address and call the
	 * bpf_redirect() with proper parameters, action = bpf_redirect(...) */

	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect(ifindex, 0);

out:
	return xdp_stats_record_action(ctx, action);
}

/* Assignment 3: nothing to do here, patch the xdp_prog_user.c program */
SEC("xdp")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char *dst;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Do we know where to redirect this packet? */
	dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
	if (!dst)
		goto out;

	bpf_printk("Last 8 bit of MAC address from map: %x", &dst[5]);

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);

	/* Redirect by map of index key */
	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_stats_record_action(ctx, action);
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	/* Assignment 4: see samples/bpf/xdp_fwd_kern.c from the kernel */
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

/* Assignment 4: Complete this router program */
SEC("xdp")
int xdp_router_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
	{
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP))
	{
		iph = data + nh_off;

		if (iph + 1 > data_end)
		{
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		/* Assignment 4: fill the fib_params structure for the AF_INET case */
		fib_params.family = AF_INET;
		fib_params.ipv4_src = iph->saddr;
		fib_params.ipv4_dst = iph->daddr;
		fib_params.l4_protocol = iph->protocol;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tos = iph->tos;
		fib_params.tot_len = bpf_ntohs(iph->tot_len);
	}
	else if (h_proto == bpf_htons(ETH_P_IPV6))
	{
		/* These pointers can be used to assign structures instead of executing memcpy: */
		struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end)
		{
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		/* Assignment 4: fill the fib_params structure for the AF_INET6 case */
		fib_params.family = AF_INET6;
		fib_params.flowinfo = *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		*src = ip6h->saddr;
		*dst = ip6h->daddr;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tot_len = bpf_ntohs(ip6h->payload_len);
		fib_params.l4_protocol = ip6h->nexthdr;
	}
	else
	{
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	/* bpf_fib_lookup will populate source mac address and destination mac address here */
	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc)
	{
	case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		/* Assignment 4: fill in the eth destination and source
		 * addresses and call the bpf_redirect function */
		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect(fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:	   /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:	/* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:	/* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:		/* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:	/* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
