#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

static __always_inline int process_packet(struct xdp_md *ctx, __u64 off){

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *udp;

	__u16 payload_len;
	__u8 protocol;

	iph = data + off;
	if (iph + 1 > data_end)
		return XDP_PASS;
	if (iph->ihl != 5)
		return XDP_PASS;

	protocol = iph->protocol;
	payload_len = bpf_ntohs(iph->tot_len);
	off += sizeof(struct iphdr);

	/* do not support fragmented packets as L4 headers may be missing */
	if (iph->frag_off & IP_FRAGMENTED)
		return XDP_PASS;

	if (protocol == IPPROTO_TCP) {
		tcp = data + off;
		if(tcp + 1 > data_end)
			return XDP_PASS;
		/*
		    struct tcphdr <linux/tcp.h>
			__u16 source
			__u16 dest
			__u32 seq
			__u32 ack_seq
			__u16 fin, syn, rst, psh, ack, urg, ece, cwr
		*/
		
		//if(tcp->source == bpf_htons(PORT_DROP) || tcp->dest == bpf_htons(PORT_DROP))
		//	return XDP_DROP;
		//else
		//	return XDP_PASS;


		if (tcp->window == bpf_htons(1024) || tcp->window == bpf_htons(2048) || tcp->window == bpf_htons(3072) || tcp->window == bpf_htons(4096)){
	    		if (tcp->fin == 1 && tcp->psh == 1 && tcp->urg == 1){
				// XMAS SCAN
				return XDP_DROP;
			} else if (tcp->fin == 1 && tcp->cwr == 0 && tcp->ece == 0 && tcp->urg == 0 && tcp->ack == 0 && tcp->psh == 0 && tcp->rst==0 && tcp->syn==0) {
				// FIN SCAN
				return XDP_DROP;
			} else if (tcp->fin == 0 && tcp->cwr == 0 && tcp->ece == 0 && tcp->urg == 0 && tcp->ack == 0 && tcp->psh == 0 && tcp->rst==0 && tcp->syn==0) {
				// NULL SCAN
				return XDP_DROP;
		    	} else if (tcp->fin == 1){
				// SYN SCAN
				return XDP_DROP;
			}
		} else {
	    		return XDP_PASS;
		}

	} else if (protocol == IPPROTO_UDP) {
		/*
		    struct udphdr <linux/udp.h>
			__u16 source
			__u16 dest
			__u16 len
			__u16 check
		*/

		udp = data + off;
		return XDP_PASS;
	}

	return XDP_PASS;
}


SEC("filter")
int pfilter(struct xdp_md *ctx){

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;	//struct to parse ethernet header
	__u32 eth_proto;
	__u32 nh_off;

	nh_off = sizeof(struct ethhdr);
	if (data + nh_off > data_end)	//boundary check
		return XDP_PASS;
	eth_proto = eth->h_proto;

	/* only accepts ipv4 packets for processing */
	if (eth_proto == bpf_htons(ETH_P_IP))
		return process_packet(ctx, nh_off);
	else
		return XDP_PASS;
}
