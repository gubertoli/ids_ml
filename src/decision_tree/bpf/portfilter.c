#include <netinet/in.h>
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
	
		
		// to obtain mss_val
		// https://stackoverflow.com/questions/42750552/read-tcp-options-fields

		uint8_t *p = (uint8_t *)tcp + 20; // or sizeof (struct tcphdr)
		uint8_t *end = (uint8_t *)tcp + tcp->doff * 4;
		uint16_t mss = 0; 
		while (p < end) {
		    uint8_t kind = *p++;
		    if (kind == 0) {
		        break;
		    }
		    if (kind == 1) {
		        // No-op option with no length.
		        continue;
		    }
		    uint8_t size = *p++;
		    if (kind == 2) {
		        mss = ntohs(*(uint16_t *)p);
		    }
		    p += (size - 2);
		}


		if (tcp->ack_seq < bpf_htons(284597952)) {
		    if (tcp->urg == 0) {
		        if (tcp->cwr == 0) {
		            if (mss < bpf_htons(1175.5)) {
		                return XDP_PASS;
		            } else {
		            	return XDP_DROP;
		            }
		        } else {
		            if (tcp->ack_seq < bpf_htons(7806425.5)) {
		                return XDP_PASS;
		            } else {
		            	return XDP_DROP;
		            }
		        }
		    } else {
		    	return XDP_DROP;
		    }
		} else {
		    // IP_DF = 0x4000
		    if ((iph->frag_off & 0x4000) == 0) {
		        if (iph->tot_len < bpf_htons(41.0)) {
		            if (tcp->rst == 0) {
		            	return XDP_DROP;
		            } else {
		                return XDP_PASS;
		            }
		        } else {
		            return XDP_PASS;
		        }
		    } else {
		        if (iph->ttl < bpf_htons(76.0)) {
		            if (iph->ttl < bpf_htons(63.0)) {
		                return XDP_PASS;
		            } else {
		            	return XDP_DROP;
		            }
		        } else {
		            return XDP_PASS;
		        }
		    }
		} 
	    

		return XDP_PASS;
	}
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
