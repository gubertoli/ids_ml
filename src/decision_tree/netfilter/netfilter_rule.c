// Decision Tree using netfilter and LKM

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>	//Needed for LINUX_VERSION_CODE <= KERNEL_VERSION
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops simpleFilterHook;

// implementation of Filter callback function - Netfilter Hook
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int simpleFilter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static unsigned int simpleFilter(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
static unsigned int simpleFilter(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
#else
static unsigned int simpleFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#endif
{

    struct ethhdr *ethh;
    struct iphdr  *iph; 	// ip header struct
    struct tcphdr *tcph;	// tcp header struct
    
    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);

    if (!(iph)){
		return NF_ACCEPT;
    }

    if (iph->protocol == IPPROTO_TCP){ // TCP Protocol
	tcph = tcp_hdr(skb);
	

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


	if (tcph->ack_seq < 284597952.0) {
	    if (tcph->urg == 0) {
	        if (tcph->cwr == 0) {
	            if (mss < 1175.5) {
	                return NF_ACCEPT;
	            } else {
	            	printk(KERN_INFO "Packet drop (1)\n");
	                return NF_DROP;
	            }
	        } else {
	            if (tcph->ack_seq < 7806425.5) {
	                return NF_ACCEPT;
	            } else {
	            	printk(KERN_INFO "Packet drop (2)\n");
	                return NF_DROP;
	            }
	        }
	    } else {
	    	printk(KERN_INFO "Packet drop (3)\n");
	        return NF_DROP;
	    }
	} else {
	    // IP_DF = 0x4000
	    if ((iph->frag_off & IP_DF) == 0) {
	        if (iph->len < 41.0) {
	            if (tcph->rst == 0) {
	            	printk(KERN_INFO "Packet drop (4)\n");
	                return NF_DROP;
	            } else {
	                return NF_ACCEPT;
	            }
	        } else {
	            return NF_ACCEPT;
	        }
	    } else {
	        if (iph->ttl < 76.0) {
	            if (iph->ttl < 63.0) {
	                return NF_ACCEPT;
	            } else {
	            	printk(KERN_INFO "Packet drop (5)\n");
	                return NF_DROP;
	            }
	        } else {
	            return NF_ACCEPT;
	        }
	    }
	} else {
	    return NF_ACCEPT;
	}
    

    return NF_ACCEPT;
}

// Netfilter hook

static struct nf_hook_ops simpleFilterHook = {
    .hook	= simpleFilter,
    .hooknum	= NF_INET_POST_ROUTING,
    .pf		= PF_INET,
    .priority	= NF_IP_PRI_FIRST,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    .owner	= THIS_MODULE
#endif
};

int setUpFilter(void){
    printk(KERN_INFO "Registering Simple Filter.\n");

    //register the hook
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
    	nf_register_hook(&simpleFilterHook);
    #else
	nf_register_net_hook(&init_net, &simpleFilterHook);
    #endif
    return 0;
}

void removeFilter(void){
    printk(KERN_INFO "Simple Filter is being removed.\n");
    
    //unregister the hook
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
	nf_register_hook(&simpleFilterHook);
    #else
        nf_unregister_net_hook(&init_net, &simpleFilterHook);
    #endif
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
