// Decision Tree using netfilter and LKM

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>	//Needed for LINUX_VERSION_CODE <= KERNEL_VERSION
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define IP_DF 0x4000

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

		/* Start of Decision Tree */
		if (tcph->seq <= htons(1)) {
		  if (iph->ttl <= htons(62)) {
			  if (iph->ttl <= htons(61)) {
				  if (tcph->window <= htons(1024)) {
					  if (tcph->window <= htons(1024)) {
						  return NF_ACCEPT;
					  } else {
						  if ((iph->frag_off & IP_DF)==0) {
							  return NF_DROP;
						  } else {
							  return NF_ACCEPT;
						  }
					  }
				  } else {
					  return NF_ACCEPT;
				  }
			  } else {
				  if (tcph->ack == 0) {
					  if (tcph->window <= htons(255)) {
						  if (iph->id <= htons(890)) {
							  return NF_DROP;
						  } else {
							  return NF_ACCEPT;
						  }
					  } else {
						  if (tcph->window < htons(40312)) {
							  return NF_DROP;
						  } else {
							  return NF_DROP;
						  }
					  }
				  } else {
					  if (tcph->doff < htons(42)) {  // tcp.hdr_len relates to the TCP options field
						  if ((iph->frag_off & IP_DF)==0) {
							  return NF_DROP;
						  } else {
							  return NF_ACCEPT;
						  }
					  } else {
						  if (tcph->window < htons(15838)) {
							  return NF_ACCEPT;
						  } else {
							  return NF_DROP;
						  }
					  }
				  }
			  }
		  } else {
			  if (iph->ttl < 252.5) {
				  return NF_ACCEPT;
			  } else {
				  if (tcph->window < htons(512)) {
					  return NF_ACCEPT;
				  } else {
					  if (tcph->ack == 0) {
						  return NF_DROP;
					  } else {
						  return NF_ACCEPT;
					  }
				  }
			  }
		  }
		} else {
		  return NF_ACCEPT;
		}
		/* End of Decision Tree */
		
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
