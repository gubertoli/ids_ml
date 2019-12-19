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
		
	if (iph->tot_len <= htons(64)){  					// tot_len is u16
		printk(KERN_INFO "Step 1\n");
		if (iph->ttl < htons(65)){ 					// ttl is u8
			printk(KERN_INFO "Step 2\n");
			if (tcph->window <= htons(1024)){		// window is u16
				printk(KERN_INFO "Step 3\n");
				if ((iph->frag_off & IP_DF)  == 0){	// frag_off is u16
					printk(KERN_INFO "Step 4 - DROP\n");
					return NF_DROP;
				} else {
					printk(KERN_INFO "Step 5\n");
					return NF_ACCEPT;
				}
			} else {
				if (iph->ttl < htons(63.5)){
					printk(KERN_INFO "Step 6\n");
					return NF_ACCEPT;
				} else {
					printk(KERN_INFO "Step 7 - DROP\n");
					return NF_DROP;
				}
			}
		} else {
			if (iph->ttl < htons(254.5)){
				printk(KERN_INFO "Step 8\n");
				return NF_ACCEPT;
			} else {
				printk(KERN_INFO "Step 9 - DROP\n");
				return NF_DROP;
			}
		}
	} else {
		//printk(KERN_INFO "Step 10\n");
		return NF_ACCEPT;
	}
	
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
