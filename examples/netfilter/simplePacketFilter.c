// Simple packet filter using netfilter and LKM

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PORT_TO_FILTER 23

static struct nf_hook_ops simpleFilterHook;

// implementation of Filter callback function
unsigned int simpleFilter (unsigned int hooknum, struct sk_buff *skb, 
			    const struct net_device *in, 
			    const struct net_device *out,
			    int (*okfn)(struct sk_buff *)){

    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph+iph->ihl*4;

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(PORT_TO_FILTER)){
	printk(KERN_INFO "Dropping packet to %d.%d.%d.%d on Port %d\n",
	    ((unsigned char *)&iph->daddr)[0],
	    ((unsigned char *)&iph->daddr)[1],
	    ((unsigned char *)&iph->daddr)[2],
	    ((unsigned char *)&iph->daddr)[3],
	    PORT_TO_FILTER);

	//match condition
	return NF_DROP;

    } else {
	return NF_ACCEPT;
    }
}

int setUpFilter(void){
    printk(KERN_INFO "Registering Simple Filter.\n");
    simpleFilterHook.hook = simpleFilter;
    simpleFilterHook.hooknum = NF_INET_POST_ROUTING;
    simpleFilterHook.pf = PF_INET;
    simpleFilterHook.priority = NF_IP_PRI_FIRST;

    //register the hook
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_register_net_hook(&init_net, &simpleFilterHook)
    #ELSE
        nf_register_hook(&simpleFilterHook);
    #ENDIF
    return 0;
}

void removeFilter(void){
    printk(KERN_INFO "Simple Filter is being removed.\n");
    nf_unregister_hook(&simpleFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
