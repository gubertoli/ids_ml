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
    
    u_int16_t tcp_segment_length; // similar to wireshark ip.len
    #u_int8_t flags;

    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);

    if (!(iph)){
		return NF_ACCEPT;
    }

    if (iph->protocol == IPPROTO_TCP){ // TCP Protocol
	tcph = tcp_hdr(skb);
	
	//flags = ((u_int8_t *)tcph)[13];

	// tcp payload size in bytes
	tcp_segment_length = ntohs(iph->tot_len) - (iph->ihl*4 + tcph->doff*4); 

	//if (tcph->dest == htons(22)){
	//	printk(KERN_INFO "tcp.th_flags: %d", flags); 
	//}

	/**** Start of Decision Tree ****/

	if (iph->tot_len < htons(65)) {
              if (tcph->fin == htons(0)) {
                  if ((tcph->doff*4) < htons(42)) {
                      if (tcph->source < htons(43521)) {
                          if (tcph->window < htons(1201)) {
                              if ((iph->frag_off & IP_DF) == 0) {
                                  if (tcph->syn == htons(0)) {
                                      if (tcph->window < htons(506)) {
                                          return NF_ACCEPT;
                                      } else {
                                          if (tcph->source < htons(944)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (tcph->window < htons(1025)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      }
                                  } else {
                                      if (tcph->source < htons(40073)) {
                                          if (tcph->source < htons(3409)) {
                                              if (tcph->window < htons(768)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          } else {
                                              if (tcph->source < htons(40058)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      } else {
                                          return NF_ACCEPT;
                                      }
                                  }
                              } else {
                                  if (iph->id < htons(33)) {
                                      if (tcph->source < htons(28708)) {
                                          if (tcph->source < htons(2006)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (tcph->source < htons(4166)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          }
                                      } else {
                                          if (tcph->source < htons(33785)) {
                                              return NF_DROP;
                                          } else {
                                              if (tcph->source < htons(40033)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          }
                                      }
                                  } else {
                                      if (tcph->ack == htons(0)) {
                                          if (tcph->source < htons(23)) {
                                              if (iph->id < htons(47896)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          } else {
                                              return NF_ACCEPT;
                                          }
                                      } else {
                                          return NF_ACCEPT;
                                      }
                                  }
                              }
                          } else {
                              if (tcph->window < htons(64240)) {
                                  if ((unsigned int)tcp_segment_length < 19) {
                                      if (iph->id < htons(50800)) {
                                          return NF_ACCEPT;
                                      } else {
                                          if (iph->id < htons(50818)) {
                                              return NF_DROP;
                                          } else {
                                              return NF_ACCEPT;
                                          }
                                      }
                                  } else {
                                      if (tcph->source < htons(16552)) {
                                          return NF_ACCEPT;
                                      } else {
                                          return NF_DROP;
                                      }
                                  }
                              } else {
                                  if (tcph->source < htons(32746)) {
                                      return NF_ACCEPT;
                                  } else {
                                      if (tcph->window < htons(64293)) {
                                          if (iph->tot_len < htons(56)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (iph->id < htons(55380)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      } else {
                                          if (tcph->source < htons(33613)) {
                                              if (tcph->source < htons(33313)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          } else {
                                              if (tcph->source < htons(41889)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      }
                                  }
                              }
                          }
                      } else {
                          if (tcph->source < htons(62217)) {
                              if (tcph->window < htons(64233)) {
                                  if (tcph->window < htons(1)) {
                                      if (tcph->source < htons(61992)) {
                                          if (tcph->source < htons(55780)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (tcph->source < htons(55799)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          }
                                      } else {
                                          return NF_DROP;
                                      }
                                  } else {
                                      if ((unsigned int)tcp_segment_length < 18) {
                                          if (tcph->window < htons(28946)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (tcph->window < htons(29000)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          }
                                      } else {
                                          if (tcph->window < htons(16528)) {
                                              return NF_ACCEPT;
                                          } else {
                                              return NF_DROP;
                                          }
                                      }
                                  }
                              } else {
                                  if (iph->tot_len < htons(59)) {
                                      if (tcph->source < htons(51418)) {
                                          if (tcph->source < htons(49003)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (iph->id < htons(54161)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      } else {
                                          return NF_ACCEPT;
                                      }
                                  } else {
                                      if (tcph->window < htons(64520)) {
                                          if (tcph->source < htons(49124)) {
                                              return NF_DROP;
                                          } else {
                                              if (tcph->source < htons(49237)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      } else {
                                          return NF_ACCEPT;
                                      }
                                  }
                              }
                          } else {
                              if (tcph->window < htons(1025)) {
                                  if ((iph->frag_off & IP_DF) == 0) {
                                      if (tcph->source < htons(62237)) {
                                          return NF_DROP;
                                      } else {
                                          if (tcph->ack == htons(0)) {
                                              return NF_ACCEPT;
                                          } else {
                                              if (tcph->window < htons(769)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      }
                                  } else {
                                      if (tcph->ack == htons(0)) {
                                          if (tcph->source < htons(62330)) {
                                              return NF_DROP;
                                          } else {
                                              if (tcph->source < htons(63851)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_ACCEPT;
                                              }
                                          }
                                      } else {
                                          return NF_ACCEPT;
                                      }
                                  }
                              } else {
                                  if ((unsigned int)tcp_segment_length < 18) {
                                      if (iph->id < htons(46559)) {
                                          return NF_ACCEPT;
                                      } else {
                                          if (iph->id < htons(46771)) {
                                              return NF_DROP;
                                          } else {
                                              return NF_ACCEPT;
                                          }
                                      }
                                  } else {
                                      return NF_DROP;
                                  }
                              }
                          }
                      }
                  } else {
                      if (tcph->window < htons(15749)) {
                          return NF_ACCEPT;
                      } else {
                          if (tcph->window < htons(23789)) {
                              return NF_DROP;
                          } else {
                              return NF_ACCEPT;
                          }
                      }
                  }
              } else {
                  if (tcph->window < htons(512)) {
                      return NF_ACCEPT;
                  } else {
                      if (tcph->ack == htons(0)) {
                          return NF_DROP;
                      } else {
                          if (iph->id < htons(19)) {
                              return NF_ACCEPT;
                          } else {
                              if (tcph->window < htons(16498)) {
                                  if (tcph->window < htons(1024)) {
                                      return NF_ACCEPT;
                                  } else {
                                      if (tcph->source < htons(3152)) {
                                          return NF_ACCEPT;
                                      } else {
                                          if (tcph->source < htons(39166)) {
                                              if (tcph->source < htons(29318)) {
                                                  return NF_DROP;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          } else {
                                              if (iph->tot_len < htons(58)) {
                                                  return NF_ACCEPT;
                                              } else {
                                                  return NF_DROP;
                                              }
                                          }
                                      }
                                  }
                              } else {
                                  return NF_ACCEPT;
                              }
                          }
                      }
                  }
              }
          } else {
              return NF_ACCEPT;
          }
	}
	
	/**** End of Decision Tree ****/

    return NF_ACCEPT;
}

// Netfilter hook

static struct nf_hook_ops simpleFilterHook = {
    .hook	= simpleFilter,
    .hooknum	= NF_INET_PRE_ROUTING,
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
