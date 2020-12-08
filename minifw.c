#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

/* static struct nf_hook_ops telnetFilterHook; */

unsigned int generic_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  if (iph->protocol == IPPROTO_TCP && iph->daddr == in_aton("10.0.2.13") && tcph->dest == htons(23)) {
    // Block A telnet to B
    printk(KERN_INFO "RULE 1: Dropping telnet packet to %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;

  } else if (iph->protocol == IPPROTO_TCP && iph->saddr == in_aton("10.0.2.13") && tcph->dest == htons(23)) {
    // Block B telnet to A
    printk(KERN_INFO "RULE 2: Dropping telnet packet from %d.%d.%d.%d\n", 
        ((unsigned char *)&iph->saddr)[0],
        ((unsigned char *)&iph->saddr)[1],
        ((unsigned char *)&iph->saddr)[2],
        ((unsigned char *)&iph->saddr)[3]);
    return NF_DROP;

  } else if (iph->protocol == IPPROTO_TCP && iph->daddr == in_aton("202.197.61.57") && tcph->dest == htons(80)) {
    // Block A to visit www.csu.edu.cn
    printk(KERN_INFO "RULE 3: Block visit to www.csu.edu.cn @ %d.%d.%d.%d\n", 
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
    
  } else if (iph->protocol == IPPROTO_ICMP) {
    // Block Any ICMP packet
    printk(KERN_INFO "RULE 4: Block icmp to %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;

  } else if (iph->protocol == IPPROTO_TCP && iph->daddr == in_aton("10.0.2.11") && tcph->dest == htons(22)) {
    // Block all ssh connection to A
    printk(KERN_INFO "RULE 5: Block ssh connection from %d.%d.%d.%d\n",
        ((unsigned char *)&iph->saddr)[0],
        ((unsigned char *)&iph->saddr)[1],
        ((unsigned char *)&iph->saddr)[2],
        ((unsigned char *)&iph->saddr)[3]);
    return NF_DROP;

  } else {
      /* if no rules are matched */
      return NF_ACCEPT;
  }
}

// register for all hooks
static struct nf_hook_ops my_hooks[] = {
    {
        .hook   = generic_hook,
        .pf     = NFPROTO_IPV4,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_LAST,
    },
    {
        .hook   = generic_hook,
        .pf     = NFPROTO_IPV4,
        .hooknum    = NF_INET_LOCAL_IN,
        .priority   = NF_IP_PRI_LAST,
    },
    {
        .hook   = generic_hook,
        .pf     = NFPROTO_IPV4,
        .hooknum    = NF_INET_FORWARD,
        .priority   = NF_IP_PRI_LAST,
    },
    {
        .hook   = generic_hook,
        .pf     = NFPROTO_IPV4,
        .hooknum    = NF_INET_LOCAL_OUT,
        .priority   = NF_IP_PRI_LAST,
    },
    {
        .hook   = generic_hook,
        .pf     = NFPROTO_IPV4,
        .hooknum    = NF_INET_POST_ROUTING,
        .priority   = NF_IP_PRI_LAST,
    },
};


int setUpFilter(void) {
        printk(KERN_INFO "Registering a Telnet filter.\n");
        /* telnetFilterHook.hook     = telnetFilter; */
        /* telnetFilterHook.hooknum  = NF_INET_POST_ROUTING; */
        /* telnetFilterHook.pf       = PF_INET; */
        /* telnetFilterHook.priority = NF_IP_PRI_FIRST; */

        // Register the hook.
        nf_register_hooks(my_hooks, ARRAY_SIZE(my_hooks));
        return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "Telnet filter is being removed.\n");
        nf_unregister_hooks(my_hooks, ARRAY_SIZE(my_hooks));
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
