#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


static struct nf_hook_ops packetFilterHook;

unsigned int packetFilter(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;
	// if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(22)) {

	if (((unsigned char *)&iph->saddr)[0] == 192
			&& ((unsigned char *)&iph->saddr)[1] == 168
			&& ((unsigned char *)&iph->saddr)[2] == 18
			&& ((unsigned char *)&iph->saddr)[3] == 8) {
		printk(KERN_INFO "Dropping ip packet to %d.%d.%d.%d\n",
				(unsigned int)((ntohl(iph->saddr))>>24)&0xFF,
				(unsigned int)((ntohl(iph->saddr))>>16)&0xFF,
				(unsigned int)((ntohl(iph->saddr))>>8)&0xFF,
				(unsigned int)((ntohl(iph->saddr))&0xFF));
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}

int setUpFilter(void) {
	printk(KERN_INFO "Registering a packet filter.\n");
	packetFilterHook.hook = packetFilter; 
	packetFilterHook.hooknum = NF_INET_LOCAL_IN;
	packetFilterHook.pf = PF_INET;
	packetFilterHook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_hook(&packetFilterHook);
	return 0;
}

void removeFilter(void) {
	printk(KERN_INFO "packet filter is being removed.\n");
	nf_unregister_hook(&packetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

