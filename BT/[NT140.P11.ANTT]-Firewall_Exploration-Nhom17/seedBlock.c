#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

static struct nf_hook_ops hook_ping, hook_telnet;

unsigned int blockPing(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
    struct iphdr *iph;
    char vm_ip[16] = "10.9.0.1";
    u32 vm_ip_addr;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    // Convert the IPv4 address from dotted decimal to 32-bit binary
    in4_pton(vm_ip, -1, (u8 *)&vm_ip_addr, '\0', NULL);

    // Check if the protocol is ICMP and the destination is the VM's IP
    if (iph->protocol == IPPROTO_ICMP && iph->daddr == vm_ip_addr) {
        printk(KERN_WARNING "*** Dropping ICMP Echo Request to %pI4\n", &(iph->daddr));
        return NF_DROP;
    }

    return NF_ACCEPT;
}

unsigned int blockTelnet(void *priv, struct sk_buff *skb,
                         const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    char vm_ip[16] = "10.9.0.1";
    u32 vm_ip_addr;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    // Convert the IPv4 address from dotted decimal to 32-bit binary
    in4_pton(vm_ip, -1, (u8 *)&vm_ip_addr, '\0', NULL);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        // Check if the destination is the VM's IP and the port is Telnet (23)
        if (iph->daddr == vm_ip_addr && ntohs(tcph->dest) == 23) {
            printk(KERN_WARNING "*** Dropping Telnet connection to %pI4 (port 23)\n", &(iph->daddr));
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

int registerFilter(void)
{
    printk(KERN_INFO "Registering filters.\n");

    // NF_INET_PRE_ROUTING for general packet filtering
    hook_ping.hook = blockPing;
    hook_ping.hooknum = NF_INET_PRE_ROUTING;
    hook_ping.pf = PF_INET;
    hook_ping.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_ping);

    hook_telnet.hook = blockTelnet;
    hook_telnet.hooknum = NF_INET_PRE_ROUTING;
    hook_telnet.pf = PF_INET;
    hook_telnet.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_telnet);

    return 0;
}

void removeFilter(void)
{
    printk(KERN_INFO "The filters are being removed.\n");
    nf_unregister_net_hook(&init_net, &hook_ping);
    nf_unregister_net_hook(&init_net, &hook_telnet);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

