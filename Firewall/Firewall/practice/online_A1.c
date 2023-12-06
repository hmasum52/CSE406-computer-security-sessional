#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/icmp.h>


static struct nf_hook_ops hook1, hook2;
int ping_count[5] = {0,0,0,0,0};
int syn_count[5] = {0,0,0,0,0};
int i = 0;

// online A1-17
unsigned int dropPackets(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   struct icmphdr *icmph;
   struct tcphdr *tcph;
   u32 src_ip_addr[5];
   u32 ip_addr;
   char ip[16] = "10.9.0.1";
   char src_ip[5][16] = {"10.9.0.5", 
                  "10.9.0.11", 
                  "192.168.60.5", 
                  "192.168.60.6", 
                  "192.168.60.7"};
   for(i=0;i<5;i++){
      in4_pton(src_ip[i], -1, (u8 *)&src_ip_addr[i], '\0', NULL);
   }
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if(!skb) return NF_ACCEPT;
   iph = ip_hdr(skb);

   for(i=0;i<5;i++){
      // printk(KERN_WARNING "*** NEW PACKET *from %s**", src_ip[i]);
      if(src_ip_addr[i]==iph->saddr){
         printk(KERN_WARNING "*** PING_COUNT = %d, SYN_COUNT = %d ***", ping_count[i], syn_count[i]);
         if(ping_count[i]>0 && syn_count[i]>0) {
            printk(KERN_WARNING "*** DROPPING ALL PACKETS, PING AND ACK RECEIVED ***");
            return NF_DROP;
         }
         if(iph->protocol == IPPROTO_ICMP){
            icmph = icmp_hdr(skb);
            if(iph->daddr == ip_addr && icmph->type == ICMP_ECHO){
               printk(KERN_WARNING "*** NEW PING %d from %s ***", ping_count[i], src_ip[i]);
               ping_count[i]++;
            }
         }
         else if(iph->protocol == IPPROTO_TCP){
            tcph = tcp_hdr(skb);
            if(iph->daddr == ip_addr && tcph->syn){
               printk(KERN_WARNING "*** NEW SYN %d from %s ***", syn_count[i], src_ip[i]);
               syn_count[i]++;
            }
         }
      }
      
   }
   return NF_ACCEPT;
}

unsigned int blockUDP(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   struct udphdr *udph;


   u16  port   = 53;
   char ip[16] = "8.8.8.8";
   u32  ip_addr;

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if (iph->protocol == IPPROTO_UDP) {
       udph = udp_hdr(skb);
       if (iph->daddr == ip_addr && ntohs(udph->dest) == port){
            printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        }
   }
   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}


int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   hook2.hook = dropPackets;
   hook2.hooknum = NF_INET_POST_ROUTING;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");


