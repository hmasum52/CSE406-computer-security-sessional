suppose check module create korbo:
#include <linux/module.h>
#include <linux/kernel.h>

int initialization(void)
{
    printk(KERN_INFO "Hello World!\n");
    return 0;
}

void cleanup(void)
{
    printk(KERN_INFO "Bye-bye World!.\n");
}

module_init(initialization);
module_exit(cleanup);

MODULE_LICENSE("GPL");



1.Module creation er jnno: labSetup folder e jao, ekta check.c file create koro, makefile e object name oita dau(obj-m += check.o), then oi folder er terminal e "make" command call
2.suppose ami dekhte chai module thikthak init ar remove hoilo kina, dekhbo "dmesg" command diya, to aage dmesg clean kore nibo(how? `sudo dmesg` diya check dibo currect msgs, `sudo dmesg -C` diya clean
3.module insert korbo command - `sudo insmod check.ko` 
ekhon `sudo dmesg` dile module init e je function likha ta call hoye print korbe , er moddher likha(ei likhagula check.c er moddhei likha lagbe
ekhon sudo dmesg dile "Hello World!" print hobe
abar module_exit ei function er moddhe module remove er somoy er kaj hobe
so, amra firewall er code gula module_int er moddhe je function pass korbo tate likhbo, module_exit er moddhe oi firewall gula remove korbo
4.thikmoto insert hoise kina module dekhar another way, module name search kora "lsmod | grep check" ebhabe
5.module remove korbo command "sudo rmmod check", ekhon sudo dmesg dile "Bye-bye World!." o print hobe
----------etokkhon basic dekhlam, ekhon dekhbo firewall kibhabe setup korbo--------
1. netfilter header file use kore korbo kaj,netfilter kisu hook define kore, erpore hook gula insert kore kaj korte hoy
example code ->Files/packet_filter/seedFilter.c
code :
module_init(registerFilter);->hook gulake register kore
module_exit(removeFilter);->hook remove kore
```
   hook1.hook = printInfo;//ei hook e kon function call hobe ta likhe deya lagbe
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;//sobar jnno same
   hook1.priority = NF_IP_PRI_FIRST;//set kora jaay eta, dui hook same priority hole 					//jeta pore call hobe seta  
   nf_register_net_hook(&init_net, &hook1);//etokkhon insert korinai, ekhon insert 						//hobe
```
---ekhane ei linegular kaj holo, jotogula local input ashbe tader jnno printInfo function call----

## ------ekhane hooknum e 5 ta value boshte pare------

   ->NF_INET_PRE_ROUTING: This hook will be triggered by any incoming traffic very soon after entering the network stack. This hook is processed before any routing decisions have been made regarding where to send the packet.
   ->NF_INET_LOCAL_IN: This hook is triggered after an incoming packet has been routed if the packet is destined for the local system.
   ->NF_INET_FORWARD: This hook is triggered after an incoming packet has been routed if the packet is to be forwarded to another host.
   ->NF_INET_LOCAL_OUT: This hook is triggered by any locally created outbound traffic as soon as it hits the network stack.
   ->NF_INET_POST_ROUTING: This hook is triggered by any outgoing or forwarded traffic after routing has taken place and just before being sent out on the wire.

## ----now printInfo function in details e dekhi----
```
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
```
-prothome state dekhe seta print dilo
-skb -incoming traffic
-ip.h header er ip_hdr(skb) call korle header info extract korbe packet
-iph=ip_hdr(skb), ei iph e source,destination esob address thakte pare, to ogula         extract kore nibo 
-return type NF_ACCEPT howa mane packet accept korbo, NF_DROP hole packet drop korbo

---function parameter type---
3 ta param thakbe:
1.void *priv : eta niya kisu bolenai
2.struct sk_buff *skb : internal traffic ta 
3.const struct nf_hook_state *state: eta hook1.hooknum theke pabo

----to code to bujhlam, ebar run dibo----
1.packet_filter folder e jau
2.make //module create korlam
3.sudo dmesg -C //msg queue clear korlam
4.sudo insmod seedFilter.ko //insert korlam
5.lsmod | grep seedFilter //check dilam module ase kina

--to specifically seedFilter module e amra printinfo function call kori ja ei print gula kore--
printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);
ekhane mainly hook1.hooknum = NF_INET_LOCAL_OUT; howay outgoing packet gular info print hobe

----blockUDP function er kaj----
to ekhane ekta command ase jeta diya UDPheader set kora jaay (dig @8.8.8.8 www.example.com), to ei command call korle kisu kaj korbena(kaj korbe mane packet drop korbe, pore "sudo dmesg" command dile ekgada line je print hoy tar majhe majhe emon line o thakbe "[36299.426983] *** Dropping 8.8.8.8 (UDP), port 53"), coz blockUDP packet drop kore ditese, tai "sudo rmmod seedFilter" diye "dig @8.8.8.8 www.example.com" call korle kaj korbe

# ----task2A--------
docksh b1//host A te dhuklam-
cd
telnet 10.9.0.11
UserName : seed
Password: dees
--seed router e login hoi gelam--
exit
--abar docker A te back korlam--
ping 10.9.0.11 (diya dekhlam ping kora jaitese, ekhon amader kaj holo khali ping gulake nibo ar kisu nibona, how?)
iptables(kar jnno likhbo likha nai tai by default filter er jnno dhorbe, total 3 ta ase : filter,nat,mangle) -A(append korbo, -p mane kon protocol, -P policy-accept/drop eta) INPUT(input packet gular jnno) -p icmp(protocol name) --icmp-type echo request(icmp type, etai ping name porichito) -j ACCEPT(accept korlam)
----erpor aro 3 line ase, 2nd line e echo reply keo oy ac kore, but 3rd-4th e baki sob input/output ke block kore, fole ekhon khali ping kora jabe, but telnet kaj korbena----
---ei 4 ta shorto router e likha lagbe(serial thik rakha lagbe), as ekhon ami ei router ke diya khali ping korabo, ar kisu diya oke access korte parbena---
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -P OUTPUT DROP
iptables -P INPUT DROP
docksh 41
cd 
telnet 10.9.0.11
--ekhon ajibon wait korbe connect korar option ashbena--
ping 10.9.0.11
--eta thik e kaj korbe--
--suppose ami abar rule gula remove korte chai, router er terminal e jabo--
iptables -F
iptables -P OUTPUT ACCEPT
iptables -P INPUT ACCEPT
-- another way, docker restart--
docker RESTART <container_id>


# Statefull Firewall
---etokkhon stateless firewall niye kaj korsi ekhon stateful firewall niye kaj---
*mainly hostgula nijeder moddhe ping korle router hoye jawa lagbe
*router er connection tracking info dekhte : "conntrack -L"
-suppose dockA theke docker1 e ping korlam, ekhon conntrack -L likhle router e , icmp diye kisu likha dekhabe-
***ekhon ami server khulbo ekta docker e, docker1 e 9090 port e server khule("nc -lu 9090"), dockerA diye connect korbo("nc -u 192.168.60.5 9090")
nc -lu 9090
nc -u 192.168.60.5 9090
*** ekibhabe tcp server khulte chaile-
nc -l 9090(in host1)
nc 192.168.60.5 9090(in hostA)


# -----task3----
ekhane bolse je aage theke kora tcp & new tcp server ke allow korbo conncet korte, but kono udp server ke sujog dibona, er jnno 3 ta command :

iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -i eth0 --dport 9090 --syn -m conntrack --ctstate NEW -j ACCEPT
iptables -P FORWARD DROP

undo korar jnno-----
main terminal e jeye: docker restart f8(router docker restart korlam)
another way:
iptables -F
iptables -P FORWARD ACCEPT


-----task4(onekta ddos attack er moto)-----
qs e deya source jodi dockerA(10.9.0.5) hoy then proti mint e 4 tar beshi ping korbena, ar at a time 2 ta ping hobe
commands:
iptables -A FORWARD -s 10.9.0.5 -m limit --limit 4/minute --limit-burst 5 -j ACCEPT
iptables -A FORWARD -s 10.9.0.5 -j DROP

undo korar way:
iptables -F
iptables -P FORWARD ACCEPT

dockergula kaj na korle docker shutdown korbo :"dcdown" command diye






