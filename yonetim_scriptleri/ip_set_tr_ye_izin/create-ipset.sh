#!/bin/bash
ipset create TR hash:net

for i in `cat ip.tr`
do
	ipset add TR ${i}
done
iptables -N cop-trafik
iptables -A cop-trafik -p tcp --dport 22  -m set ! --match-set TR src -j DROP
iptables -A cop-trafik -p tcp --dport 22022  -m set ! --match-set TR src -j DROP
iptables -A cop-trafik -p tcp --dport 18888  -m set ! --match-set TR src -j DROP
iptables -A cop-trafik -p tcp --dport 8006  -m set ! --match-set TR src -j DROP

iptables -I INPUT -j cop-trafik


