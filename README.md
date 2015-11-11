# DNS Spoofer
PoC program using ARP poisoning for a MITM attack between the target machine and router as a base for the DNS spoofer.


## Requirements
* [Scapy Library] (http://www.secdev.org/projects/scapy/)
* Enable forwarding rules on the machine you will be using as the MITM.
  - `echo "1" > /proc/sys/net/ipv4/ip_forward`
  - This will allow the packets to successfully go to and from the router and the target machine so they are able to access the Internet OK, however this will mean your DNS response packets will have to beat the router's. 
* If you don't wish to have the forwarding rule in place and rather drop all forwading packets:
  - On Linux systems: `iptables -A FORWARD -p udp -dport 53 -j DROP`
