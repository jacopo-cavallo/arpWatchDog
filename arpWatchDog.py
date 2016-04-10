#!/usr/bin/python
from scapy.all import sniff, ARP
import sys
from signal import SIGINT, signal
#data###################################################################
machines = dict()
#functions##############################################################
def paranoid(pckt):
	if( pckt[ARP].hwsrc in machines ):
		if(	machines[pckt[ARP].hwsrc] == pckt[ARP].psrc	):
			return "I know it"
		else:
			return "Same MAC, different IP"
	elif( pckt[ARP].psrc in machines.values() ):
		return "Same IP, different MAC"
	else:
		return "Nice to meet you"
 
def pckt_hndlr(pckt):
	source_ip = pckt[ARP].psrc
	source_MAC = pckt[ARP].hwsrc
#if op == 'is-at'
	if(pckt[ARP].op == 2):
		res = paranoid(pckt)
		if(res == "Nice to meet you"):
			machines[pckt[ARP].hwsrc] = pckt[ARP].psrc
			print "[New entry]\tIP: " + str(source_ip) + "\t|\tMAC: " + str(source_MAC)
		elif(res == "I know it"):
			pass
		elif(res == "Same MAC, different IP"):
			print "[ALERT]\t\tIP: " + str(source_ip) + " \t|\tMAC: " + str(source_MAC)+ " MAC known with different IP !!"
		elif( res == "Same IP, different MAC"):
			print "[ALERT]\t\tIP: " + str(source_ip) + " \t|\tMAC: " + str(source_MAC)+ " IP known with different MAC !!"  

def sig_handler(signal_number, interrupted_stack_frame):
	print "\nSIGINT received....."
	sys.exit(0)
			
#EXECUTION##############################################################		
if(len(sys.argv) < 2):
	my_iface = "wlan0"			 
else:
	my_iface = sys.argv[1]
		 
signal(SIGINT, sig_handler) 
#count: number of packets to capture. 0 means infinity
#store: wether to store sniffed packets or discard them
#prn: function to apply to each packet
sniff(filter = 'arp', count = 0, store = 0, iface = my_iface, prn = pckt_hndlr)
