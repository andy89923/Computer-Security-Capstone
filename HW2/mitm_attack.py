#!/usr/bin/env python3


import netifaces as ni
from math import log2
from scapy.all import ARP, Ether, srp, send

arp_table = {}

def arp_scan():
	
	# gtw_ip = 192.168.0.1
	# itf_if = (Interface Info)
	#      {'addr': '192.168.0.141', 'netmask': '255.255.255.0', 'broadcast': '192.168.0.255'} 
	# hot_ip = 192.168.0.141  MY IP
	# msk_ln = 24
	
	broadcast_mac = Ether(dst='ff:ff:ff:ff:ff:ff')

	gateway = ni.gateways()[ni.AF_INET][0]
	gtw_ip = gateway[0]
	itf_if = ni.ifaddresses(gateway[1])[ni.AF_INET][0]
	hot_ip = itf_if['addr']
	msk_ln = 32 - sum([int(log2(256 - int(i))) for i in itf_if['netmask'].split('.')])
	
	subnet = hot_ip + '/' + str(msk_ln)
	arp = ARP(pdst=subnet)
	
	packet = broadcast_mac / arp	
	result = srp(packet, timeout=2, verbose=False)[0]

	for i in result:
		arp_table[i[1].psrc] = { "ip": i[1].psrc, "mac": i[1].hwsrc }

	print("Available devices")
	print("-------------------------------------")
	print("IP Address       MAC Address         ")
	print("-------------------------------------")
	for i in arp_table:
		if i == gtw_ip or i == hot_ip: continue;
		print("%-15s %18s" % (i, arp_table[i]['mac']))
	
	print("-------------------------------------")
	return



def main():
	arp_scan()
	return 


if __name__ == '__main__':
    main()
