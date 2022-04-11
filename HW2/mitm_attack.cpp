#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <arpa/inet.h>    // inet_addr() ....
#include <netdb.h>        // hostent
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/unistd.h>   // int gethostname(char *name, size_t len);
using namespace std;

// https://codeantenna.com/a/dFN06QiPaL

struct arp_packet {
    // Ethernet 
    char dest_MAC[6];
    char srce_MAC[6];
    char type[2];

    // ARP 
    char hdw_typ[2];
    char pto_typ[2];
    char hdw_siz;
    char pto_siz;
    char opcode[2];

    char src_MAC[6];
    int32_t src_IP;
    char dst_MAC[6];
    int32_t dst_IP;
};

void socket_init(int& sock_r) {
    sock_r = socket(AF_PACKET, SOCK_RAW, ETH_P_ARP);
	
    if (sock_r < 0) {
        cout << "Error on socket init!\n";
        exit(1);
    }

	struct timeval tv = { 3, 0 };      //set receive timeout 4s
    int one = 1;
    if (setsockopt(sock_r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 1) {
        cout << "Fail to Set IP_HDRINCL\n";
        exit(2);
    }
}

int main(int argc, char const *argv[]) {
    int sock_r;
    // socket_init(sock_r);

    char hostname[15];
	gethostname(hostname, 15);

	cout << hostname << '\n';
	hostent* host = nullptr;

	host = gethostbyname(hostname);
	struct in_addr ipaddr;

	ipaddr.s_addr = *(uint32_t*) (host -> h_addr);
	cout << inet_ntoa(ipaddr) << '\n';


    cout << "Avalible devices:\n";    
    cout << "--------------------------------------\n";
    cout << "IP                   MAC              \n";    
    cout << "--------------------------------------\n";



	close(sock_r);
    return 0;
}
