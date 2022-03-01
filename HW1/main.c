#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>    // inet_addr
#include <netinet/ip.h>   // Provides declarations for ip header
#include <netinet/tcp.h>  // Provides declarations for tcp header

// Checksum (from internet)
unsigned short checksum(unsigned short *buf, int bufsz){
    unsigned long sum = 0xffff;

    while (bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }
    if (bufsz == 1) sum += *(unsigned char*) buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

int main(int argc, char const *argv[]) {
    
    

    return 0;
}
