#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>


#include <sys/socket.h>
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
    sock_r = socket(AF_INET, SOCK_RAW, ETH_P_ARP);

    if (sock_r < 0) {
        cout << "Error on socket init!\n";
        exit(1);
    }
    int one = 1;
    if (setsockopt(sock_r, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        cout << "Fail to Set IP_HDRINCL\n";
        exit(2);
    }
}

int main(int argc, char const *argv[]) {
    int sock_r;
    socket_init(sock_r);

    


    cout << "Avalible devices:\n";    
    cout << "--------------------------------------\n";
    cout << "IP                   MAC              \n";    
    cout << "--------------------------------------\n";




    return 0;
}
