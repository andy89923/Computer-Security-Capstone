#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// #include <sys/socket.h> //for socket ofcourse
// #include <stdlib.h> //for exit(0);
// #include <errno.h> //For errno - the error number
// #include <netinet/tcp.h>    //Provides declarations for tcp header
// #include <netinet/ip.h> //Provides declarations for ip header
// #include <arpa/inet.h> // inet_addr

#ifndef _DEBUG_COLOR_
#define _DEBUG_COLOR_
    #define KDRK "\x1B[0;30m"
    #define KGRY "\x1B[1;30m"
    #define KRED "\x1B[0;31m"
    #define KRED_L "\x1B[1;31m"
    #define KGRN "\x1B[0;32m"
    #define KGRN_L "\x1B[1;32m"
    #define KYEL "\x1B[0;33m"
    #define KYEL_L "\x1B[1;33m"
    #define KBLU "\x1B[0;34m"
    #define KBLU_L "\x1B[1;34m"
    #define KMAG "\x1B[0;35m"
    #define KMAG_L "\x1B[1;35m"
    #define KCYN "\x1B[0;36m"
    #define KCYN_L "\x1B[1;36m"
    #define WHITE "\x1B[0;37m"
    #define WHITE_L "\x1B[1;37m"
    #define RESET "\x1B[0m"
#endif

// 做 checksum 運算, 驗證資料有無毀損
unsigned short checksum(unsigned short *buf, int bufsz){
    unsigned long sum = 0xffff;

    while (bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1)
        sum += *(unsigned char*) buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int main(int argc, char *argv[]){
    int sd;
    struct icmphdr hdr;
    struct sockaddr_in addr;
    int num;
    char buf[1024];
    struct icmphdr *icmphdrptr;
    struct iphdr *iphdrptr;

    if(argc != 2){
        printf("usage: %s IPADDR\n", argv[0]);
        exit(-1);
    }

    addr.sin_family = PF_INET; // IPv4

    // 將使用者輸入的 IP 轉成 network order
    num = inet_pton(PF_INET, argv[1], &addr.sin_addr);
    if(num < 0){
        perror("inet_pton");
        exit(-1);
    }

    // 開一個 IPv4 的 RAW Socket , 並且準備收取 ICMP 封包
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd < 0){
        perror("socket");
        exit(-1);
    }

    // 清空結構內容
    memset(&hdr, 0, sizeof(hdr));

    // 初始化 ICMP Header
    hdr.type = ICMP_ECHO;
    hdr.code = 0;
    hdr.checksum = 0;
    hdr.un.echo.id = 0;
    hdr.un.echo.sequence = 0;

    // 計算出 checksum
    hdr.checksum = checksum((unsigned short*)&hdr, sizeof(hdr));

    // 將定義好的 ICMP Header 送到目標主機
    num = sendto(sd, (char*)&hdr, sizeof(hdr), 0, (struct sockaddr*)&addr, sizeof(addr));
    if(num < 1){
        perror("sendto");
        exit(-1);
    }
    printf(KYEL"We have sended an ICMP packet to %s\n", argv[1]);

    // 清空 buf
    memset(buf, 0, sizeof(buf));

    printf(KGRN"Waiting for ICMP echo...\n");

    // 接收來自目標主機的 Echo Reply
    num = recv(sd, buf, sizeof(buf), 0);
    if(num < 1){
        perror("recv");
        exit(-1);
    }

    // 取出 IP Header
    iphdrptr = (struct iphdr*)buf;

    // 取出 ICMP Header
    icmphdrptr = (struct icmphdr*)(buf+(iphdrptr->ihl)*4);

    // 判斷 ICMP 種類
    switch(icmphdrptr->type){
        case 3:
            printf(KBLU"The host %s is a unreachable purpose!\n", argv[1]);
            printf(KBLU"The ICMP type is %d\n", icmphdrptr->type);
            printf(KBLU"The ICMP code is %d\n", icmphdrptr->code);
            break;
        case 8:
            printf(KRED"The host %s is alive!\n", argv[1]);
            printf(KRED"The ICMP type is %d\n", icmphdrptr->type);
            printf(KRED"The ICMP code is %d\n", icmphdrptr->code);
            break;
        case 0:
            printf(KRED"The host %s is alive!\n", argv[1]);
            printf(KRED"The ICMP type is %d\n", icmphdrptr->type);
            printf(KRED"The ICMP code is %d\n", icmphdrptr->code);
            break;
        default:
            printf(KMAG"Another situations!\n");
            printf(KMAG"The ICMP type is %d\n", icmphdrptr->type);
            printf(KMAG"The ICMP code is %d\n", icmphdrptr->code);
            break;
    }

    close(sd); // 關閉 socket
    return EXIT_SUCCESS;
}