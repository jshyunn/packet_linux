#pragma once

#include "protocol.h"

typedef struct print_info {
    char time[16];
    char protocol[20];
    char src[20];
    char dst[20];
    int len;
} print_info;

void print(print_info);

void getPrintInfo(print_info*, const struct pcap_pkthdr*, const u_char*);
void getEtherInfo(print_info*, const u_char*);
void getIPv4Info(print_info*, const u_char*);