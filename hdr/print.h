#pragma once

#include "protocol.h"

typedef struct print_info {
    char time[16];
    char protocol[20];
    char src[20];
    char dst[20];
    int len;
    char info[100];
} print_info;

typedef struct typemap {
	u_int val;
	const char* str;
} typemap;

typedef struct funcmap {
    u_int val;
    void (*func)(print_info*, arp_header*);
} funcmap;

void print(print_info);

void getPrintInfo(print_info*, const struct pcap_pkthdr*, const u_char*);
void getEtherInfo(print_info*, const u_char*);
void getIPv4Info(print_info*, const u_char*);
void getARPInfo(print_info*, const u_char*);
void getARPReqInfo(print_info*, arp_header*);
void getARPRepInfo(print_info*, arp_header*);
void getSTPInfo(print_info*, const u_char*);