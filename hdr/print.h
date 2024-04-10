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

void setPrintInfo(print_info*, const struct pcap_pkthdr*, const u_char*);
void setEtherInfo(print_info*, const u_char*);
void setIPv4Info(print_info*, const u_char*);
void setARPInfo(print_info*, const u_char*);
void setARPReqInfo(print_info*, arp_header*);
void setARPRepInfo(print_info*, arp_header*);
void setSTPInfo(print_info*, const u_char*);