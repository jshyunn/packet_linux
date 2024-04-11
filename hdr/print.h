#pragma once

#include "protocol.h"

typedef struct print_info {
    char time[16];
    char protocol[20];
    char src[40];
    char dst[40];
    int len;
    char info[100];
} print_info;

typedef struct typemap {
	const u_int val;
	const char* str;
    void (*const func)(print_info*, const u_char*);
} typemap;

void print(print_info);

void setPrintInfo(print_info*, const struct pcap_pkthdr*, const u_char*);
void setEtherInfo(print_info*, const u_char*);
void setIPv4Info(print_info*, const u_char*);
void setIPv6Info(print_info*, const u_char*);
void setARPInfo(print_info*, const u_char*);
void setSTPInfo(print_info*, const u_char*);
void setNotSupportedInfo(print_info*, const u_char*);