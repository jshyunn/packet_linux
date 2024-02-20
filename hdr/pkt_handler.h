#pragma once
#include <pcap.h>

typedef struct pktinfo_t {
	void* data;
	struct pktinfo_t* next;
} pktinfo_t;

void getPktInfo(pktinfo_t*, const u_char*);
void insertPktInfo(pktinfo_t*, void*);
void releasePktInfo(pktinfo_t**);