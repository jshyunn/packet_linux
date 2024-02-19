#pragma once
#include <pcap.h>

typedef struct pktinfo_t {
	void* frame;
	void* packet;
	void* segment;
	void* data;
} pktinfo_t;

pktinfo_t* getPktInfo(const u_char*);
void releasePktInfo(pktinfo_t*);