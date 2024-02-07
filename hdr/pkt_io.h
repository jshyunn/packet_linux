#pragma once

#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "pkt_handler.h"

typedef struct protocol {
	void* pHeader;
	void* pBody;
} protocol;

/* Prototype of Runnig Mode functions */
int setLive(pcap_t**);
int setOffline(pcap_t**, char*);
int processPkt(const struct pcap_pkthdr*, const u_char*);

/* Console */
void printFrame(const struct pcap_pkthdr*);
void printEther(const struct ether_header*);
void printIp(const struct ip*);
void printArp(const struct ether_arp*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);