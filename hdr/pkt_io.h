#pragma once

#include <pcap.h>
#include "protocol.h"

/* Prototype of Runnig Mode functions */
int setLive(pcap_t**);
int setOffline(pcap_t**, char*);

/* Console */
void printFrame(const struct pcap_pkthdr*);
void printEther(const ether_header*);
void printIPv4(const ipv4_header*);
void printArp(const arp_header*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);
