#pragma once

#include "protocol.h"

void printPkt(const struct pcap_pkthdr*, const void*);
void printInfo(const struct pcap_pkthdr*);
void printEther(const ether_header*);
void printIPv4(const ipv4_header*);
void printArp(const arp_header*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);
