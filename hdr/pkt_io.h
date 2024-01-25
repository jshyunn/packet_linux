#pragma once

#include "protocol.h"
#include "pkt_handler.h"

/* Console */
void printStatistics(const Statistics);
void printFrame(const struct pcap_pkthdr*);
void printEther(const ether_header*);
void printIp(const ip_header*);
void printArp(const arp_header*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);