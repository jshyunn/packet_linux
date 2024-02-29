#pragma once

#include "protocol.h"

void printMAC(const mac_addr, const mac_addr);
void printIP(const ip_addr, const ip_addr);
void printPkt(const struct pcap_pkthdr*, const void*);
void printEther(const ether_header*);
void printIPv4(const ipv4_header*);
void printARP(const arp_header*);
void printICMP(const icmp_header*);
void printTCP(const tcp_header*);
void printUDP(const udp_header*);
