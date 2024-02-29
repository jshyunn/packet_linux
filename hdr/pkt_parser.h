#pragma once
#include <pcap.h>
#include "protocol.h"

ether_header* getEther(const u_char*);
ipv4_header* getIPv4(const u_char*);
arp_header* getARP(const u_char*);
icmp_header* getICMP(const u_char*);
udp_header* getUDP(const u_char*);
tcp_header* getTCP(const u_char*);
void releaseEther(ether_header*);
void releaseIPv4(ipv4_header*);
void releaseARP(arp_header*);
void releaseICMP(icmp_header*);
void releaseUDP(udp_header*);
void releaseTCP(tcp_header*);
char* getEtherType(const ether_header*);
char* getIPv4Type(const ipv4_header*);
