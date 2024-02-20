#pragma once
#include <pcap.h>
#include "protocol.h"

ether_header* getEther(const u_char*);
ipv4_header* getIPv4(const u_char*);
arp_header* getArp(const u_char*);
void releaseEther(ether_header*);
void releaseIPv4(ipv4_header*);
void releaseArp(arp_header*);