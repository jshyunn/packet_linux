#pragma once
#include <pcap.h>
#include "protocol.h"

ether_header* getEther(const u_char*);
ipv4_header* getIPv4(const u_char*);
arp_header* getArp(const u_char*);
void delEther(ether_header*);
void delIPv4(ipv4_header*);
void delArp(arp_header*);