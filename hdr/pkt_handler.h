#pragma once
#include <pcap.h>
#include "../hdr/protocol.h"
#include "../hdr/pkt_io.h"
ether_header* getEther(const u_char*);
void delEther(ether_header*);
ipv4_header* getIPv4(const u_char*);
void delIPv4(ipv4_header*);
/* Prototype of the Packet Handler */
void processPkt(const u_char**);
void handleEther(const ether_header*);
void handleIp(const ipv4_header*);
