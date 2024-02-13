#pragma once
#include <pcap.h>
#include "../hdr/pkt_io.h"

/* Prototype of the Packet Handler */
void processPkt(const u_char**);
void handleEther(const ether_header*);
void handleIp(const ip_header*);