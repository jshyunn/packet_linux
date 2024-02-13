#pragma once

#include <pcap.h>
#include "protocol.h"

/* Prototype of Runnig Mode functions */
int setLive(pcap_t**);
int setOffline(pcap_t**, char*);

/* Console */
void printFrame(const struct pcap_pkthdr*);
void printEther(const ether_header*);
void printIp(const ip_header*);
void printArp(const struct arp_header*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);