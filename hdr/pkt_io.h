#pragma once

#include "pkt_handler.h"

/* Prototype of Runnig Mode functions */
int setLive(pcap_t**);
int setOffline(pcap_t**, char*);
int processPkt(pcap_t **);

/* Console */
void printFrame(const struct pcap_pkthdr*);
void printEther(const ether_header*);
void printIp(const ip_header*);
void printArp(const arp_header*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);