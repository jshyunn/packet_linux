#pragma once

#include "pkt_handler.h"

typedef enum Mode {
	Offline=1,
	Live,
	Exit
} Mode;

// Prototype of Runnig Mode functions
int runOffline(pcap_t**, char*);
int runLive(pcap_t**, char*);
int runExit();
int run();

/* Console */
void printStatistics(const Statistics);
void printFrame(const struct pcap_pkthdr*);
void printEther(const ether_header*);
void printIp(const ip_header*);
void printArp(const arp_header*);
void printIcmp(const icmp_header*);
void printTcp(const tcp_header*);
void printUdp(const udp_header*);