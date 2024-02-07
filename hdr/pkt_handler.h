#pragma once
#include <pcap.h>

/* IP Addresss Structure */
typedef struct ip_addr {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_addr;


/* MAC Addresss Structure */
typedef struct mac_addr {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
} mac_addr;

/* ICMP Header Structure */
typedef struct icmp_header {
	u_char type; /* Type */
	u_char code; /* Code */
	u_short checksum; /* Checksum */
} icmp_header;


/* TCP Header Structure */
typedef struct tcp_header {
	u_short sport; /* Source port */
	u_short dport; /* Destination port */
	u_int seq_num; /* Sequence number */
	u_int ack_num; /* Acknowledgement number */
	u_short hlen_flags; /* Header length(4bits) & Flags(12bits) */
	u_short win_size; /* Window size */
	u_short checksum; /* Checksum */
	u_short urgent_ptr; /* Urgent Pointer*/
} tcp_header;

/* TCP Flags Type */
typedef enum tcp_flags {
	FIN = 0b1,
	SYN = 0b10,
	RST = 0b100,
	PSH = 0b1000,
	ACK = 0b10000,
	URG = 0b100000
} tcp_flags;


/* UDP Header Structure */
typedef struct udp_header {
	u_short sport; /* Source port */
	u_short dport; /* Destination port */
	u_short tlen; /* Total length*/
	u_short checksum; /* Checksum */
} udp_header;

/* Prototype of the Packet Handler */
/*void handleFrame(const struct pcap_pkthdr*, const u_char*);
void handleEther(const ether_header*);
void handleIp(const ip_header*);*/

/* Statistics */
typedef struct Statistics {
	double prev_t;
	int byte;
	int pkt;
	int icmp;
	int udp;
	int tcp;
	int syn_f;
	int zerowin;
	int get_f;
} Statistics;
