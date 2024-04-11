#pragma once

#include <pcap.h>

/* IPv4 Addresss Structure */
typedef struct ipv4_addr {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ipv4_addr;


/* IPv6 Address Structure */
typedef struct ipv6_addr {
	u_short byte1;
	u_short byte2;
	u_short byte3;
	u_short byte4;
	u_short byte5;
	u_short byte6;
	u_short byte7;
	u_short byte8;
} ipv6_addr;


/* MAC Addresss Structure */
typedef struct mac_addr {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
} mac_addr;


/* Ethernet Header Structure */
typedef struct ether_header {
	mac_addr dst;   /* Destination MAC address */
	mac_addr src;   /* Source MAC address */
	u_short type;   /* Type */
} ether_header;


/* LLC STP Configuration BPDUs Header Structure */
#pragma pack(push, 1)
typedef struct llc_stp_conf_header {
	u_char dsap;
	u_char ssap;
	u_char ctl_field;
	u_short prot_id;
	u_char prot_ver_id;
	u_char bpdu_type;
	u_char flags;
	u_short root_prior;
	mac_addr root_id;
	u_int cost;
	u_short bri_prior;
	mac_addr bri_id;
	u_short port;
	u_short msg_age;
	u_short max_age;
	u_short hello_time;
	u_short for_delay;
} llc_stp_conf_header;


/* LLC STP Configuration BPDUs Header Structure */
typedef struct llc_stp_tcn_header {
	u_char dsap;
	u_char ssap;
	u_char ctl_field;
	u_short prot_id;
	u_char prot_ver_id;
	u_char bpdu_type;
} llc_stp_tcn_header;
#pragma pack(pop)


/* IPv4 Header Structure */
typedef struct ipv4_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_char hl:4;    /* Internet header length(4bits) */
	u_char v:4;     /* Version(4bits) */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	u_char v:4;     /* Version(4bits) */
	u_char hl:4;    /* Internet header length(4bits) */
#endif
	u_char tos;     /* Type of service */
	u_short len;    /* Total length */
	u_short id;     /* Identification */
	u_short off;    /* Flags(3bits) & Fargment offset(13bits) */
	u_char ttl;     /* Time to live */
	u_char p;       /* Protocol */
	u_short sum;    /* Header Checksum */
	ipv4_addr src;    /* Source address */
	ipv4_addr dst;    /* Destination address */
} ipv4_header;


/* IPv6 Header Structure */
typedef struct ipv6_header {
	u_int v_cls_label;	/* Version(4bits), Traffic class, Flow label(20bits) */
	u_short plen;		/* Payload length */
	u_char nhdr;		/* Next header */
	u_char hop_lim;		/* Hop limit */
	ipv6_addr src; 		/* Source address */
	ipv6_addr dst;		/* Destination address */
} ipv6_header;


/* ARP Structure */
typedef struct arp_header {
	u_short hard;   /* Hardware type */
	u_short pro;    /* Protocol type */
	u_char hlen;    /* Hardware address length */
	u_char plen;    /* Protocol address length */
	u_short op;     /* Opcode */
	mac_addr sha;   /* Source hardware address(mac address) */
	ipv4_addr spa;    /* Source protocol address(ip address) */
	mac_addr dha;   /* Destination hardware address(mac address) */
	ipv4_addr dpa;    /* Destination protocol address(ip address) */
} arp_header;


/* ICMP Header Structure */
typedef struct icmp_header {
	u_char type;        /* Type */
	u_char code;        /* Code */
	u_short sum;	   /* Checksum */
} icmp_header;


/* TCP Header Structure */
typedef struct tcp_header {
	u_short sport;          /* Source port */
	u_short dport;          /* Destination port */
	u_int seq_num;          /* Sequence number */
	u_int ack_num;          /* Acknowledgement number */
	u_short hlen_flags ;    /* Header length(4bits) & Flags(12bits) */
	u_short win_size;       /* Window size */
	u_short sum;		/* Checksum */
	u_short ugt_ptr;	/* Urgent Pointer*/
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
	u_short sport;      	/* Source port */
	u_short dport;      	/* Destination port */
	u_short tlen;       	/* Total length*/
	u_short sum;		/* Checksum */
} udp_header;
