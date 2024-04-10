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


/* IP Header Structure */
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
	ip_addr src;    /* Source address */
	ip_addr dst;    /* Destination address */
} ipv4_header;


/* ARP Structure */
typedef struct arp_header {
	u_short hard;   /* Hardware type */
	u_short pro;    /* Protocol type */
	u_char hlen;    /* Hardware address length */
	u_char plen;    /* Protocol address length */
	u_short op;     /* Opcode */
	mac_addr sha;   /* Source hardware address(mac address) */
	ip_addr spa;    /* Source protocol address(ip address) */
	mac_addr dha;   /* Destination hardware address(mac address) */
	ip_addr dpa;    /* Destination protocol address(ip address) */
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
