#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "../hdr/pkt_parser.h"

#define TO_LITTLE(data) data = ntohs(data); // convert byte order

ether_header* getEther(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)malloc(sizeof(ether_header));
	memcpy(ether_hdr, (ether_header*)pkt_data, sizeof(ether_header));
	TO_LITTLE(ether_hdr->type);
	return ether_hdr;
}

ipv4_header* getIPv4(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)pkt_data;
	ipv4_header* ipv4_hdr = (ipv4_header*)malloc(sizeof(ipv4_header));
	memcpy(ipv4_hdr, (ipv4_header*)(ether_hdr + 1), sizeof(ipv4_header));
	TO_LITTLE(ipv4_hdr->len);
	TO_LITTLE(ipv4_hdr->id);
	TO_LITTLE(ipv4_hdr->off);
	TO_LITTLE(ipv4_hdr->sum);
	return ipv4_hdr;
}

arp_header* getARP(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)pkt_data;
	arp_header* arp_hdr = (arp_header*)malloc(sizeof(arp_header));
	memcpy(arp_hdr, (arp_header*)(ether_hdr + 1), sizeof(arp_header));
	TO_LITTLE(arp_hdr->hard);
	TO_LITTLE(arp_hdr->pro);
	TO_LITTLE(arp_hdr->op);
	return arp_hdr;
}

icmp_header* getICMP(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)pkt_data;
	ipv4_header* ipv4_hdr = (ipv4_header*)(ether_hdr + 1);
	icmp_header* icmp_hdr = (icmp_header*)malloc(sizeof(icmp_header));
	memcpy(icmp_hdr, (icmp_header*)(ipv4_hdr + 1), sizeof(icmp_header));
	TO_LITTLE(icmp_hdr->sum);
	return icmp_hdr;
}

udp_header* getUDP(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)pkt_data;
	ipv4_header* ipv4_hdr = (ipv4_header*)(ether_hdr + 1);
	udp_header* udp_hdr = (udp_header*)malloc(sizeof(udp_header));
	memcpy(udp_hdr, (icmp_header*)(ipv4_hdr + 1), sizeof(udp_header));
	TO_LITTLE(udp_hdr->sport);
	TO_LITTLE(udp_hdr->dport);
	TO_LITTLE(udp_hdr->tlen);
	TO_LITTLE(udp_hdr->sum);
	return udp_hdr;
}

tcp_header* getTCP(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)pkt_data;
	ipv4_header* ipv4_hdr = (ipv4_header*)(ether_hdr + 1);
	tcp_header* tcp_hdr = (tcp_header*)malloc(sizeof(tcp_header));
	memcpy(tcp_hdr, (tcp_header*)(ipv4_hdr + 1), sizeof(tcp_header));
	TO_LITTLE(tcp_hdr->sport);
	TO_LITTLE(tcp_hdr->dport);
	TO_LITTLE(tcp_hdr->hlen_flags);
	TO_LITTLE(tcp_hdr->win_size);
	TO_LITTLE(tcp_hdr->sum);
	TO_LITTLE(tcp_hdr->ugt_ptr);
	return tcp_hdr;
}

void releaseEther(ether_header* ether_hdr)
{
	free(ether_hdr);
}

void releaseIPv4(ipv4_header* ipv4_hdr)
{
	free(ipv4_hdr);
}

void releaseARP(arp_header* arp_hdr)
{
	free(arp_hdr);
}

void releaseICMP(icmp_header* icmp_hdr)
{
	free(icmp_hdr);
}

void releaseUDP(udp_header* udp_hdr)
{
	free(udp_hdr);
}

void releaseTCP(tcp_header* tcp_hdr)
{
	free(tcp_hdr);
}

char* getEtherType(const ether_header* ether_hdr)
{
	if (ether_hdr->type == IPv4) return "IPv4";
	if (ether_hdr->type == ARP) return "ARP";
	return "NULL";
}

char* getIPv4Type(const ipv4_header* ipv4_hdr)
{
	if (ipv4_hdr->p == ICMP) return "ICMP";
	if (ipv4_hdr->p == TCP) return "TCP";
	if (ipv4_hdr->p == UDP) return "UDP";
	return "NULL";
}
