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

arp_header* getArp(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)pkt_data;
	arp_header* arp_hdr = (arp_header*)malloc(sizeof(arp_header));
	memcpy(arp_hdr, (arp_header*)(ether_hdr + 1), sizeof(arp_header));
	TO_LITTLE(arp_hdr->hard);
	TO_LITTLE(arp_hdr->pro);
	TO_LITTLE(arp_hdr->op);
	return arp_hdr;
}

void delEther(ether_header* ether_hdr)
{
	free(ether_hdr);
}

void delIPv4(ipv4_header* ipv4_hdr)
{
	free(ipv4_hdr);
}

void delArp(arp_header* arp_hdr)
{
	free(arp_hdr);
}