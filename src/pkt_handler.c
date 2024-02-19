#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "../hdr/pkt_handler.h"

#define TO_LITTLE(data) data = ntohs(data); // convert byte order

ether_header* getEther(const u_char* pkt_data)
{
	ether_header* ether_hdr = (ether_header*)malloc(sizeof(ether_header));
	memcpy(ether_hdr, (ether_header*)pkt_data, sizeof(ether_header));
	TO_LITTLE(ether_hdr->type);
	return ether_hdr;
}

void delEther(ether_header* ether_hdr)
{
	free(ether_hdr);
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

void delIPv4(ipv4_header* ipv4_hdr)
{
	free(ipv4_hdr);
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

void delArp(arp_header* arp_hdr)
{
	free(arp_hdr);
}

void processPkt(const u_char** pkt_data)
{
	ether_header* ether_hdr = (ether_header*)*pkt_data;
	TO_LITTLE(ether_hdr->type);

	switch (ether_hdr->type)
	{
		case IPv4:
		{
			ipv4_header* ipv4_hdr = (ipv4_header*)(ether_hdr + 1);
			TO_LITTLE(ipv4_hdr->len);
			TO_LITTLE(ipv4_hdr->id);
			TO_LITTLE(ipv4_hdr->off);
			TO_LITTLE(ipv4_hdr->sum);

			handleIp(ipv4_hdr);
			break;
		}
		case ARP:
		{
			arp_header* arp_hdr = (arp_header*)(ether_hdr + 1);
			TO_LITTLE(arp_hdr->hard);
			TO_LITTLE(arp_hdr->pro);
			TO_LITTLE(arp_hdr->op);
			break;
		}
	}
}

void handleIp(const ipv4_header* ipv4_hdr)
{
	switch (ipv4_hdr->p)
	{
		case ICMP:
		{
			icmp_header* icmp_hdr = (icmp_header*)(ipv4_hdr + 1);
			TO_LITTLE(icmp_hdr->sum);

			break;
		}
		case TCP:
		{
			tcp_header* tcp_hdr = (tcp_header*)(ipv4_hdr + 1);
			TO_LITTLE(tcp_hdr->sport);
			TO_LITTLE(tcp_hdr->dport);
			TO_LITTLE(tcp_hdr->seq_num);
			TO_LITTLE(tcp_hdr->ack_num);
			TO_LITTLE(tcp_hdr->hlen_flags);
			TO_LITTLE(tcp_hdr->win_size);
			TO_LITTLE(tcp_hdr->sum);
			TO_LITTLE(tcp_hdr->ugt_ptr);

			break;
		}
		case UDP:
		{
			udp_header* udp_hdr = (udp_header*)(ipv4_hdr + 1);
			TO_LITTLE(udp_hdr->sport);
			TO_LITTLE(udp_hdr->dport);
			TO_LITTLE(udp_hdr->tlen);
			TO_LITTLE(udp_hdr->sum);

			break;
		}
	}
}
