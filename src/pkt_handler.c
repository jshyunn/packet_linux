#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "../hdr/pkt_parser.h"
#include "../hdr/pkt_handler.h"

pktinfo_t* getPktInfo(const u_char* pkt_data)
{
	pktinfo_t* pkt_info = (pktinfo_t*)malloc(sizeof(pktinfo_t));
	ether_header* ether_hdr = getEther(pkt_data);
	memcpy(pkt_info->frame, ether_hdr, sizeof(ether_hdr));
	delEther(ether_hdr);
	switch (ether_hdr->type)
	{
		case IPv4:
		{
			ipv4_header* ipv4_hdr = getIPv4(pkt_data);
			memcpy(pkt_info->packet, ipv4_hdr, sizeof(ipv4_hdr));
			delIPv4(ipv4_hdr);
		}
		case ARP:
		{
			arp_header* arp_hdr = getArp(pkt_data);
			memcpy(pkt_info->packet, arp_hdr, sizeof(arp_hdr));
			delArp(arp_hdr);
		}
	}
	return pkt_info;
}

void releasePktInfo(pktinfo_t* pkt_info)
{
	free(pkt_info->frame);
	free(pkt_info->packet);
	free(pkt_info);
}
/*
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
*/