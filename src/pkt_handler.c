#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "../hdr/pkt_parser.h"
#include "../hdr/pkt_handler.h"

void getPktInfo(pktinfo_t** pkt_info, const u_char* pkt_data)
{
	ether_header* ether_hdr = getEther(pkt_data);
	(*pkt_info)->data = ether_hdr;
	switch (ether_hdr->type)
	{
		case IPv4:
		{
			ipv4_header* ipv4_hdr = getIPv4(pkt_data);
			(*pkt_info)->next->data = ipv4_hdr;
		}
		case ARP:
		{
			arp_header* arp_hdr = getArp(pkt_data);
			(*pkt_info)->next->data = arp_hdr;
		}
	}
}

void insertPktInfo(pktinfo_t* pkt_info, void* pkt_data)
{
	pkt_info
}

void releasePktInfo(pktinfo_t* pkt_info)
{
	/*while (pkt_info != NULL)
	{
		free(pkt_info->data);
		pkt_info = pkt_info->next;
	}*/
	free(pkt_info->next->data);
	free(pkt_info->data);
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