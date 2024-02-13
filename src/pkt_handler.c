#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "../hdr/protocol.h"
#include "../hdr/pkt_handler.h"

#define TO_LITTLE(data) data = ntohs(data); // convert byte order

void processPkt(const u_char** pkt_data)
{
	ether_header* ether_hdr = (ether_header*)*pkt_data;
	TO_LITTLE(ether_hdr->type);

	switch (ether_hdr->type)
	{
		case IPv4:
		{
			ip_header* ip_hdr = (ip_header*)(ether_hdr + 1);
			TO_LITTLE(ip_hdr->len);
			TO_LITTLE(ip_hdr->id);
			TO_LITTLE(ip_hdr->off);
			TO_LITTLE(ip_hdr->sum);

			handleIp(ip_hdr);
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

void handleIp(const ip_header* ip_hdr)
{
	switch (ip_hdr->p)
	{
		case ICMP:
		{
			icmp_header* icmp_hdr = (icmp_header*)(ip_hdr + 1);
			TO_LITTLE(icmp_hdr->sum);

			break;
		}
		case TCP:
		{
			tcp_header* tcp_hdr = (tcp_header*)(ip_hdr + 1);
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
			udp_header* udp_hdr = (udp_header*)(ip_hdr + 1);
			TO_LITTLE(udp_hdr->sport);
			TO_LITTLE(udp_hdr->dport);
			TO_LITTLE(udp_hdr->tlen);
			TO_LITTLE(udp_hdr->sum);

			break;
		}
	}
}
