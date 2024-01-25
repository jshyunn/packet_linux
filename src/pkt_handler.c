#include <stdio.h>
#include <string.h>
#include "../hdr/pkt_handler.h"

Statistics stat = { 0 };

void handleFrame(const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data)
{
	double now = (double)pkt_hdr->ts.tv_sec + (double)pkt_hdr->ts.tv_usec / 1000000;
	if (now - stat.prev_t > 1)
	{
		memset(&stat, 0, sizeof(stat));
		stat.prev_t = now;
	}
	stat.byte += (pkt_hdr->caplen * 8);
	stat.pkt++;

	ether_header* ether_hdr = (ether_header*)pkt_data;
	ether_hdr->type = ntohs(ether_hdr->type);
	handleEther(ether_hdr);
}

void handleEther(const ether_header* ether_hdr)
{
	ether_type type = ether_hdr->type;
	switch (type)
	{
		case IPv4:
		{
			ip_header* ip_hdr = (ip_header*)(ether_hdr + 1);
			ip_hdr->tlen = ntohs(ip_hdr->tlen); // convert byte order (big endian(network) -> little(windows))
			ip_hdr->id = ntohs(ip_hdr->id);
			ip_hdr->off = ntohs(ip_hdr->off);
			ip_hdr->checksum = ntohs(ip_hdr->checksum);
			handleIp(ip_hdr);
			break;
		}
		case ARP:
		{
			arp_header* arp_hdr = (arp_header*)(ether_hdr + 1);
			arp_hdr->hard = ntohs(arp_hdr->hard);
			arp_hdr->pro = ntohs(arp_hdr->pro);
			arp_hdr->op = ntohs(arp_hdr->op);
			break;
		}
	}
}

void handleIp(const ip_header* ip_hdr)
{
	ip_type type = ip_hdr->pro;
	switch (type)
	{
		case ICMP:
		{
			icmp_header* icmp_hdr = (icmp_header*)(ip_hdr + 1);
			icmp_hdr->checksum = ntohs(icmp_hdr->checksum);
			stat.icmp += 1;
			break;
		}
		case TCP:
		{
			tcp_header* tcp_hdr = (tcp_header*)(ip_hdr + 1);
			tcp_hdr->sport = (int)ntohs(tcp_hdr->sport);
			tcp_hdr->dport = (int)ntohs(tcp_hdr->dport);
			tcp_hdr->seq_num = ntohl(tcp_hdr->seq_num);
			tcp_hdr->ack_num = ntohl(tcp_hdr->ack_num);
			tcp_hdr->hlen_flags = ntohs(tcp_hdr->hlen_flags);
			tcp_hdr->win_size = (int)ntohs(tcp_hdr->win_size);
			tcp_hdr->checksum = ntohs(tcp_hdr->checksum);
			tcp_hdr->urgent_ptr = ntohs(tcp_hdr->urgent_ptr);
			stat.tcp += 1;
			break;
		}
		case UDP:
		{
			udp_header* udp_hdr = (udp_header*)(ip_hdr + 1);
			udp_hdr->sport = (int)ntohs(udp_hdr->sport);
			udp_hdr->dport = (int)ntohs(udp_hdr->dport);
			udp_hdr->tlen = (int)ntohs(udp_hdr->tlen);
			udp_hdr->checksum = ntohs(udp_hdr->checksum);
			stat.udp += 1;
			break;
		}
	}
}

