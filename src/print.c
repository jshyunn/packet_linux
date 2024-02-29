#include <time.h>
#include <string.h>

#include "../hdr/print.h"
#include "../hdr/pkt_parser.h"

int printStatistics(const struct pcap_pkthdr* header)
{
	double now_sec = 0, prev_sec = 0, bytes = 0;
	int idx = 0, cnt = 0;

	now_sec = (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1000000;
	if (now_sec - prev_sec > 1)
	{
		cnt = 0;
		bytes = 0;
		prev_sec = now_sec;
	}
	idx++;
	cnt++;
	bytes += header->caplen;
	printf("\nNo: %d\tPps: %d\tBps: %f MB/s", idx, cnt, bytes / 1000);
}

void printMAC(const mac_addr src, const mac_addr dst)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x ",
	src.byte1, src.byte2, src.byte3, 
	src.byte4, src.byte5, src.byte6,
	dst.byte1, dst.byte2, dst.byte3, 
	dst.byte4, dst.byte5, dst.byte6);
}

void printIP(const ip_addr src, const ip_addr dst)
{
	printf("%d.%d.%d.%d > %d.%d.%d.%d ",
	src.byte1, src.byte2, src.byte3, src.byte4,
	dst.byte1, dst.byte2, dst.byte3, dst.byte4);
}

void printIPwithPort(const ip_addr src, const ip_addr dst, const u_char sport, const u_char dport)
{
	printf("%d.%d.%d.%d:%d > %d.%d.%d.%d:%d ",
	src.byte1, src.byte2, src.byte3, src.byte4, sport,
	dst.byte1, dst.byte2, dst.byte3, dst.byte4, dport);
}

void printPkt(const struct pcap_pkthdr* pkt_hdr, const void* pkt_data)
{
	struct tm* ltime;
	char timesec[9];
	time_t local_tv_sec;
	ether_header* ether_hdr = getEther(pkt_data);
	char ether_type[10];
	char ip_type[10];

	local_tv_sec = pkt_hdr->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timesec, sizeof timesec, "%H:%M:%S", ltime);
	strcpy(ether_type, getEtherType(ether_hdr));
	printf("%s.%ld %s ", timesec, pkt_hdr->ts.tv_usec, ether_type);
	if (strcmp(ether_type, "IPv4") == 0)
	{
		ipv4_header* ipv4_hdr = getIPv4(pkt_data);
		strcpy(ip_type, getIPv4Type(ipv4_hdr));
		u_short sport = 0;
		u_short	dport = 0;
		if (strcmp(ip_type, "ICMP") == 0)
		{
			icmp_header* icmp_hdr = getICMP(pkt_data);
			releaseICMP(icmp_hdr);
		}
		else if (strcmp(ip_type, "UDP") == 0)
		{
			udp_header* udp_hdr = getUDP(pkt_data);
			sport = udp_hdr->sport;
			dport = udp_hdr->dport;
			releaseUDP(udp_hdr);
		}
		else if (strcmp(ip_type, "TCP") == 0)
		{
			tcp_header* tcp_hdr = getTCP(pkt_data);
			sport = tcp_hdr->sport;
			dport = tcp_hdr->dport;
			releaseTCP(tcp_hdr);
		}
		if (sport != 0)
			printIPwithPort(ipv4_hdr->src, ipv4_hdr->dst, sport, dport);
		else
			printIP(ipv4_hdr->src, ipv4_hdr->dst);
		printf("%s ", ip_type);
		releaseIPv4(ipv4_hdr);
	}
	else if (strcmp(ether_type, "ARP") == 0)
	{
		arp_header* arp_hdr = getARP(pkt_data);
		printMAC(arp_hdr->sha, arp_hdr->dha);
		releaseARP(arp_hdr);
	}
	printf("length %d\n", pkt_hdr->caplen);
	releaseEther(ether_hdr);
}

void printEther(const ether_header* ether_hdr)
{
	printMAC(ether_hdr->src, ether_hdr->dst);
	printf("Type %s", getEtherType(ether_hdr));
}

void printIPv4(const ipv4_header* ipv4_hdr)
{
	printf("Version: %d\n", ipv4_hdr->v);
	printf("Internet Header Length: %d\n", ipv4_hdr->hl * 4);
	printf("Type of Service: 0x%02x\n", ipv4_hdr->tos);
	printf("Total Length: %d\n", ipv4_hdr->len);
	printf("Fragment Identification: 0x%04x\n", ipv4_hdr->id);
	printf("Fragmentation Flags & Offset: %x\n", ipv4_hdr->off);
	printf("Time to Live: %d\n", ipv4_hdr->ttl);
	printf("Protocol: %d\n", ipv4_hdr->p);
	printf("Header Checksum : 0x%04x\n", ipv4_hdr->sum);
	printIP(ipv4_hdr->src, ipv4_hdr->dst);
}

void printArp(const arp_header* arp_hdr)
{
	printf("Hardware Type: 0x%04x\n", arp_hdr->hard);
	printf("Protocol Type: 0x%04x\n", arp_hdr->pro);
	printf("Hardware Size: %d\n", arp_hdr->hlen);
	printf("Protocol Size: %d\n", arp_hdr->plen);
	printf("Opcode: 0x%04x\n", arp_hdr->op);
	printMAC(arp_hdr->sha, arp_hdr->dha);
	printIP(arp_hdr->spa, arp_hdr->dpa);
}

void printIcmp(const icmp_header* icmp_hdr)
{

	printf("Type: 0x%02x\n", icmp_hdr->type);
	printf("Code: 0x%02x\n", icmp_hdr->code);
	printf("Checksum: 0x%04x\n", icmp_hdr->sum);
}

void printTcp(const tcp_header* tcp_hdr)
{
	printf("Seq: %u, Ack: %u\n", tcp_hdr->seq_num, tcp_hdr->ack_num);
	printf("Header Len: %d\n", (ntohs(tcp_hdr->hlen_flags & 0xf000) / 16 * 4));
	printf("Flags: 0x%03x\n", (tcp_hdr->hlen_flags & 0x0fff));
	printf("Window Size: %d\n", tcp_hdr->win_size);
	printf("Checksum: 0x%04x\n", tcp_hdr->sum);
	printf("Urgent Pointer: 0x%04x\n", tcp_hdr->ugt_ptr);
}

void printUdp(const udp_header* udp_hdr)
{
	printf("Total Length: %d\n", ntohs(udp_hdr->tlen));
	printf("Checksum: 0x%04x\n", ntohs(udp_hdr->sum));
}
