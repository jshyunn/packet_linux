#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pcap.h>
#include <malloc.h>
#include "../hdr/pkt_io.h"
#include "../hdr/pkt_handler.h"

int setLive(pcap_t** fp)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error: %s\n", errbuf);
		return -1;
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return 0;
	}

	printf("Enter the interface number (1-%d): ", i);
	scanf("%d", &inum);
	fflush(stdin);

	if (inum < 1 || inum > i)
	{
		fprintf(stderr, "\nError: Interface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((*fp = pcap_open_live(d->name,					// name of the device
							65536,						// portion of the packet to capture. 
														// 65536 grants that the whole packet will be captured on all the MACs.
							PCAP_OPENFLAG_PROMISCUOUS,	// promiscuous mode (nonzero means promiscuous)
							1000,						// read timeout
							errbuf						// error buffer
						)) == NULL)
	{
		fprintf(stderr, "\nError: Unable to open the adapter. %s is not supported by Npcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);

	return 0;
}

int setOffline(pcap_t** fp, char* filepath)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((*fp = pcap_open_offline(filepath, errbuf)) == NULL)
	{
		fprintf(stderr, "Error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

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

void printFrame(const struct pcap_pkthdr* pkt_hdr)
{
	struct tm* ltime;
	char timesec[9];
	time_t local_tv_sec;

	local_tv_sec = pkt_hdr->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timesec, sizeof timesec, "%H:%M:%S", ltime);
	printf("\n=============================== Frame ================================\n");
	printf("Time: %s.%ld Frame Length: %d Capture Length: %d\n", timesec, pkt_hdr->ts.tv_usec, pkt_hdr->caplen, pkt_hdr->len);
}

void printEther(const ether_header* ether_hdr)
{
	char typestr[10];
	switch (ether_hdr->type)
	{
	case IPv4:
		strcpy(typestr, "IPv4");
		break;
	case ARP:
		strcpy(typestr, "ARP");
		break;
	case RARP:
		strcpy(typestr, "RARP");
		break;
	case VLAN:
		strcpy(typestr, "VLAN");
		break;
	case IPv6:
		strcpy(typestr, "IPv6");
		break;
	case LP:
		strcpy(typestr, "Loopbcak");
		break;
	}
	printf("============================== Ethernet ==============================\n");
	printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC: %02x:%02x:%02x:%02x:%02x:%02x Type: 0x%04x(%s)\n",
		ether_hdr->src.byte1, ether_hdr->src.byte2, ether_hdr->src.byte3, ether_hdr->src.byte4, ether_hdr->src.byte5, ether_hdr->src.byte6,
		ether_hdr->dst.byte1, ether_hdr->dst.byte2, ether_hdr->dst.byte3, ether_hdr->dst.byte4, ether_hdr->dst.byte5, ether_hdr->dst.byte6,
		ether_hdr->type, typestr);
}

void printIPv4(const ipv4_header* ipv4_hdr)
{
	char typestr[10];
	switch (ipv4_hdr->p)
	{
	case ICMP:
		strcpy(typestr, "ICMP");
		break;
	case TCP:
		strcpy(typestr, "TCP");	
		break;
	case UDP:
		strcpy(typestr, "UDP");
		break;
	}
	
	printf("=============================== IPv4 =================================\n");
	printf("Version: %d\n", ipv4_hdr->v);
	printf("Internet Header Length: %d\n", ipv4_hdr->hl * 4);
	printf("Type of Service: 0x%02x\n", ipv4_hdr->tos);
	printf("Total Length: %d\n", ipv4_hdr->len);
	printf("Fragment Identification: 0x%04x\n", ipv4_hdr->id);
	printf("Fragmentation Flags & Offset: %x\n", ipv4_hdr->off);
	printf("Time to Live: %d\n", ipv4_hdr->ttl);
	printf("Protocol: %d(%s)\n", ipv4_hdr->p, typestr);
	printf("Header Checksum : 0x%04x\n", ipv4_hdr->sum);
	printf("SRC IP: %d.%d.%d.%d -> DST IP: %d.%d.%d.%d\n",
		ipv4_hdr->src.byte1, ipv4_hdr->src.byte2, ipv4_hdr->src.byte3, ipv4_hdr->src.byte4,
		ipv4_hdr->dst.byte1, ipv4_hdr->dst.byte2, ipv4_hdr->dst.byte3, ipv4_hdr->dst.byte4);
}

/*void printArp(const ether_arp* arp_hdr)
{
	printf("================================ ARP =================================\n");
	printf("Hardware Type: 0x%04x\n", arp_hdr->hard);
	printf("Protocol Type: 0x%04x\n", arp_hdr->pro);
	printf("Hardware Size: %d\n", arp_hdr->hlen);
	printf("Protocol Size: %d\n", arp_hdr->plen);
	printf("Opcode: 0x%04x\n", arp_hdr->op);
	printf("Sender MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_hdr->sha.byte1, arp_hdr->sha.byte2, arp_hdr->sha.byte3, arp_hdr->sha.byte4, arp_hdr->sha.byte5, arp_hdr->sha.byte6);
	printf("Sender IP Address: %d.%d.%d.%d\n", arp_hdr->spa.byte1, arp_hdr->spa.byte2, arp_hdr->spa.byte3, arp_hdr->spa.byte4);
	printf("Target MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_hdr->dha.byte1, arp_hdr->dha.byte2, arp_hdr->dha.byte3, arp_hdr->dha.byte4, arp_hdr->dha.byte5, arp_hdr->dha.byte6);
	printf("Target IP Address: %d.%d.%d.%d\n", arp_hdr->dpa.byte1, arp_hdr->dpa.byte2, arp_hdr->dpa.byte3, arp_hdr->dpa.byte4);
}*/

void printIcmp(const icmp_header* icmp_hdr)
{

	printf("================================ ICMP ================================\n");
	printf("Type: 0x%02x\n", icmp_hdr->type);
	printf("Code: 0x%02x\n", icmp_hdr->code);
	printf("Checksum: 0x%04x\n", icmp_hdr->sum);
}

void printTcp(const tcp_header* tcp_hdr)
{
	printf("================================ TCP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", tcp_hdr->sport, tcp_hdr->dport);
	printf("Seq: %u, Ack: %u\n", tcp_hdr->seq_num, tcp_hdr->ack_num);
	printf("Header Len: %d\n", (ntohs(tcp_hdr->hlen_flags & 0xf000) / 16 * 4));
	printf("Flags: 0x%03x\n", (tcp_hdr->hlen_flags & 0x0fff));
	printf("Window Size: %d\n", tcp_hdr->win_size);
	printf("Checksum: 0x%04x\n", tcp_hdr->sum);
	printf("Urgent Pointer: 0x%04x\n", tcp_hdr->ugt_ptr);
}

void printUdp(const udp_header* udp_hdr)
{
	printf("================================ UDP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(udp_hdr->sport), ntohs(udp_hdr->dport));
	printf("Total Length: %d\n", ntohs(udp_hdr->tlen));
	printf("Checksum: 0x%04x\n", ntohs(udp_hdr->sum));
}
