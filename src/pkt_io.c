#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include "../hdr/pkt_io.h"

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

int processPkt(pcap_t** fp)
{
	int res;
	int idx = 0, cnt = 0;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	double now_sec, prev_sec = 0, bytes = 0;
	pthread_t p_thread;

	while ((res = pcap_next_ex(*fp, &header, &pkt_data)) >= 0) {
		if (res == 0)
			continue;

		if (header->len < 14) continue;

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
		handleFrame(header, pkt_data);
	}
	
	if (res == -1) {
		fprintf(stderr, "Error: %s\n", pcap_geterr(*fp));
		return -1;
	}

	pcap_close(*fp);
	return 0;
}

void printFrame(const struct pcap_pkthdr* pkt_hdr)
{
	struct tm* ltime;
	char timesec[9];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = pkt_hdr->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timesec, sizeof timesec, "%H:%M:%S", ltime);
	printf("\n=============================== Frame ================================\n");
	printf("Time: %s.%ld Frame Length: %d Capture Length: %d\n", timesec, pkt_hdr->ts.tv_usec, pkt_hdr->caplen, pkt_hdr->len);
}

void printEther(const ether_header* ether_hdr)
{
	ether_type type = ether_hdr->type;
	char typestr[10] = "";
	switch (type)
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
	case IPv6:
		strcpy(typestr, "IPv6");
		break;
	}
	printf("============================== Ethernet ==============================\n");
	printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC: %02x:%02x:%02x:%02x:%02x:%02x Type: 0x%04x(%s)\n",
		ether_hdr->src.byte1, ether_hdr->src.byte2, ether_hdr->src.byte3, ether_hdr->src.byte4, ether_hdr->src.byte5, ether_hdr->src.byte6,
		ether_hdr->dst.byte1, ether_hdr->dst.byte2, ether_hdr->dst.byte3, ether_hdr->dst.byte4, ether_hdr->dst.byte5, ether_hdr->dst.byte6,
		type, typestr);
}

void printIp(const ip_header* ip_hdr)
{
	ip_type type = ip_hdr->pro;
	char typestr[10] = "";
	switch (type)
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
	printf("Version: %d\n", (int)(ip_hdr->ver_ihl & 0xf0) / 16);
	printf("Internet Header Length: %d\n", (int)(ip_hdr->ver_ihl & 0x0f) * 4);
	printf("Type of Service: 0x%02x\n", ip_hdr->tos);
	printf("Total Length: %d\n", ip_hdr->tlen);
	printf("Fragment Identification: 0x%04x\n", ip_hdr->id);
	printf("Fragmentation Flags & Offset: %x\n", ip_hdr->off);
	printf("Time to Live: %d\n", ip_hdr->ttl);
	printf("Protocol: %d(%s)\n", type, typestr);
	printf("Header Checksum : 0x%04x\n", ip_hdr->checksum);
	printf("SRC IP: %d.%d.%d.%d -> DST IP: %d.%d.%d.%d\n",
		ip_hdr->src.byte1, ip_hdr->src.byte2, ip_hdr->src.byte3, ip_hdr->src.byte4,
		ip_hdr->dst.byte1, ip_hdr->dst.byte2, ip_hdr->dst.byte3, ip_hdr->dst.byte4);
}

void printArp(const arp_header* arp_data)
{
	printf("================================ ARP =================================\n");
	printf("Hardware Type: 0x%04x\n", arp_data->hard);
	printf("Protocol Type: 0x%04x\n", arp_data->pro);
	printf("Hardware Size: %d\n", arp_data->hlen);
	printf("Protocol Size: %d\n", arp_data->plen);
	printf("Opcode: 0x%04x\n", arp_data->op);
	printf("Sender MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_data->sha.byte1, arp_data->sha.byte2, arp_data->sha.byte3, arp_data->sha.byte4, arp_data->sha.byte5, arp_data->sha.byte6);
	printf("Sender IP Address: %d.%d.%d.%d\n", arp_data->spa.byte1, arp_data->spa.byte2, arp_data->spa.byte3, arp_data->spa.byte4);
	printf("Target MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_data->dha.byte1, arp_data->dha.byte2, arp_data->dha.byte3, arp_data->dha.byte4, arp_data->dha.byte5, arp_data->dha.byte6);
	printf("Target IP Address: %d.%d.%d.%d\n", arp_data->dpa.byte1, arp_data->dpa.byte2, arp_data->dpa.byte3, arp_data->dpa.byte4);
}

void printIcmp(const icmp_header* icmp_hdr)
{

	printf("================================ ICMP ================================\n");
	printf("Type: 0x%02x\n", icmp_hdr->type);
	printf("Code: 0x%02x\n", icmp_hdr->code);
	printf("Checksum: 0x%04x\n", icmp_hdr->checksum);
}

void printTcp(const tcp_header* tcp_hdr)
{
	//TODO : Flag Ç¥Çö
	printf("================================ TCP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", tcp_hdr->sport, tcp_hdr->dport);
	printf("Seq: %u, Ack: %u\n", tcp_hdr->seq_num, tcp_hdr->ack_num);
	printf("Header Len: %d\n", (ntohs(tcp_hdr->hlen_flags & 0xf000) / 16 * 4));
	printf("Flags: 0x%03x\n", (tcp_hdr->hlen_flags & 0x0fff));
	printf("Window Size: %d\n", tcp_hdr->win_size);
	printf("Checksum: 0x%04x\n", tcp_hdr->checksum);
	printf("Urgent Pointer: 0x%04x\n", tcp_hdr->urgent_ptr);
}

void printUdp(const udp_header* udp_hdr)
{
	printf("================================ UDP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(udp_hdr->sport), ntohs(udp_hdr->dport));
	printf("Total Length: %d\n", ntohs(udp_hdr->tlen));
	printf("Checksum: 0x%04x\n", ntohs(udp_hdr->checksum));
}
