#include <time.h>
#include <string.h>

#include "../hdr/print.h"
#include "../hdr/utils.h"

#define Broadcast "ff:ff:ff:ff:ff:ff"
#define STP "01:80:c2:00:00:00"

const typemap ether_type_map[] = {
	{ 0x0600,	"Xerox XNS IDP" },
	{ 0x0800,	"IPv4" },
	{ 0x0805,	"X.25" },
	{ 0x0806,	"ARP" },
	{ 0x0835,	"RARP" },
	{ 0x6003,	"DEC DECnet Phase IV" },
	{ 0x8100,	"VLAN ID" },
	{ 0x8137,	"Novell Netware IPX" },
	{ 0x8191,	"NetBIOS" },
	{ 0x86dd,	"IPv6" },
	{ 0x8847,	"MPLS" },
	{ 0x8863,	"PPPoE Discovery Stage" },
	{ 0x8864,	"PPPoE PPP Session Stage" },
	{ 0x888E,	"IEEE 802.1X" },
	{ 0x88CC,	"LLDP" },
	{ 0,		"NULL" },
};

const typemap ipv4_type_map[] = {
	{ 1,	"ICMP" },
	{ 2,	"IGMP" },
	{ 6,	"TCP" },
	{ 8,	"EGP" },
	{ 17,	"UDP" },
	{ 89,	"OSPF" },
};

const typemap ipv6_type_map[] = {
	{ 0,	"Hop-by-Hop Options for IPv6" },
	{ 6,	"TCP" },
	{ 17,	"UDP" },
	{ 58,	"ICMPv6" },
};

void print(print_info pi)
{
	printf("%s %s %s > %s length: %d", pi.time, pi.protocol, pi.src, pi.dst, pi.len);
	if (strcmp(pi.info, ""))
		printf(" info: %s", pi.info);
	puts("");
}

void setPrintInfo(print_info* pi, const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data)
{
	struct tm* ltime;

	ltime = localtime(&pkt_hdr->ts.tv_sec);
	snprintf(pi->time, sizeof(pi->time), "%02d:%02d:%02d.%06ld",
		ltime->tm_hour, ltime->tm_min, ltime->tm_sec, pkt_hdr->ts.tv_usec);
	pi->len = pkt_hdr->caplen;
	setEtherInfo(pi, pkt_data);	
}

void setEtherInfo(print_info* pi, const u_char* pkt_data)
{
	const typemap* tm;
	char src[18];
	char dst[18];

	ether_header* ether_hdr = (ether_header*)pkt_data;

	mactostr(src, sizeof(src), ether_hdr->src);
	mactostr(dst, sizeof(dst), ether_hdr->dst);

	// set protocol
	strcpy(pi->protocol, "NULL");
	for (tm = ether_type_map; tm->str; ++tm)
		if (tm->val == ntohs(ether_hdr->type)) {
			strcpy(pi->protocol, tm->str);
			break;
		}
	if (strcmp(dst, STP) == 0)
		strcpy(pi->protocol, "STP");

	// set src, dst addr
	if (strcmp(dst, Broadcast) == 0)
		strcpy(dst, "Broadcast");
	strcpy(pi->src, src);
	strcpy(pi->dst, dst);

	// set info
	strcpy(pi->info, "");

	if (strcmp(pi->protocol, "IPv4") == 0)
		setIPv4Info(pi, pkt_data + sizeof(ether_header));
	if (strcmp(pi->protocol, "ARP") == 0)
		setARPInfo(pi, pkt_data + sizeof(ether_header));
	if (strcmp(pi->protocol, "STP") == 0)
		setSTPInfo(pi, pkt_data + sizeof(ether_header));
	if (strcmp(pi->protocol, "IPv6") == 0)
		setIPv6Info(pi, pkt_data + sizeof(ether_header));
}

void setIPv4Info(print_info* pi, const u_char* pkt_data)
{
	const typemap* tm;
	char src[16];
	char dst[16];

	ipv4_header* ipv4_hdr = (ipv4_header*)pkt_data;

	ipv4tostr(src, sizeof(src), ipv4_hdr->src);
	ipv4tostr(dst, sizeof(dst), ipv4_hdr->dst);

	// set protocol
	for (tm = ipv4_type_map; tm->str; ++tm)
		if (tm->val == ipv4_hdr->p) {
			strcpy(pi->protocol, tm->str);
			break;
		}

	// set src, dst addr
	strcpy(pi->src, src);
	strcpy(pi->dst, dst);
}

void setIPv6Info(print_info* pi, const u_char* pkt_data)
{
	const typemap* tm;
	char src[40];
	char dst[40];

	ipv6_header* ipv6_hdr = (ipv6_header*)pkt_data;
	
	ipv6tostr(src, sizeof(src), ipv6_hdr->src);
	ipv6tostr(dst, sizeof(dst), ipv6_hdr->dst);

	// set protocol
	for (tm = ipv6_type_map; tm->str; ++tm)
		if (tm->val == ipv6_hdr->nhdr) {
			strcpy(pi->protocol, tm->str);
			break;
		}

	// set src, dst addr
	strcpy(pi->src, src);
	strcpy(pi->dst, dst);
}

void setARPInfo(print_info* pi, const u_char* pkt_data)
{
	arp_header* arp_hdr = (arp_header*)pkt_data;

	switch (ntohs(arp_hdr->op))
	{
		case 1: // Request
		{
			char src[16];
			char dst[16];

			ipv4tostr(src, sizeof(src), arp_hdr->spa);
			ipv4tostr(dst, sizeof(dst), arp_hdr->dpa);

			snprintf(pi->info, sizeof(pi->info), "Who has %s? Tell %s", dst, src);
			break;
		}
		case 2: // Response
		{
			char buf[16];

			ipv4tostr(buf, sizeof(buf), arp_hdr->spa);

			snprintf(pi->info, sizeof(pi->info), "%s is at %s", buf, pi->src);
			break;
		}
		default:
		{
			snprintf(pi->info, sizeof(pi->info), "Not Supported");
			break;
		}
	}
}

void setSTPInfo(print_info* pi, const u_char* pkt_data)
{
	llc_stp_tcn_header* stp_hdr = (llc_stp_tcn_header*)pkt_data;

	if (stp_hdr->bpdu_type == 0x00) {// Configuration BPDUs
		char root_id_buf[18];
		char root_id[30];
		
		llc_stp_conf_header* stp_hdr = (llc_stp_conf_header*)pkt_data;

		mactostr(root_id_buf, sizeof(root_id_buf), stp_hdr->root_id);

		snprintf(root_id, sizeof(root_id), "%d/%x/%s", 
			ntohs(stp_hdr->root_prior), stp_hdr->root_prior >> 8, root_id_buf);

		snprintf(pi->info, sizeof(pi->info), "Conf. Root = %s Cost = %d Port = 0x%04x",
			root_id, ntohs(stp_hdr->cost), ntohs(stp_hdr->port));
	}
	else if (stp_hdr->bpdu_type == 0x80) // TCN BPDUs
		strcpy(pi->info, "Topology Change Notification");
}

/*
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
}*/