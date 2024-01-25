#include "../header/atk_detector.h"

#define Threshold 100

void isLandAttack(const ip_header* ip_hdr, const Statistics stat)
{
	if (!memcmp(&ip_hdr->src, &ip_hdr->dst, sizeof(ip_addr)) && stat.icmp > Threshold)
		printf("################################## Waring: Land Attack Occured!!!!!! ##############################\n");
}

void isPingofDeath(const ip_header* ip_hdr, const Statistics stat)
{
	char flags[17];
	_itoa((int)ip_hdr->off, flags, 2);
	if (flags[0] == '1' && (int)ip_hdr->tlen == 1500 && stat.icmp > Threshold)
		printf("################################## Warning: Ping of Death!!!!!! ###################################\n");
}

void isUdpFlood(const ip_header* ip_hdr, const Statistics stat)
{
	char flags[17];
	_itoa((int)ip_hdr->off, flags, 2);
	if (flags[0] == '1' && (int)ip_hdr->tlen == 1500 && stat.udp > Threshold)
		printf("################################ Warning: UDP Flood Attack!!!!!! ##################################\n");
}

void isTcpSynFlood(const tcp_header* tcp_hdr, Statistics* stat)
{
	if (((tcp_hdr->hlen_flags & 0x0fff) & SYN) == SYN)
		stat->syn_f += 1;

		if (stat->syn_f > Threshold)
			printf("############################## Warning: TCP SYN Flood Attack!!!!!! ################################\n");
}

void isSlowRead(const tcp_header* tcp_hdr, Statistics* stat)
{
	if (tcp_hdr->win_size == 0)
		stat->zerowin += 1;

		if (stat->zerowin > Threshold)
			printf("################################ Warning: Slow Read Attack!!!!!! ##################################\n");
}

void isHttpGetFlood(const tcp_header* tcp_hdr, Statistics* stat)
{
	if (strstr((u_char*)(tcp_hdr + 1), "GET") && containsBody((u_char*)(tcp_hdr + 1)) == 0)
		stat->get_f += 1;

		if (stat->get_f > Threshold)
			printf("############################# Warning: HTTP GET Flood Attack!!!!!! ################################\n");
}




int containsBody(const u_char* data) {
	for (int i = 0; data[i + 3] != '\0'; ++i) {
		if (data[i] == 0x0d && data[i + 1] == 0x0a && data[i + 2] == 0x0d && data[i + 3] == 0x0a) {
			return 1;
		}
	}
	return 0;
}