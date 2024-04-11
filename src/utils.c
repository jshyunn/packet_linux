#include <string.h>

#include "../hdr/utils.h"

void mactostr(char* buf, int buf_size, const mac_addr mac)
{
	snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac.byte1, mac.byte2, mac.byte3, mac.byte4, mac.byte5, mac.byte6);
}

void ipv4tostr(char* buf, int buf_size, const ipv4_addr ip)
{
	snprintf(buf, buf_size, "%d.%d.%d.%d",
		ip.byte1, ip.byte2, ip.byte3, ip.byte4);
}

void ipv6tostr(char* buf, int buf_size, const ipv6_addr ip)
{
	snprintf(buf, buf_size, "%x:%x:%x:%x:%x:%x:%x:%x",
		ntohs(ip.byte1), ntohs(ip.byte2), ntohs(ip.byte3), ntohs(ip.byte4), 
		ntohs(ip.byte5), ntohs(ip.byte6), ntohs(ip.byte7), ntohs(ip.byte8));
}