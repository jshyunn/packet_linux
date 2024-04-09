#include <string.h>

#include "../hdr/utils.h"

void mactostr(char* buf, int buf_size, const mac_addr mac)
{
	snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac.byte1, mac.byte2, mac.byte3, mac.byte4, mac.byte5, mac.byte6);
}

void iptostr(char* buf, int buf_size, const ip_addr ip)
{
	snprintf(buf, buf_size, "%d.%d.%d.%d",
		ip.byte1, ip.byte2, ip.byte3, ip.byte4);
}