#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "hdr/pkt_io.h"

int main()
{
	while (1)
	{
		if (run() == 0) break;
	}
}
