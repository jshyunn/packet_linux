#include <stdio.h>
#include <time.h>
#include <string.h>
#include "../hdr/ui.h"

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
