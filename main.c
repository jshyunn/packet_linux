#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "hdr/pkt_handler.h"

// Prototype of Runnig Mode functions
int run_offline(pcap_t**, char*);
int run_live(pcap_t**, char*);

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* fp = { 0 };

	while (1) 
	{
		int Mode = 0;
		int (*run_type[2])(pcap_t**, char*) = {
			run_offline,
			run_live
		};

		puts("\n====================== Intrusion Detection Tool ======================\n");
		puts("[1] Offline\n[2] Live\n");
		puts("Enter the mode: ");

		rewind(stdin);
		scanf("%d", &Mode);

		if (Mode < 1 || Mode > 2)
		{
			fprintf(stderr, "Invalid Mode Number: %d\n", Mode);
			continue;
		}

		if (run_type[Mode - 1](&fp, errbuf) == -1)
		{
			fprintf(stderr, "\nError: %s.\n", errbuf);
			continue;
		}
		
		int res;
		int idx = 0;;
		struct pcap_pkthdr* header = { 0 };
		const u_char* pkt_data = 0;

		/* Retrieve the packets */
		while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
			
			if (res == 0)
				/* Timeout elapsed */
				continue;

			if (header->len < 14) continue;

			idx += 1;
			printf("\nNo: %d", idx);
			handleFrame(header, pkt_data);
		}

		if (res == -1) {
			printf("Error reading the packets: %s\n", pcap_geterr(fp));
			return -1;
		}

		pcap_close(fp);
	}
}

int run_offline(pcap_t** fp, char* errbuf)
{
	char pcap_file_path[FILENAME_MAX];

	printf("Enter pcap file path: ");
	rewind(stdin);
	scanf("%s", pcap_file_path);

	/* Open the capture file */
	if ((*fp = pcap_open_offline(pcap_file_path, errbuf)) == NULL)
	{
		//printf("\nUnable to open the file: %s.\n", pcap_file_path);
		return -1;
	}
	return 0;
}

int run_live(pcap_t** fp, char* errbuf)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
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
	rewind(stdin);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
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
		printf("\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);

	return 0;
}