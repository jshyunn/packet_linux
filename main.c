#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "header/pkt_handler.h"

#ifdef _WIN32
#include <tchar.h>

BOOL LoadNpcapDlls() // Npcap을 설치했는지 확인하는 함수
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

// Prototype of Runnig Mode functions
int run_offline(pcap_t**, char*);
int run_live(pcap_t**, char*);

int main()
{
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls()) // Npcap이 설치되지 않았으면 종료
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

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
		scanf_s("%d", &Mode, sizeof(int));

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
		u_char* pkt_data = 0;

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
	char pcap_file_path[MAX_PATH + _MAX_FNAME];

	printf("Enter pcap file path: ");
	rewind(stdin);
	scanf_s("%s", pcap_file_path, MAX_PATH + _MAX_FNAME);

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

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) // Device 확인
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next) // Device list 나열
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
	scanf_s("%d", &inum, sizeof(int));

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 0;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((*fp = pcap_open_live(d->name,					// name of the device
							65536,						// portion of the packet to capture. 
														// 65536 grants that the whole packet will be captured on all the MACs.
							PCAP_OPENFLAG_PROMISCUOUS,	// promiscuous mode (nonzero means promiscuous)
							1000,						// read timeout
							errbuf						// error buffer
						)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 0;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	return 1;
}