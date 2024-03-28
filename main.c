#include <stdio.h>
#include <unistd.h>
#include "hdr/print.h"
#include "hdr/ui.h"

void printUsage(char* command)
{
	printf("Usage: ./%s [MODE] [OPTION]\n"
	"\tMODE\n"
	"\t\t[ -l ]\n" 		// live
	"\t\t[ -r file ]\n" 	// offline
	"\tOPTION\n"
	"\t\t[ -w file ]\n" 	// write
	"\t\t[ -f file ]\n" 	// filter
	"\t\t[ -d file ]\n" 	// detection
	"\t\t[ -s ]\n" 		// statistics
	"\t\t[ -v ]\n", 	// verbose
	command);
}

int main(int argc, char* argv[])
{
	char opt;
	pcap_t* fp;

	if (argc < 2) 
	{
		printUsage(argv[0]);
		return -1;
	}

	while ((opt = getopt(argc, argv, "lr:w:f:d:sv")) != -1) {
		switch (opt)
		{
			case 'l':
			{
				if (setLive(&fp) == -1)
					return -1;
				break;
			}
			case 'r':
			{
				if (setOffline(&fp, optarg) == -1)
					return -1;
				break;
			}
			case 'w':
			{
				//setWrite
				break;
			}
			case 'f':
			{
				//setFilterRule
				break;
			}
			case 'd':
			{
				//setDetectionRule
				break;
			}
			case 'v':
			{
				//setVerbose
				break;
			}
			case 's':
			{
				//setStatistics
				break;
			}
			default:
			{
				printUsage(argv[0]);
				return -1;
			}
		}
	}

	int res;
	struct pcap_pkthdr* pkt_hdr;
	const u_char* pkt_data;

	while ((res = pcap_next_ex(fp, &pkt_hdr, &pkt_data)) >= 0) {
		if (res == 0) continue;
		if (pkt_hdr->len < 14) continue;

		printPkt(pkt_hdr, pkt_data);	
	}
	
	if (res == -1) {
		fprintf(stderr, "Error: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	return 0;
}
