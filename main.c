#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "hdr/print.h"
#include "hdr/option.h"

#define SHORTOPT "lr:w:f:d:sv"

void printUsage(char* filename)
{
	printf("Usage: ./%s [MODE] [OPTION]\n"
	"\tMODE\n"
	"\t\t[ -l ]\n" 			// live
	"\t\t[ -r file ]\n" 	// offline
	"\tOPTION\n"
	"\t\t[ -w file ]\n" 	// write
	"\t\t[ -f file ]\n" 	// filter
	"\t\t[ -d file ]\n" 	// detection
	"\t\t[ -s ]\n" 			// statistics
	"\t\t[ -v ]\n", 		// verbose
	filename);
}

int main(int argc, char* argv[])
{
	if (argc < 2) 
	{
		printUsage(argv[0]);
		exit(1);
	}

	int opt;
	option u_opt;
	char* mode_arg;
	
	memset(&u_opt, 0, sizeof(u_opt));

	while ((opt = getopt(argc, argv, SHORTOPT)) != -1) {
		switch (opt)
		{
			case 'l':
			{
				++u_opt.lflag;
				u_opt.setMode = setLive;
				break;
			}
			case 'r':
			{
				++u_opt.rflag;
				u_opt.setMode = setOffline;
				mode_arg = optarg;
				break;
			}
			case 'w':
			{
				++u_opt.wflag;
				break;
			}
			case 'f':
			{
				++u_opt.fflag;
				break;
			}
			case 'd':
			{
				++u_opt.dflag;
				break;
			}
			case 'v':
			{
				++u_opt.vflag;
				break;
			}
			case 's':
			{
				++u_opt.sflag;
				break;
			}
			default:
			{
				printUsage(argv[0]);
				exit(1);
			}
		}
	}

	if (u_opt.lflag && u_opt.rflag) {
		fputs("Error: -l and -r are mutually exclusive.\n", stderr);
		exit(1);
	}

	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (u_opt.setMode(&fp, mode_arg, errbuf) == -1) {
		fprintf(stderr, "Error: %s\n", errbuf);
		exit(1);
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
		exit(1);
	}

	pcap_close(fp);
	exit(0);
}
