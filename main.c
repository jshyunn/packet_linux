#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "print.h"
#include "option.h"

#define SHORTOPT "lr:w:sv"

void printUsage(char* filename)
{
	printf("Usage: %s [MODE] [OPTION]\n"
	"\tMODE\n"
	"\t\t[ -l ]\n" 			// live
	"\t\t[ -r file ]\n" 	// offline
	"\tOPTION\n"
	"\t\t[ -w file ]\n" 	// write
	"\t\t[ -s ]\n" 			// statistics
	"\t\t[ -v ]\n", 		// verbose
	filename);
}

int main(int argc, char* argv[])
{
	int opt, status;
	option u_opt;
	char *read_file, *write_file;
	pcap_t* pcap_fp;
	pcap_dumper_t* pcap_dfp = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* pkt_hdr;
	const u_char* pkt_data;
	print_info pi;

	if (argc < 2) 
	{
		printUsage(argv[0]);
		exit(1);
	}

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
				read_file = optarg;
				break;
			}
			case 'w':
			{
				++u_opt.wflag;
				write_file = optarg;
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

	if (u_opt.setMode(&pcap_fp, read_file, errbuf) == -1) {
		fprintf(stderr, "Error: %s\n", errbuf);
		exit(1);
	}

	if (u_opt.wflag) {
		if ((pcap_dfp = pcap_dump_open(pcap_fp, write_file)) == NULL) {
			fprintf(stderr, "Error: %s\n", pcap_geterr(pcap_fp));
			exit(1);
		}
	}

	while ((status = pcap_next_ex(pcap_fp, &pkt_hdr, &pkt_data)) >= 0) {
		if (status == 0) continue;
		if (pkt_hdr->len < 14) continue;
		if (pcap_dfp) pcap_dump((u_char*)pcap_dfp, pkt_hdr, pkt_data);
		
		setPrintInfo(&pi, pkt_hdr, pkt_data);
		print(pi);
	}
	
	if (status == -1) {
		fprintf(stderr, "Error: %s\n", pcap_geterr(pcap_fp));
		exit(1);
	}

	pcap_close(pcap_fp);
	exit(0);
}
