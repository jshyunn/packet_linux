#include <stdio.h>
#include <unistd.h>
#include "hdr/pkt_io.h"
#include "hdr/pkt_handler.h"
/*

+ 사용자는 잘 몰라도 사용할 수 있는 인터페이스 제공
+ 멀티스레딩 - 캡처 중지 신호 대기

1. 모드 및 옵션 선택
2. 패킷 처리 -> 파싱된 자료 반환
3. 반환된 자료로 옵션 수행
4. 정지나 종료 후 저장 여부

*/

void printUsage(char* command)
{
	printf("Usage: %s [MODE] [OPTION]\n"
	"\tMODE\n"
	"\t\t[ -l ]\n" // live
	"\t\t[ -r file ]\n" // offline
	"\tOPTION\n"
	"\t\t[ -w file ]\n" // write
	"\t\t[ -f file ]\n" // filter
	"\t\t[ -d file ]\n" // detection
	"\t\t[ -s ]\n" // statistics
    "\t\t[ -v ]\n", // verbose
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
		if (res == 0)
			continue;

		if (pkt_hdr->len < 14) continue;

		// 패킷 처리
		// 옵션 처리
		processPkt(&pkt_data);
		printEther((ether_header*)pkt_data);
		printIp((ip_header*)((ether_header*)pkt_data + 1));
	}
	
	if (res == -1) {
		fprintf(stderr, "Error: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	return 0;
}
