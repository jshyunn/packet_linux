#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "hdr/pkt_io.h"
/*

����ڴ� �� ���� ����� �� �ִ� �������̽� ����

1. �ɼ�(���) ����
2. ��Ŷ ó��(���� ���)
3. ���� �� ���� ����

*/

void printUsage(char* command)
{
	printf("Usage: %s [OPTION] [ARGS]\n"
	"\t\t[ -l live ]\n"
	"\t\t[ -o offline ] [FILEPATH]\n", 
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

	if ((opt = getopt(argc, argv, "lo:")) != -1) {
		printf("%c\n", opt);
		switch (opt)
		{
			case 'l':
			{
				if (setLive(&fp) == -1)
					return -1;
				break;
			}
			case 'o':
			{
				if (setOffline(&fp, optarg) == -1)
					return -1;
				break;
			}
			default:
			{
				printUsage(argv[0]);
				return -1;
			}
		}
	}

	parsePkt(&fp);
}