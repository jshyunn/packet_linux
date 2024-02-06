#include <stdio.h>
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
	printf("Usage: %s [OPTION]\n"
	"\t\t[ -l ]\n"
	"\t\t[ -o file ]\n"
        "\t\t[ -v ]\n",	
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

	while ((opt = getopt(argc, argv, "lo:v")) != -1) {
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
			case 'v':
			{
				//setVerbose
				//break;
			}
			default:
			{
				printUsage(argv[0]);
				return -1;
			}
		}
	}
	processPkt(&fp);
}
