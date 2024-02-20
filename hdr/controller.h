#pragma once

#include <pcap.h>

int setLive(pcap_t**);
int setOffline(pcap_t**, char*);