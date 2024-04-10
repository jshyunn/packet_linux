#pragma once

#include <pcap.h>

#define MODE_ARGS (pcap_t**, char*, char*)

typedef struct option {
    int (*setMode) MODE_ARGS;
    int lflag;
    int rflag;
    int wflag;
    int sflag;
    int vflag;
} option;

int setLive MODE_ARGS;
int setOffline MODE_ARGS;