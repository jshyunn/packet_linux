#pragma once

#include "../hdr/protocol.h"

void mactostr(char*, int, const mac_addr);
void ipv4tostr(char*, int, const ipv4_addr);
void ipv6tostr(char*, int, const ipv6_addr);