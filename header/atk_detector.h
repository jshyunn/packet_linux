#pragma once

#include "protocol.h"
#include "pkt_handler.h"

void isLandAttack(const ip_header*, const Statistics); // Land Attack
void isPingofDeath(const ip_header*, const Statistics); // Ping of Death
void isUdpFlood(const ip_header*, const Statistics); // UDP Flood Attack
void isTcpSynFlood(const tcp_header*, Statistics*); // TCP SYN Flood Attack
void isSlowRead(const tcp_header*, Statistics*); // Slow Read Attack
void isHttpGetFlood(const tcp_header*, Statistics*); // HTTP Get Flood Attack


/* etc */
int containsBody(const u_char*);