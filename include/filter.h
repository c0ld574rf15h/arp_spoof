#pragma once
#include "packet.h"

int filter_ARP(int opcode);
int filter_snd(int type, const BYTE *addr);
int filter_dst(int type, const BYTE *addr);