#pragma once
#include "packet.h"

int filter_ARP(int opcode, const BYTE *data);
int filter_src(int type, const BYTE *addr, const BYTE *data);
int filter_dst(int type, const BYTE *addr, const BYTE *data);