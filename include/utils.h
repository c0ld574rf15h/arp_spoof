#pragma once
#include "packet.h"

#define TRUE        1
#define FALSE       0
#define SUCCESS     0
#define FAIL        1
#define PROTO       1
#define HW          2
#define DEC         10
#define PERIOD      1
#define SESSION_MX  10

typedef struct session {
    BYTE sender_IP[IP_ADDR_LEN];
    BYTE target_IP[IP_ADDR_LEN];
    BYTE sender_MAC[HW_ADDR_LEN];
    BYTE target_MAC[HW_ADDR_LEN];
    BYTE sender_MAC_str[HW_ADDR_LEN<<1+1];
    BYTE target_MAC_str[HW_ADDR_LEN<<1+1];
}SESS;

int check_args(int argc, const char *exe);
void parse_bytes(BYTE *stream, char div, const char *str, int size, int base);
void addr_to_str(char *addr_str, const char *msg, const BYTE *addr);