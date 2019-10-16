#include "packet.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_args(int argc, const char *exe) {
    if(argc != 4) {
        fprintf(stderr, "[-] Usage : %s <interface> <victim IP> <gateway IP>");
        return FAIL;
    }
    else return SUCCESS;
}

void parse_bytes(BYTE *stream, char div, const char *str, int size, int base) {
    for(int i = 0; i < size; ++i) {
        stream[i] = strtoul(str, NULL, base);
        str = strchr(str, div);     // move pointer to divider
        if(str == NULL || *str == '\0') break;
        str += 1;
    }
}

void addr_to_str(char *addr_str, const char *msg, const BYTE *addr) {
    for(int i = 0; i < HW_ADDR_LEN; ++i) sprintf(&addr_str[i << 1], "%02X", addr[i]);
    addr_str[HW_ADDR_LEN << 1] = '\0';
    printf("[+] %s : %s\n", msg, addr_str);
}