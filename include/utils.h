#pragma once

#define TRUE    1
#define FALSE   0
#define SUCCESS 0
#define FAIL    1
#define PROTO   1
#define HW      2
#define DEC     10

void check_args(const char *msg);
void parse_bytes(BYTE *stream, char div, const char *str, int size, int base);
void addr_to_str(char *addr_str, const char *msg, const BYTE *addr);