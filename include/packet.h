#pragma once
#include <pcap.h>

// Type definition for convenience
typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;

#define HW_ADDR_LEN     6
#define IP_ADDR_LEN     4
#define SZ_ETHERNET     14
#define TYPE_ARP        0X0806
#define TYPE_IPV4       0x0800
#define OP_REQ          1
#define OP_RES          2

typedef struct eth_hdr {
    BYTE dst_hw_addr[HW_ADDR_LEN];
    BYTE src_hw_addr[HW_ADDR_LEN];
    WORD eth_type;
} ETH;

typedef struct arp_hdr {
    WORD hw_type, proto_type;
    BYTE hw_addr_len, proto_addr_len;
    WORD opcode;
    BYTE snd_hw_addr[HW_ADDR_LEN], snd_proto_addr[IP_ADDR_LEN];
    BYTE trg_hw_addr[HW_ADDR_LEN], trg_proto_addr[IP_ADDR_LEN];
} ARP;

typedef struct arp_packet {
    ETH eth_hdr;
    ARP arp_hdr;
};

int pcap_next_handler(int res, struct pcap_pkthdr *hdr);