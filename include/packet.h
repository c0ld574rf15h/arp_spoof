#pragma once
#include <pcap.h>

// Type definition for convenience
typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;

#define HW_ADDR_LEN     6
#define IP_ADDR_LEN     4
#define SZ_ETHERNET     14
#define TYPE_ETH        0x0001
#define TYPE_ARP        0X0806
#define TYPE_IPV4       0x0800
#define DONT_CARE       0
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

typedef struct ip_hdr {
    BYTE ver_hdl, tos;
    WORD ip_len;
    WORD id, frag_off;
    BYTE ttl, protocol;
    WORD hdr_checksum;
    BYTE src_addr[IP_ADDR_LEN], dst_addr[IP_ADDR_LEN];
} IP;

typedef struct arp_packet {
    ETH eth_hdr;
    ARP arp_hdr;
} ARP_PKT;

typedef struct ip_packet {
    ETH eth_hdr;
    IP  ip_hdr;
} IP_PKT;

int pcap_next_handler(int res, struct pcap_pkthdr *hdr);
void send_arp(pcap_t *handle, int opcode, BYTE *snd_mac, BYTE *snd_ip, BYTE *trg_mac, BYTE *trg_ip);
int check_relay(const BYTE *data, const BYTE *sender_MAC, const BYTE *attacker_IP);
int check_request(const BYTE *data, const BYTE *sender_MAC, const BYTE *attacker_IP);