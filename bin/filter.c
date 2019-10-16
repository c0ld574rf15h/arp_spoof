#include <arpa/inet.h>
#include "filter.h"
#include "utils.h"

int filter_ARP(int opcode, const BYTE *data) {
    ETH *eth_hdr = (ETH*)data;
    if(eth_hdr -> eth_type == ntohs(TYPE_ARP)) {
        ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
        return (arp_hdr -> opcode == ntohs(opcode)) ? SUCCESS : FAIL;
    } else return FAIL;
}

int filter_src(int type, const BYTE *addr, const BYTE *data) {
    switch(type) {
        case PROTO:
            ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
            return (memcmp(arp_hdr->snd_proto_addr, addr, IP_ADDR_LEN) == 0 ? SUCCESS : FAIL);
        case HW:
            ETH *eth_hdr = (ETH*)data;
            return (memcmp(eth_hdr->src_hw_addr, addr, HW_ADDR_LEN) == 0 ? SUCCESS : FAIL);
        default:
            fprintf(stderr, "[-] Invalid type for filtering source");
            return FAIL;
    }
}

int filter_dst(int type, const BYTE *addr, const BYTE *data) {
    switch(type) {
        case PROTO:
            ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
            return (memcmp(arp_hdr->trg_proto_addr, addr, IP_ADDR_LEN) == 0 ? SUCCESS : FAIL);
        case HW:
            ETH *eth_hdr = (ETH*)data;
            return (memcmp(eth_hdr->dst_hw_addr, addr, HW_ADDR_LEN) == 0 ? SUCCESS : FAIL);
        default:
            fprintf(stderr, "[-] Invalid type for filtering destination");
            return FAIL;
    }
}