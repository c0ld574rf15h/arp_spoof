#include <arpa/inet.h>
#include <string.h>
#include "filter.h"
#include "utils.h"
#include "packet.h"

int filter_ARP(int opcode, const BYTE *data) {
    ETH *eth_hdr = (ETH*)data;
    if(ntohs(eth_hdr->eth_type) == TYPE_ARP) {
        ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
        if(opcode == DONT_CARE) return SUCCESS;
        return (ntohs(arp_hdr->opcode) == opcode) ? SUCCESS : FAIL;
    } else return FAIL;
}

int filter_IP(const BYTE *data) {
    ETH *eth_hdr = (ETH*)data;
    return (ntohs(eth_hdr -> eth_type) == TYPE_IPV4) ? SUCCESS : FAIL;
}

int filter_src(int type, const BYTE *addr, const BYTE *data) {
    ETH *eth_hdr = (ETH*)data;
    switch(ntohs(eth_hdr->eth_type)) {
        case TYPE_ARP: {
            ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
            if(type == PROTO) return (memcmp(arp_hdr->snd_proto_addr, addr, IP_ADDR_LEN) ? FAIL : SUCCESS);
            else if(type == HW) return (memcmp(eth_hdr->src_hw_addr, addr, HW_ADDR_LEN) ? FAIL : SUCCESS);
        }
        case TYPE_IPV4: {
            IP *ip_hdr = (IP*)(data + SZ_ETHERNET);
            if(type == PROTO) return (memcmp(ip_hdr->src_addr, addr, IP_ADDR_LEN) ? FAIL : SUCCESS);
            else if(type ==HW) return (memcmp(eth_hdr->src_hw_addr, addr, HW_ADDR_LEN) ? FAIL : SUCCESS);
        }
    }
    return FAIL;    // Return fail by default
}

int filter_dst(int type, const BYTE *addr, const BYTE *data) {
    ETH *eth_hdr = (ETH*)data;
    switch(ntohs(eth_hdr->eth_type)) {
        case TYPE_ARP: {
            ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
            if(type == PROTO) return (memcmp(arp_hdr->trg_proto_addr, addr, IP_ADDR_LEN) ? FAIL : SUCCESS);
            else if(type == HW) return (memcmp(eth_hdr->dst_hw_addr, addr, HW_ADDR_LEN) ? FAIL : SUCCESS);
        }
        case TYPE_IPV4: {
            IP *ip_hdr = (IP*)(data + SZ_ETHERNET);
            if(type == PROTO) return (memcmp(ip_hdr->dst_addr, addr, IP_ADDR_LEN) ? FAIL : SUCCESS);
            else if(type ==HW) return (memcmp(eth_hdr->dst_hw_addr, addr, HW_ADDR_LEN) ? FAIL : SUCCESS);
        }
    }
    return FAIL;    // Return fail by default
}