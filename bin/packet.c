#include "packet.h"
#include "utils.h"
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
        default:
            fprintf(stdout, "[+] Packet captured ( %dB )\n", hdr->caplen);
    }
    return flag;
}

void send_arp(pcap_t *handle, int opcode, BYTE *snd_mac, BYTE *snd_ip, BYTE *trg_mac, BYTE *trg_ip) {
    const BYTE BROADCAST[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";
    const BYTE NULL_ADDR[6] = "\x00\x00\x00\x00\x00\x00";
    ETH eth_hdr; ARP arp_hdr;

    memcpy(eth_hdr.dst_hw_addr, opcode==OP_REQ ? BROADCAST : trg_mac, HW_ADDR_LEN);
    memcpy(eth_hdr.src_hw_addr, snd_mac, HW_ADDR_LEN);
    eth_hdr.eth_type = ntohs(TYPE_ARP);

    arp_hdr.hw_type = ntohs(TYPE_ETH); arp_hdr.proto_type = ntohs(TYPE_IPV4);
    arp_hdr.hw_addr_len = HW_ADDR_LEN; arp_hdr.proto_addr_len = IP_ADDR_LEN;
    arp_hdr.opcode = ntohs(opcode);
    memcpy(arp_hdr.snd_hw_addr, snd_mac, HW_ADDR_LEN);
    memcpy(arp_hdr.snd_proto_addr, snd_ip, IP_ADDR_LEN);
    memcpy(arp_hdr.trg_hw_addr, opcode==OP_REQ ? NULL_ADDR : trg_mac, HW_ADDR_LEN);
    memcpy(arp_hdr.trg_proto_addr, trg_ip, IP_ADDR_LEN);

    ARP_PKT arp_pkt = { eth_hdr, arp_hdr };
    if(pcap_sendpacket(handle, (const BYTE*)&arp_pkt, sizeof(arp_pkt)) != 0)
        fprintf(stderr, "[-] Failed sending packet\n");
}