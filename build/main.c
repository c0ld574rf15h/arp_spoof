#include "utils.h"
#include "packet.h"
#include <stdio.h>

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
    get_HW_IP(&attacker_IP, &attacker_MAC, dev);
    addr_to_str(attacker_MAC_str, "[*] Attacker MAC", attacker_MAC);

    // 4-1. Initial Infection (the victim)
    BYTE sender_MAC[HW_ADDR_LEN];
    char sender_MAC_str[HW_ADDR_LEN * 2 + 1];
    get_host_MAC(sender_MAC, attacker_MAC, sender_IP, handle);
    addr_to_str(sender_MAC_str, '[*] Victim MAC', sender_MAC);

    return 0;
}