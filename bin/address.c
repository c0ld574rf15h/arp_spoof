#include "packet.h"
#include "address.h"
#include "utils.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>

void get_HW_IP(BYTE *hw_addr, BYTE *proto_addr, const char *dev) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);

    // Fetch HW address
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(hw_addr, ifr.ifr_hwaddr.sa_data, HW_ADDR_LEN);

    // Fetch Protocol address
    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(proto_addr, ifr.ifr_addr.sa_data + 2, IP_ADDR_LEN);
}

void get_host_MAC(BYTE *hw_addr, BYTE *rcv_hw_addr, BYTE *snd_proto_addr, pcap_t *handle) {
    struct pcap_pkthdr *header;
    const BYTE *data;

    while(TRUE) {
        int res = pcap_next_ex(handle, &header, &data);
        if(pcap_next_handler(res, header) == FAIL) return -1;
        if(filter_ARP(OP_RES, data) == SUCCESS
            && filter_src(PROTO, snd_proto_addr, data) == SUCCESS
            && filter_dst(HW, rcv_hw_addr, data) == SUCCESS) {
            break;
        }
    }
    ARP *arp_hdr = (ARP*)(data + SZ_ETHERNET);
    memcpy(hw_addr, arp_hdr -> snd_hw_addr, HW_ADDR_LEN);
}