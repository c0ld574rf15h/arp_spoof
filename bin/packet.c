#include "packet.h"
#include "utils.h"
#include <pcap.h>
#include <stdio.h>

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
            fprintf(stdout, "[+] Packet captured ( %dB )", hdr->caplen);
    }
    return flag;
}