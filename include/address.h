#pragma once

void get_HW_IP(BYTE *hw_addr, BYTE *proto_addr, const char *dev);
void get_host_MAC(BYTE *hw_addr, BYTE *rcv_hw_addr, BYTE *snd_proto_addr, pcap_t *handle);