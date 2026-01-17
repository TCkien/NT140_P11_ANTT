#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>      // For IP header structure
#include <netinet/if_ether.h> // For Ethernet header structure

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // Define Ethernet and IP headers
    struct ether_header *eth_header;
    struct ip *ip_header;

    // Get the Ethernet header (first 14 bytes of the packet)
    eth_header = (struct ether_header *) packet;
    
    // Check if the packet is IP (Ethernet type 0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Get the IP header (after the Ethernet header)
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Print source and destination IP addresses
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n\n", inet_ntoa(ip_header->ip_dst));
    }
}



int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("br-6d579396a370", BUFSIZ, 1, 1000, errbuf); 
  
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {  
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }
                              
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    
  pcap_close(handle);   //Close the handle
  return 0;
}
