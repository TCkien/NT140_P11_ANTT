#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>

// Calculate the checksum of the IP header
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

int main() {
    // Create a raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Set the socket to send IP packets
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // Construct IP header
    struct iphdr ip;
    ip.version = 4;
    ip.ihl = 5;
    ip.tos = 0;
    ip.tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip.id = htons(54321);
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_ICMP;
    ip.saddr = inet_addr("1.2.3.4");        // Spoofed source IP address
    ip.daddr = inet_addr("10.9.0.6");        

    // Construct ICMP header
    struct icmphdr icmp;
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = rand();
    icmp.un.echo.sequence = rand();
    icmp.checksum = 0;

    // Calculate ICMP checksum
    icmp.checksum = checksum(&icmp, sizeof(icmp));

    // Construct packet
    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
    memcpy(packet, &ip, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &icmp, sizeof(struct icmphdr));

    // Provide destination information
    struct sockaddr_in dest_info;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip.daddr;

    // Send packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){
        perror("Packet send failed");
    } else {
        printf("Spoofed ICMP Echo Request sent to 10.9.0.6 with source IP 1.2.3.4\n");
    }


    // Close the socket
    close(sock);
    return 0;
}

