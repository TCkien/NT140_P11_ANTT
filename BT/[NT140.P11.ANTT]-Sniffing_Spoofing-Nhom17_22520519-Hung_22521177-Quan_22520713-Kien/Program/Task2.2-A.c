#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// Calculate the checksum of the IP header
unsigned short checksum(unsigned char *buf, int len) {
    unsigned int sum = 0;
    unsigned short *word = (unsigned short *)buf;

    while (len > 1) {
        sum += *word++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
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

    // Create an IP header
    struct iphdr ip;
    ip.version = 4;
    ip.ihl = 5;
    ip.ttl = 20;
    ip.protocol = IPPROTO_ICMP;
    ip.saddr = inet_addr("1.2.3.4");       // Spoofed source IP
    ip.daddr = inet_addr("10.9.0.6");      // Target IP

    // Calculate the checksum of the IP header
    ip.check = checksum((unsigned char *)&ip, sizeof(struct iphdr));

    // Create the packet
    char packet[sizeof(struct iphdr) + sizeof("Hi")];
    memcpy(packet, &ip, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), "Hi", sizeof("Hi"));

    // Provide destination information
    struct sockaddr_in dest_info;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip.daddr;

    // Send packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("Packet send failed");
    } else {
        printf("Spoofed packet sent successfully\n");
    }

    // Close the socket
    close(sock);
    return 0;
}

