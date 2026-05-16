#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

const char* get_service(int port) {
    switch(port) {
        case 80:   return "HTTP";
        case 443:  return "HTTPS";
        case 53:   return "DNS";
        case 22:   return "SSH";
        case 21:   return "FTP";
        case 25:   return "SMTP";
        case 3306: return "MySQL";
        default:   return "unknown";
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {

    struct ip *ip_header = (struct ip *)(packet + 14);
    int ip_header_len = ip_header->ip_hl * 4;

    char src_ip[16], dst_ip[16];
    snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(ip_header->ip_src));
    snprintf(dst_ip, sizeof(dst_ip), "%s", inet_ntoa(ip_header->ip_dst));

    long timestamp = (long)time(NULL);
    int length = ntohs(ip_header->ip_len);

    if (ip_header->ip_p == 6) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
        int src_port = ntohs(tcp->th_sport);
        int dst_port = ntohs(tcp->th_dport);

        int syn = (tcp->th_flags & TH_SYN) ? 1 : 0;
        int ack = (tcp->th_flags & TH_ACK) ? 1 : 0;
        int fin = (tcp->th_flags & TH_FIN) ? 1 : 0;
        int rst = (tcp->th_flags & TH_RST) ? 1 : 0;
        int psh = (tcp->th_flags & TH_PUSH) ? 1 : 0;
        int alert = (syn && !ack) ? 1 : 0;

        printf("{\"protocol\":\"TCP\","
               "\"src_ip\":\"%s\",\"src_port\":%d,"
               "\"dst_ip\":\"%s\",\"dst_port\":%d,"
               "\"service\":\"%s\","
               "\"flags\":{\"SYN\":%s,\"ACK\":%s,\"FIN\":%s,\"RST\":%s,\"PSH\":%s},"
               "\"length\":%d,"
               "\"timestamp\":%ld,"
               "\"alert\":%s}\n",
               src_ip, src_port,
               dst_ip, dst_port,
               get_service(dst_port),
               syn?"true":"false",
               ack?"true":"false",
               fin?"true":"false",
               rst?"true":"false",
               psh?"true":"false",
               length, timestamp,
               alert?"true":"false");
    }

    else if (ip_header->ip_p == 17) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_header_len);
        int src_port = ntohs(udp->uh_sport);
        int dst_port = ntohs(udp->uh_dport);

        printf("{\"protocol\":\"UDP\","
               "\"src_ip\":\"%s\",\"src_port\":%d,"
               "\"dst_ip\":\"%s\",\"dst_port\":%d,"
               "\"service\":\"%s\","
               "\"flags\":{\"SYN\":false,\"ACK\":false,\"FIN\":false,\"RST\":false,\"PSH\":false},"
               "\"length\":%d,"
               "\"timestamp\":%ld,"
               "\"alert\":false}\n",
               src_ip, src_port,
               dst_ip, dst_port,
               get_service(dst_port),
               length, timestamp);
    }

    else if (ip_header->ip_p == 1) {
        printf("{\"protocol\":\"ICMP\","
               "\"src_ip\":\"%s\",\"src_port\":0,"
               "\"dst_ip\":\"%s\",\"dst_port\":0,"
               "\"service\":\"unknown\","
               "\"flags\":{\"SYN\":false,\"ACK\":false,\"FIN\":false,\"RST\":false,\"PSH\":false},"
               "\"length\":%d,"
               "\"timestamp\":%ld,"
               "\"alert\":false}\n",
               src_ip, dst_ip,
               length, timestamp);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "en0";
    char *filter = "tcp or udp";
    if (argc > 1) filter = argv[1];

    fprintf(stderr, "=== NIDS Sniffer v0.4 ===\n");
    fprintf(stderr, "Interface : %s\n", filter);
    fprintf(stderr, "Outputting JSON...\n\n");

    pcap_t *handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        return 1;
    }
    pcap_setfilter(handle, &fp);

    /* -1 means run forever until Ctrl+C */
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
