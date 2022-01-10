#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>


void RawSocket(struct iphdr *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);//raw socket create
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip->daddr;
    sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void fakeReply(const struct iphdr *ip)
{
    int ip_h_len = ip->ihl * 4;
    const char buffer[512];
    memset((char *)buffer, 0, 512);
    memcpy((char *)buffer, ip, ntohs(ip->tot_len));
    struct iphdr *fake_ip = (struct iphdr *)buffer;
    struct icmphdr *fake_icmp = (struct icmphdr *)(buffer + ip_h_len);
    fake_ip->saddr = ip->daddr;
    fake_ip->daddr = ip->saddr;
    fake_ip->ttl = 64;
    fake_icmp->type = 0; 
    RawSocket(fake_ip);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sockaddr_in src;
    struct sockaddr_in dest;


    const struct iphdr *ip = (struct iphdr *)(packet + ETH_HLEN);
    if (ip->protocol == IPPROTO_ICMP)//prints only ICMP 
    {
        memset(&src, 0, sizeof(src));
        src.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;
        printf("______New Packet_________\n");
        printf("Source IP: %s\n", inet_ntoa(src.sin_addr));
        printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
        printf("Protocol: ICMP\n");
        fakeReply(ip);
    }

}


int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";//filtering icmp
    bpf_u_int32 net;
    handle = pcap_open_live("br-98f7ba4f3b7c", BUFSIZ, 1, 1000, errbuf);//Open live pcap session 
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
