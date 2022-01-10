#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sockaddr_in src;
    struct sockaddr_in dest;
    const char *payload;
    int payload_size;


    const struct iphdr *ip = (struct iphdr *)(packet + ETH_HLEN);
    int ip_h_length = ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP)//only TCP
    {
        const struct tcphdr *tcp = (struct tcphdr *)(packet + ETH_HLEN + ip_h_length);
        int tcp_h_length = tcp->doff * 4;


        memset(&src, 0, sizeof(src));
        src.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;

        if (payload_size > 0)
        {
            printf("\n_________New Packet________: %s\n", inet_ntoa(src.sin_addr));
            printf("Source: %s\n", inet_ntoa(src.sin_addr));
            printf("Destination: %s\n", inet_ntoa(dest.sin_addr));
            printf("Protocol: TCP\n");
            const u_char *ch;
            ch = (u_char *)(packet + ETH_HLEN + ip_h_length + tcp_h_length);
            printf("Payload: \n\t\t");
            int len = ntohs(ip->tot_len) - (ip_h_length + tcp_h_length);
            for (int i = 0; i < len; i++)
                {
                  if (isprint(*ch)){
                    if (len == 1){
                       printf("\t%c", *ch);
                    }
                    else{
                    printf("%c", *ch);
                    }
                }
             ch++;
            }  

        }
    }

}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("br-98f7ba4f3b7c", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}


