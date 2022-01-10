#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

unsigned short checksum(unsigned short *paddress, int len)//From given header
{
  int nleft = len;
  int sum = 0;
  unsigned short *w = paddress;
  unsigned short answer = 0;

  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1)
  {
    *((unsigned char *)&answer) = *((unsigned char *)w);
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff); 
  sum += (sum >> 16);                 
  answer = ~sum;                      

  return answer;
}

void RawSocket(struct iphdr *ip)
{
  struct sockaddr_in dest;//Socket address
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = ip->daddr;
    int enable = 1;
  
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);//create raw socket
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));
  sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest));
  close(sock);
}

int main()
{
  char buffer[1500]; 
  memset(buffer, 0, 1500);
  
  /////Struct Icmp Header For Fake Mesege///////
  struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));
  icmp->type = 8; 
  icmp->checksum = 0;
  icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));

  /////Struct Ip Header For Fake Mesege///////
  struct iphdr *ip = (struct iphdr *)buffer;
  ip->version = 4;
  ip->ihl = 5;
  ip->ttl = 20;
  ip->saddr = inet_addr("10.9.0.5"); 
  ip->daddr = inet_addr("1.2.3.4");
  ip->protocol = IPPROTO_ICMP;
  ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
  
  
  RawSocket(ip);
  printf("Sent Fake Messege\n");

  return 0;
}
