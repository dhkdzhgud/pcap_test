#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

typedef struct _ethernet_header{

    const u_char Dst_Mac[6];
    const u_char Src_Mac[6];

}ethernet_header;

typedef struct _ip_header{

    const u_char Src_Ip[4];
    const u_char Dst_Ip[4];

}ip_header;

typedef struct _tcp_header{

    const u_char Src_Port[2];
    const u_char Dst_Port[2];
    const u_char dummy[16];
    const u_char Tcp_Data[10];

}tcp_header;

void print_mac(const u_char * mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

}

void print_ip(const u_char * ip)
{
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char * port)
{
    printf("%d\n", (port[0] << 8) | port[1]);
}

void print_tcpdata(const u_char * tcpdata)
{
    for(int i = 0; i < 10; i++)
    {
        if(tcpdata[i] == 0)
            break;
        printf("%x ", tcpdata[i]);

    }
    printf("\n\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    //ipv4 or ipv6 check
    if((0x0800 != packet[12] * 256 + packet[13]) &&
       (0x86DD != packet[12] * 256 + packet[13]))
        continue;

    //TCP check
    if(0x06 != packet[23])
        continue;
/*
    //Test src, dst PORT http
    if(80 != (packet[34]*256 + packet[35]) &&
       80 != (packet[36]*256 + packet[37]))
         continue;

*/


    //******header offset reset**********
    ethernet_header * p_ethernet_h = (ethernet_header*)(packet);

    ip_header * p_ip_h = (ip_header *)(packet + 26);

    tcp_header * p_tcp_h = (tcp_header *)(packet + 34);

    printf("*********************************************\n\n");

    printf("Destination Mac : ");
    print_mac(p_ethernet_h->Dst_Mac);

    printf("Source Mac : ");
    print_mac(p_ethernet_h->Src_Mac);

    printf("Source IP : ");
    print_ip(p_ip_h->Src_Ip);  // 14 (Ethernet header) + 12

    printf("Destination IP : ");
    print_ip(p_ip_h->Dst_Ip);

    printf("Source Port : ");
    print_port(p_tcp_h->Src_Port);

    printf("Destination Port : ");
    print_port(p_tcp_h->Dst_Port);

    printf("TCP Data : ");
    print_tcpdata(p_tcp_h->Tcp_Data);

    printf("*********************************************\n\n");

}
  pcap_close(handle);
  return 0;
}
