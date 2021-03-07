#include <pcap/pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

// Ethernet header
struct ethheader
{
    u_char ether_dhost[6]; // destination host address
    u_char ether_shost[6]; // source host address
    u_short ether_type;    // protocol type (IP, ARP, RARP, etc)
};

// IP Header
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

// ICMP Header
struct icmpheader
{
    unsigned char icmp_type;		// ICMP message type
    unsigned char icmp_code;		// Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;		// Used for identifying request
    unsigned short int icmp_seq;	// Sequence number
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP type is 0x0800
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("Pkt Source: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Pkt Destination: %s\n", inet_ntoa(ip->iph_destip));
        printf("\n");

        // print by protocol
        if (ip->iph_protocol == IPPROTO_TCP) {
            printf("Protocol: TCP\n");
            return;
        } else if (ip->iph_protocol == IPPROTO_UDP){
            printf("Protocol: UDP\n");
            return;
        } else if (ip->iph_protocol == IPPROTO_ICMP){
            printf("Protocol: ICMP\n");
            sendEchoReply(ip);

            return;
        } else {
            printf("Protocol: others\n");
            return;
        }
    }
}

void sendEchoReply(struct ipheader * ip) {
  int ip_header_len = ip->iph_ihl * 4;
  const char buffer[1500];

  // copy the original packet (deep copy)
  memset((char *)buffer, 0, 1500);
  memcpy((char *)buffer, ip, ntohs(ip->iph_len));
  struct ipheader* newip = (struct ipheader*) buffer;
  struct icmpheader* newicmp = (struct icmpheader*) (buffer + sizeof(ip_header_len));

  // construct IP Packet, swap source and destination adresses to fake the echo response
  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip   = ip->iph_sourceip;
  newip->iph_ttl = 64;

  // 0 is icmp echo response type 
  newicmp->icmp_type = 0;
  sendRawIPPKT(newip);


}

void sendRawIPPKT(struct ipheader *ip)
{
    int on = 1;
    struct sockaddr_in dest_info;

    // Step 1: Create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    // Step 3: Provide needed information about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

int main() {
    pcap_t *handle;
    char error[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    struct bpf_program fp;
//    char filter_exp [] = "icmp and src host 10.0.2.4 and dst host 10.0.9.1";


    // Step 1: Open live pcap session on the device: "enp0s3"
    handle = pcap_open_live("enp0s3" , BUFSIZ , 1 , 1000 , error);
    if (handle == NULL){ fprintf(stderr, "Couldn't open device %s : %s\n" , "enp0s3" , error);
        return -1;
    }
    // Step 2: Compile and set the filter for sniffing
    // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) printf("failed compiling filter");
    // if (pcap_setfilter(handle, &fp) == -1) printf("failed setting filter");


    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);


    // Step 4: Close the handle
    pcap_close(handle); 
    return 0;
}
