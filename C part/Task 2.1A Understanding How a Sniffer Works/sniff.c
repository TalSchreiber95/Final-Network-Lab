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
            return;
        } else {
            printf("Protocol: others\n");
            return;
        }
    }
}

int main() {
    pcap_t *handle;
    char error[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    struct bpf_program fp;


    // Step 1: Open live pcap session on the device: "enp0s3"
    handle = pcap_open_live("enp0s3" , BUFSIZ , 1 , 1000 , error);
    if (handle == NULL){ fprintf(stderr, "Couldn't open device %s : %s\n" , "enp0s3" , error);
        return -1;
    }

    // Step 2: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);


    // Step 3: Close the handle
    pcap_close(handle); 
    return 0;
}