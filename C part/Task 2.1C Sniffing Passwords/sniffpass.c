#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header


struct sockaddr_in source,dest;
int total=0;



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
    int size = header->len;
    //IP Header
    struct iphdr *iph = (buffer + sizeof(struct ethhdr));
    print_tcp_packet(buffer , size);
}

void print_ip_header(const u_char * Buffer, int Size){
    unsigned short iphdrlen;
    struct iphdr *iph = (Buffer  + sizeof(struct ethhdr));
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("Pkt Source: %s\n",  inet_ntoa(source.sin_addr));
    printf("Pkt Destination: %s\n",  inet_ntoa(dest.sin_addr));
    printf("\n");
}

void print_tcp_packet(const u_char * Buffer, int Size){
    unsigned short iphdrlen;
    //IP Header
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    //Tcp Header
    struct tcphdr *tcph=(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    printf("\n #####Packet captured!#####\n");

    print_ip_header(Buffer,Size);
    printf("Data:\n");
    PrintData(Buffer + header_size , Size - header_size );

}

void PrintData (const u_char * data , int Size){
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet

                else printf("."); //otherwise print a dot
            }
            printf("\n");
        }

        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                printf("   "); //extra spaces
            }

            printf("         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    printf("%c",(unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }
            }
            printf( "\n" );
        }
    }
}

int main() {
    pcap_t *handle;
    char error[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    struct bpf_program fp;
    char filter_exp [] = "tcp and port 23 and src host 10.0.2.15";
    

    // Step 1: Open live pcap session on the device: "enp0s3"
    handle = pcap_open_live("enp0s3" , BUFSIZ , 1 , 1000 , error);
    if (handle == NULL){ fprintf(stderr, "Couldn't open device %s : %s\n" , "enp0s3" , error);
        return -1;
    }
    
    // Step 2: Compile and set the filter for sniffing
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) printf("failed compiling filter");
    if (pcap_setfilter(handle, &fp) == -1) printf("failed setting filter");


    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);


    // Step 4: Close the handle
    pcap_close(handle); 
    return 0;
}