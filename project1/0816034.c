#include <stdio.h>
#include <stdlib.h> // system()
#include <stdbool.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <netinet/if_ether.h> // ethernet header
#include <netinet/ip.h> // ip header
#include <arpa/inet.h> // ip_addr.s_addr (parse IP address)
#include <string.h>

#define RECEIVE_PACKET_NUM -1

static void print_packet_info(const u_char *packet, const struct pcap_pkthdr *packet_header);
void print_whole_packet(const u_char *packet, const struct pcap_pkthdr *packet_header);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *packet_header, const u_char *packet);

char *filter_input; // 1024 byte defined in line 63
pcap_t *handle;

int main(int argc, char *argv[])
{
    size_t bufsize = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp, *traverse;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int promiscious = 1;
    int timeout_limit = 100; /* In milliseconds */
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;
    int ret = 0;
    
    int r = pcap_findalldevs(&alldevsp, errbuf); // find all devices
    if (r < 0) {
        fprintf(stderr, "%s", errbuf);
        return 2;
    }

    // print all devices' name
    int t = 0;
    traverse = alldevsp;
    while (traverse != NULL) {
        printf("Device %d: %s\n", t++, traverse->name);
        traverse = traverse->next;
    }

    // input interface number to sniff
    printf("Insert a number to select interface: \n");
    int interface;
    scanf("%d", &interface);
    getchar();
    t = 0;
    traverse = alldevsp;
    while(t < interface) {
        traverse = traverse->next;
        t++;
    }
    printf("Interface: %d %s\n", interface, traverse->name);
    char *interface_name = traverse->name;
    printf("Start listening at %s\n", interface_name);
    printf("Insert BPF filter expression:\n");
    filter_input = (char *)malloc(1024 * sizeof(char));
    int readlen = -1;
    if ((readlen = getline(&filter_input, &bufsize, stdin)) < 0) {
        fprintf(stderr, "Getline error.\n");
        return 2;
    } 
    printf("filter: %s\n", filter_input);

    /* Returns (pcap_t *) */
    handle = pcap_open_live(
            interface_name,
            BUFSIZ,
            promiscious,
            timeout_limit,
            errbuf
        );

    /* set filter */
    if ((ret = pcap_compile(handle, &filter, filter_input, 0, 0)) < 0) {
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return 2;
    }
    
    if ((ret = pcap_setfilter(handle, &filter)) < 0) {
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return 2;
    }

    /* read packets */
    printf("Waiting packets...\n");
    if (pcap_loop(handle, RECEIVE_PACKET_NUM, pcap_callback, NULL) < 0) {
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return 2; 
    }

    // free (pcap_t *)
    pcap_close(handle);
    printf("%s closed.\n", interface_name);
    return 0;
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    printf("fdfd");
    print_packet_info(packet, packet_header);
    return;
}

static void print_packet_info(const u_char *packet, const struct pcap_pkthdr *packet_header) {
    static int d = 0;
    static u_short tunnels[256]; // 256 is a random number I choosed
    static int tunnel_num = 0;
    printf("--------------------------------\n");
    printf("Packet %3d captured\n", ++d);
    printf("Packet capture length: %d\n", packet_header->caplen);
    printf("Packet total length %d\n", packet_header->len);
    
    /*
     *  Outer ethernet header
     *  struct	ether_header {
     *      u_char	ether_dhost[6];
     *      u_char	ether_shost[6];
     *      u_short	ether_type;
     *  };
     */

    struct ether_header *outer_eth = (struct ether_header *)packet;

    /* Source MAC */ 
    printf("Source MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", (u_int)outer_eth->ether_shost[i]);
        if (i != 5)
            printf(":");
        else
            printf("\n");
    }

    /* Destination MAC */ 
    printf("Destination MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", (u_int)outer_eth->ether_dhost[i]);
        if (i != 5)
            printf(":");
        else
            printf("\n");
    }

    /* Ethertype */
    printf("Ethernet type: ");
    if (ntohs(outer_eth->ether_type) == ETHERTYPE_IP)
        printf("IPv4\n"); // 0x0800
    else {
        printf("Not IPv4\n");
        print_whole_packet(packet, packet_header);
        return;
    }

    /*
     * Outer IP header
    */
    struct ip *outer_ip = (struct ip *)(packet+14);

    /* Source IP address */
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &outer_ip->ip_src, str, INET_ADDRSTRLEN);
    printf("Source IP: %s\n", str);

    /* Destination IP address */
    inet_ntop(AF_INET, &outer_ip->ip_dst, str, INET_ADDRSTRLEN);
    printf("Destination IP: %s\n", str);

    /* Protocol inside the packet */
    printf("Next layer protocol: ");
    if (outer_ip->ip_p == 0x11) // UDP number from wikipedia
        printf("UDP\n");
    else
        printf("Not UDP\n");
    
    /* UDP header base: 34 */
    u_short src_port, des_port;
    if (outer_ip->ip_p == 0x11) {
        void *udp = (void *)(packet+34);
        src_port = ntohs(*(u_short *)(udp+0));
        des_port = ntohs(*(u_short *)(udp+2));
        printf("Source Port: %hu\n", src_port);
        printf("Destination Port: %hu\n", des_port);
    
    }

    /* GRE header base: 42 */
    void *gre = (void *)(packet+42);
    bool isfou = false;
    u_int key;
    if (ntohs(*(u_short *)(gre+2)) == 0x6558) {
        printf("Found Fou over GRETAP\n");
        isfou = true;
        key = ntohl(*(u_int *)(gre+4));
        printf("Key: %u\n", key);
    }
    else
        printf("No GRETAP\n");

    if (!isfou) {
        print_whole_packet(packet, packet_header);
        return;
    } 

    /* build GRE tunnel */
    bool flag = true;
    for(int i = 0; i < tunnel_num; i++) {
        if (tunnels[i] == des_port) {
            flag = false;
            break;
        } 
    }

    if (flag) {
        char command[256];
        char remote[INET_ADDRSTRLEN];
        char local[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &outer_ip->ip_src, remote, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &outer_ip->ip_dst, local, INET_ADDRSTRLEN);

        sprintf(
            command,
            "ip fou add port %hu ipproto 47",
            des_port
            );
        system(command);
        sprintf(
            command, 
            "ip link add GRETAP_%d type gretap remote %s local %s key %u encap fou encap-sport %hu encap-dport %hu", 
            tunnel_num,
            remote,
            local,
            key,
            des_port,
            src_port
            );
        system(command);
        sprintf(
            command,
            "ip link set GRETAP_%d up",
            tunnel_num);
        system(command);
        sprintf(
            command,
            "ip link set GRETAP_%d master br0",
            tunnel_num);
        system(command);
        sprintf(
            command,
            "ip link set br0 up");
        system(command);
        
        /* update filter */
        char filter_add[1024];
        sprintf(filter_add, " && port not %hu", des_port);
        strcat(filter_input, filter_add);

        /* set filter */
        struct bpf_program filter;
        int ret = -1;
        if ((ret = pcap_compile(handle, &filter, filter_input, 0, 0)) < 0) {
            fprintf(stderr, "%s\n", pcap_geterr(handle));
            return;
        }
        
        if ((ret = pcap_setfilter(handle, &filter)) < 0) {
            fprintf(stderr, "%s\n", pcap_geterr(handle));
            return;
        }

        /* finish message */
        printf("GREfou tunnel %d builded.\n", tunnel_num);
        tunnels[tunnel_num++] = des_port;
    }

    /* Print whole packet */
    print_whole_packet(packet, packet_header);
}

void print_whole_packet(const u_char *packet, const struct pcap_pkthdr *packet_header) {
    printf("Byte code:");
    for (int i = 0; i < packet_header->caplen; i++) {
        if (i % 16 == 0)
            printf("\n%4d  ", i);
        printf("%02x", (int)packet[i]); 
        printf(" ");
    }
    printf("\n\n");
}

