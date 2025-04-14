
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>

#include "checksum.h"

// TCP Flags
#define TCP_SYN 0x0002
#define TCP_RST 0x0004
#define TCP_FIN 0x0001
#define TCP_ACK 0x0010

// Pseudo header Info
#define TCP_PSEUDO_LEN 12

uint16_t dispEthHeader(const uint8_t* pkt_data);
void dispArpHeader(const uint8_t* pkt_data);
void processIPHeader(const uint8_t* pkt_data);
void dispTCPHeader(const uint8_t* pkt_data, int tcp_seg_size, uint8_t* pseudo_header);
void dispICMPHeader(const uint8_t* pkt_data);
void dispUDPHeader(const uint8_t* pkt_data);

uint16_t cpy_format_tohost_16(const uint8_t* ref_data);
uint32_t cpy_format_tohost_32(const uint8_t* ref_data);
char* ether_ttos(const uint16_t ethertype);
char* arp_rtos(const uint16_t request);
char *ip_ptos(const uint8_t pnum);
void printTCPflags(const uint8_t* flags);
void generate_pseudo_header(uint8_t* pseudo_header, const uint8_t* pkt_data, uint16_t payload_len_h);
void print_port_num(uint16_t port_num);


int main(int argc, char* argv[])
{
    // Verify a file is being input
    if (argc != 2)
    {
        printf("USAGE: %s /path/to/file\n", argv[0]);
        return 1;
    }
    // Read in the file
    char* pcap_filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];


    pcap_t *pcap_file = pcap_open_offline(pcap_filename, errbuf);
    if (pcap_file == NULL)
    {
        printf("Error: %s\n", errbuf);
        return 1;
    }
    // Process each set of headers
    struct pcap_pkthdr **pkt_header = malloc(sizeof(struct pcap_pkthdr *));
    const uint8_t *pkt_data;

    // int packet;
    // Setting a packet number for display purposes
    int packetNum = 1;
    while (pcap_next_ex(pcap_file, pkt_header, &pkt_data) != PCAP_ERROR_BREAK)
    {
        // Print the general info about the packet
        printf("\nPacket number: %d  Packet Len: %d\n\n", packetNum++, (*pkt_header)->caplen);

        // Displaying the ethernet header, the first 14 bits of the packet
        uint16_t packet_type = dispEthHeader(pkt_data);
        const uint8_t* payload = &pkt_data[14];
        // Determining what type the packet is and then reading the data
        if (packet_type == ETHERTYPE_ARP)
            dispArpHeader(payload);
        else if (packet_type == ETHERTYPE_IP || packet_type == ETHERTYPE_IPV6)
            processIPHeader(payload);
    }

    pcap_close(pcap_file);
    return 0;
}

/*  Displaying the ethernet header to the console. Returns the ethertype 
    as a 16 bit short */
uint16_t dispEthHeader(const uint8_t* pkt_data)
{
    const struct ether_addr* destAddr   = (const struct ether_addr*) pkt_data;
    const struct ether_addr* srcAddr    = (const struct ether_addr*) &(pkt_data[6]);
    uint16_t ethertype = cpy_format_tohost_16(&(pkt_data[12]));

    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n", ether_ntoa(destAddr));
    printf("\t\tSource MAC: %s\n", ether_ntoa(srcAddr));
    printf("\t\tType: %s\n", ether_ttos(ethertype));

    return ethertype;
}

/* A helper function to return a string of the ethertype */
char* ether_ttos(const uint16_t ethertype)
{
    switch (ethertype)
    {
    case ETHERTYPE_ARP:
        return "ARP";
    case ETHERTYPE_IP:
        return "IP";
    case ETHERTYPE_IPV6:
        return "IPv6";
    default:
        return "Unknown";
    }
}

char *arp_rtos(const uint16_t request)
{
    switch (request)
    {
    case ARPOP_REQUEST:
        return "Request";
    case ARPOP_REPLY:
        return "Reply";
    default:
        return "Unknown";
    }
}

char *ip_ptos(const uint8_t pnum)
{
    switch (pnum)
    {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_UDP:
        return "UDP";
    default:
        return "Unknown";
    }
}


/* A helper function that copies the 16  bits of data and returns the value*/
uint16_t cpy_format_tohost_16(const uint8_t* ref_data)
{
    uint16_t data_n;
    memcpy(&data_n, ref_data, sizeof(uint16_t));
    return ntohs(data_n);
}


uint32_t cpy_format_tohost_32(const uint8_t* ref_data)
{
    uint32_t data_n;
    memcpy(&data_n, ref_data, sizeof(uint32_t));
    return ntohl(data_n);
}

/*  A function that displays the ARP information.
    Takes in the first byte of the ARP packet. */
void dispArpHeader(const uint8_t* pkt_data)
{
    // The request code
    const uint16_t request_code = cpy_format_tohost_16(&(pkt_data[6]));

    // The sender MAC
    const struct ether_addr* srcAddr = (const struct ether_addr*) &(pkt_data[8]);

    // The sender IP
    struct in_addr* srcIP = (struct in_addr *) &(pkt_data[14]);

    // The target MAC
    const struct ether_addr* destAddr = (const struct ether_addr*) &(pkt_data[18]);

    // The target IP
    struct in_addr* destIP = (struct in_addr *) &(pkt_data[24]);

    printf("\n\tARP header\n");
    printf("\t\tOpcode: %s\n", arp_rtos(request_code));
    printf("\t\tSender MAC: %s\n", ether_ntoa(srcAddr));
    printf("\t\tSender IP: %s\n", inet_ntoa(*srcIP));
    printf("\t\tTarget MAC: %s\n", ether_ntoa(destAddr));
    printf("\t\tTarget IP: %s\n", inet_ntoa(*destIP));
}

void processIPHeader(const uint8_t* pkt_data)
{


    // Determine the header length
    uint8_t vlen;
    memcpy(&vlen, pkt_data, sizeof(uint8_t));
    // Size is lower half - bit mask, and then multiply 4 (*32 for bits, /8 for bytes)
    uint8_t h_len = (vlen & 0xF) * 4;
    // Determine the PDU Length
    uint16_t pdu_len = cpy_format_tohost_16(&(pkt_data[2]));
    // Determine the TTL
    uint8_t ttl;
    memcpy(&ttl, &(pkt_data[8]), sizeof(uint8_t));
    // Determine the Protocol
    uint8_t protocol;
    memcpy(&protocol, &(pkt_data[9]), sizeof(uint8_t));
    // Run the checksum
    unsigned short chksum_header = cpy_format_tohost_16(&(pkt_data[10]));
    unsigned short chksum_result = in_cksum((unsigned short *) pkt_data, h_len);
    // Determine the src and dest ips
    struct in_addr* srcIP = (struct in_addr *) &(pkt_data[12]);
    struct in_addr* destIP = (struct in_addr *) &(pkt_data[16]);

    printf("\n\tIP Header\n");
    printf("\t\tIP PDU Len: %hu\n", pdu_len);
    printf("\t\tHeader Len (bytes): %hhu\n", h_len);
    printf("\t\tTTL: %hhu\n", ttl);
    printf("\t\tProtocol: %s\n", ip_ptos(protocol));
    printf("\t\tChecksum: ");
    if (chksum_result== 0)
        printf("Correct (0x%04x)\n", chksum_header);
    else printf("Incorrect (0x%04x)\n", chksum_header);
    printf("\t\tSender IP: %s\n", inet_ntoa(*srcIP));
    printf("\t\tDest IP: %s\n", inet_ntoa(*destIP));

    const uint8_t *payload = &(pkt_data[h_len]);
    // Go to the next layer
    if (protocol == IPPROTO_TCP)
    {
        uint8_t pseudo_header[TCP_PSEUDO_LEN];
        uint16_t tcp_len = pdu_len - h_len;
        generate_pseudo_header(pseudo_header, pkt_data, tcp_len);
        dispTCPHeader(payload, tcp_len, pseudo_header);
    }
    else if (protocol == IPPROTO_ICMP) dispICMPHeader(payload);
    else if (protocol == IPPROTO_UDP) dispUDPHeader(payload);
}

void dispTCPHeader(const uint8_t* pkt_data, int tcp_seg_size, uint8_t* pseudo_header)
{
    // Getting the TCP source & dest port
    uint16_t src_port = cpy_format_tohost_16(pkt_data);
    uint16_t dest_port = cpy_format_tohost_16(&(pkt_data[2]));

    // Getting the sequence and ACK number
    uint32_t seq_num = cpy_format_tohost_32(&(pkt_data[4]));
    uint32_t ack_num = cpy_format_tohost_32(&(pkt_data[8]));

    // Getting the header length
    uint8_t h_len;
    memcpy(&h_len, &(pkt_data[TCP_PSEUDO_LEN]), sizeof(uint8_t));
    h_len = h_len >> 4;

    // Get the window size
    uint16_t window_size = cpy_format_tohost_16(&(pkt_data[14]));

    // Verify the checksum

    // Making the packet data - its length should be the pseudo header length plus the header length
    uint8_t chksum_data[TCP_PSEUDO_LEN + tcp_seg_size];
    memcpy(chksum_data, pseudo_header, sizeof(uint8_t) * TCP_PSEUDO_LEN);
    memcpy(&(chksum_data[TCP_PSEUDO_LEN]), pkt_data, tcp_seg_size);
    unsigned short chksum_header = cpy_format_tohost_16(&(pkt_data[16]));
    unsigned short chksum_result = in_cksum((unsigned short *) chksum_data, tcp_seg_size + TCP_PSEUDO_LEN);

    // Getting the TCP segment length:
    printf("\n\tTCP Header\n");
    printf("\t\tSegment Length: %d\n", tcp_seg_size);
    printf("\t\tSource Port:  ");
    print_port_num(src_port);
    printf("\t\tDest Port:  ");
    print_port_num(dest_port);
    printf("\t\tSequence Number: %u\n", seq_num);
    printf("\t\tACK Number: %u\n", ack_num);
    printf("\t\tData Offset (bytes): %hhu\n", h_len * 4);
    printTCPflags(&(pkt_data[12]));
    printf("\t\tWindow Size: %hu\n", window_size);
    printf("\t\tChecksum: ");
    if (chksum_result== 0) printf("Correct (0x%04x)\n", chksum_header);
    else printf("Incorrect (0x%04x)\n", chksum_header);
}

// Putting this in its own function because of HTTP(and maybe others) having a special name
void print_port_num(uint16_t port_num)
{
    if (port_num==80) printf("HTTP\n");
    else if (port_num==53) printf("DNS\n");
    else if (port_num==23) printf("Telnet\n");
    else if (port_num==21) printf("FTP\n");
    else if (port_num==110) printf("POP3\n");
    else if (port_num==25) printf("SMTP\n");
    else printf("%hu\n", port_num);
}

// Make a function called print tcp flags that takes in the 12 bits and prints
void printTCPflags(const uint8_t* flags)
{
    // Looking for 12 bits of data, so we need to copy two bytes and then mask
    uint16_t flagdata = cpy_format_tohost_16(flags);
    flagdata = flagdata & 0x0FFF;
    printf("\t\tSYN Flag: ");
    if (flagdata & TCP_SYN) printf("Yes\n");
    else printf("No\n");
    printf("\t\tRST Flag: ");
    if (flagdata & TCP_RST) printf("Yes\n");
    else printf("No\n");
    printf("\t\tFIN Flag: ");
    if (flagdata & TCP_FIN) printf("Yes\n");
    else printf("No\n");
    printf("\t\tACK Flag: ");
    if (flagdata & TCP_ACK) printf("Yes\n");
    else printf("No\n");
}

// A function that generates the pseudo headder and puts it in the pointer specified
void generate_pseudo_header(uint8_t* pseudo_header, const uint8_t* pkt_data, uint16_t payload_len_h)
{
    // Copying over the src & dest IP
    memcpy(pseudo_header, &(pkt_data[TCP_PSEUDO_LEN]), sizeof(uint8_t) * 8);

    // Adding zeros
    uint8_t blank = 0x00;
    memcpy(&(pseudo_header[8]), &blank, sizeof(uint8_t));
    // Copying the protocol - 9th spot
    memcpy(&(pseudo_header[9]), &(pkt_data[9]), sizeof(uint8_t));

    // Copying the tcp length
    uint16_t payload_len_n = htons(payload_len_h);
    memcpy(&(pseudo_header[10]), &payload_len_n, sizeof(uint16_t));
}

void dispICMPHeader(const uint8_t* pkt_data)
{
    printf("\n\tICMP Header\n");
    printf("\t\tType: ");
    if (pkt_data[0] == 0x08) printf("Request\n");
    else if (pkt_data[0] == 0x00) printf("Reply\n");
    else printf("%hhu\n", pkt_data[0]);
}

void dispUDPHeader(const uint8_t* pkt_data)
{
    // Grab the source port
    uint16_t src_port = cpy_format_tohost_16(pkt_data);
    // Grab the dest port
    uint16_t dest_port = cpy_format_tohost_16(&(pkt_data[2]));

    printf("\n\tUDP Header\n");
    printf("\t\tSource Port:  ");
    print_port_num(src_port);
    printf("\t\tDest Port:  ");
    print_port_num(dest_port);
}