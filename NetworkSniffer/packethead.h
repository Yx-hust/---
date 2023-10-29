#pragma once
#include "pcap.h"
#include<stdint.h>
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl : 4, //IP header length
        iph_ver : 4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};
/* IPV6 Header */
struct ipv6header {
    unsigned int       ipv6_version : 4, //IP version
        ipv6_traffic_class : 8, //Traffic Class
        ipv6_flow_label : 20; //Flow Label
    unsigned short int ipv6_payload_len; //Payload length
    unsigned char      ipv6_next_header; //Next Header
    unsigned char      ipv6_hop_limit; //Hop Limit
    struct in6_addr    ipv6_source; //Source IP address
    struct in6_addr    ipv6_dest; //Destination IP address
};
/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};

/* UDP Header */
struct udpheader
{
    uint16_t udp_sport;           /* source port */
    uint16_t udp_dport;           /* destination port */
    uint16_t udp_ulen;            /* udp length */
    uint16_t udp_sum;             /* udp checksum */
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

/*  arp header */
struct arpheader {
    unsigned short int hardware_type; // 硬件类型
    unsigned short int protocol_type; // 协议类型
    unsigned char hardware_len; // 硬件地址长度
    unsigned char protocol_len; // 协议地址长度
    unsigned short int opcode; // ARP 操作码
    unsigned char sender_mac[6]; // 发送者 MAC 地址
    unsigned char sender_ip[4]; // 发送者 IP 地址
    unsigned char target_mac[6]; // 目标 MAC 地址
    unsigned char target_ip[4]; // 目标 IP 地址
};
