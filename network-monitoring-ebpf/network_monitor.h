#include <stdint.h>

/* Ethernet protocol ID's */
#define	ETHERTYPE_IP		0x0800		/* IP */
/* Ethernet II header */
typedef struct ether_header{
    uint8_t ether_dest_host[6]; /*6 bytes destination address*/
    uint8_t ether_source_host[6]; /*6 bytes source address*/
    uint16_t ether_type; /*2 bytes ether type*/
}ethernet_header;

/* IP protocol ID's */
#define TCP_IP 06		  /* TCP over IP */
#define	UDP_IP 17		/* UDP over IP */
/* IPv4 header */
typedef struct ip_header{
    uint8_t  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    uint8_t  tos;            // Type of service
    uint16_t tlen;           // Total length
    uint16_t identification; // Identification
    uint16_t flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;            // Time to live
    uint8_t  proto;          // Transportation Protocol
    uint16_t crc;            // Header checksum
    __u8 source_addr[4];      // Source address
    __u8 dest_addr[4];      // Destination address
}ip_header;

/* TCP header */
typedef struct tcp_header{
    uint16_t sport;    // Source port
    uint16_t dport;      // Destination port
}tcp_header;

/* The statistics we are gonna collect for each l3 protocol and store in the eBPF map */
struct l3proto_stats {
	unsigned long pkts;
	unsigned long bytes;
};
/* 5-tuple used in the eBPF map as a key to recognize the traffic */
struct key_tuple{
	__u8 source_address[4];
	__u16 source_port;
	__u8 destination_address[4];
	__u16 destination_port;
	__u8 protocol;
};