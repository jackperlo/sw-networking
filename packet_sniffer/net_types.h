#ifndef HTTP_CAPTURING_NET_TYPES_H
#define HTTP_CAPTURING_NET_TYPES_H

/* Ethernet protocol ID's */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
/* Ethernet II header */
typedef struct ether_header{
    u_int8_t ether_dest_host[6]; /*6 bytes destination address*/
    u_int8_t ether_source_host[6]; /*6 bytes source address*/
    u_int16_t ether_type; /*2 bytes ether type*/
}ethernet_header;

/* IP protocol ID's */
#define TCP_IP 06		  /* TCP over IP */
#define	UDP_IP 17		/* UDP over IP */
/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;
/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Transportation Protocol
    u_short crc;            // Header checksum
    ip_address source_addr;      // Source address
    ip_address dest_addr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header */
typedef struct udp_header{
    u_short source_port;    // Source port
    u_short dest_port;      // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* TCP header */
typedef struct tcp_header{
    u_short source_port;    // Source port
    u_short dest_port;      // Destination port
    u_int32_t seq_number;   // Sequence Number
    u_int32_t ack_number;   // Ack Number
    u_int16_t reserved;     // HLEN + reserved bits
    u_int16_t window_size;  // window size
    u_int16_t checksum;     // checksum
    u_int16_t urgent_pointer;
    u_int op_pad;           // Option + Padding
}tcp_header;


#endif //HTTP_CAPTURING_NET_TYPES_H
