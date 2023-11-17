#define TCP_IP 06
#define UDP_IP 17

/* The statistics we are gonna collect for each l3 protocol and store in the eBPF map */
struct l3proto_stats {
	unsigned long pkts;
	unsigned long bytes;
};
/* 5-tuple used in the eBPF map as a key to recognize the traffic */
struct key_tuple{
	__u32 source_address;
	__u16 source_port;
	__u32 destination_address;
	__u16 destination_port;
	__u8 protocol;
};