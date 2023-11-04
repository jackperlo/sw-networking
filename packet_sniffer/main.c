#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "pcap.h"
#include "net_types.h"

int interfaces_scan(pcap_if_t **);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
u_int16_t handle_ethernet(const u_char *);
void handle_ip(const u_char *);
void handle_udp(const u_char *, u_char);
void handle_tcp(const u_char *, u_char);

int main() {
  pcap_if_t *all_devs = NULL;
  pcap_if_t *d;
  int i_num;
  int i;
  pcap_t *device_handle;
  char err_buf[PCAP_ERRBUF_SIZE];

  /* Scanning and  Printing the list of interfaces */
  i = interfaces_scan(&all_devs);

  printf("Enter the interface number (1-%d):",i);
  scanf("%d", &i_num);
  if(i_num < 1 || i_num > i)
  {
    printf("\nInterface number out of range.\n");
    /* Free the device list */
    pcap_freealldevs(all_devs);
    return -1;
  }

  /* Jump to the selected adapter */
  for(d=all_devs, i=0; i < i_num - 1; d=d->next, i++);

  /* Open the device */
  if ( (device_handle = pcap_open_live(d->name,            // name of the device
                            65536,                    // portion of the packet to capture
                                                      // 65536 guarantees that the whole packet will be captured on all the link layers
                            PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                            1000,                     // read timeout
                            err_buf                    // error buffer
  ) ) == NULL)
  {
    fprintf(stderr,"\nUnable to open the adapter. %s is not supported by LibPcap: %s\n", d->name, err_buf);
    /* Free the device list */
    pcap_freealldevs(all_devs);
    return -1;
  }
  printf("\nlistening on %s...\n", d->name);

  /* At this point, we don't need any more the device list. Free it */
  pcap_freealldevs(all_devs);

  /* We don't need any more the device list. Free it */
  pcap_loop(device_handle, 0, packet_handler, NULL);

  return 0;
}

int interfaces_scan(pcap_if_t **all_devs){
  *all_devs = malloc(sizeof(pcap_if_t));
  pcap_if_t *d;
  char err_buf[PCAP_ERRBUF_SIZE];
  int i = 0;

  /* Retrieve the device list from the local machine */
  if (pcap_findalldevs(all_devs, err_buf) == -1)
  {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", err_buf);
    exit(1);
  }

  /* Print the list */
  for(d=*all_devs; d != NULL; d=d->next)
  {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if (i == 0)
  {
    printf("\nNo interfaces found! Make sure LibPcap is installed.\n");
    return -1;
  }
  return i;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  struct tm ltime;
  char timestr[16];
  /* convert the timestamp to readable format */
  time_t local_tv_sec = header->ts.tv_sec;
  localtime(&local_tv_sec);
  strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
  printf("\n%s,%.6d ", timestr, header->ts.tv_usec);

  u_int16_t type = handle_ethernet(pkt_data);
  switch (type) {
    case ETHERTYPE_IP:
      handle_ip(pkt_data);
      break;
    default:
      break;
  }
}

u_int16_t handle_ethernet(const u_char *pkt_data) {
  struct ether_header *eth_ptr;

  /* let's start with the ether header... */
  eth_ptr = (ethernet_header *) pkt_data;

  printf("MAC source: %02x:%02x:%02x:%02x:%02x:%02x -->", eth_ptr->ether_source_host[0], eth_ptr->ether_source_host[1], eth_ptr->ether_source_host[2], eth_ptr->ether_source_host[3], eth_ptr->ether_source_host[4], eth_ptr->ether_source_host[5]);
  printf(" MAC dest: %02x:%02x:%02x:%02x:%02x:%02x ", eth_ptr->ether_dest_host[0], eth_ptr->ether_dest_host[1], eth_ptr->ether_dest_host[2], eth_ptr->ether_dest_host[3], eth_ptr->ether_dest_host[4], eth_ptr->ether_dest_host[5]);

  /* check to see if we have an ip packet */
  if (ntohs (eth_ptr->ether_type) == ETHERTYPE_IP){
    printf("(IP) ");
  }else  if (ntohs (eth_ptr->ether_type) == ETHERTYPE_ARP){
    printf("(ARP) ");
  }else {
    printf("(%x) ", eth_ptr->ether_type);
  }

  return ntohs (eth_ptr->ether_type);
}

void handle_ip(const u_char *pkt_data) {
  ip_header *ip_h;
  u_int ip_head_len;

  /* retrieve the position of the ip header */
  ip_h = (ip_header *) (pkt_data + sizeof(ethernet_header)); //length of ethernet header (6B(MAC_S)+6B(MAC_D)+2B(ETHER_TYPE) = 14B)
  /* retrieve the position of the udp header */
  ip_head_len = (ip_h->ver_ihl & 0xf) * 4; //the length of the ip header must be computed since can be [20, 60] Bytes
  u_char offset = sizeof(ethernet_header) + ip_head_len;
  switch (ip_h->proto) {
    case TCP_IP:
      handle_tcp(pkt_data, offset);
      break;
    case UDP_IP:
      handle_udp(pkt_data, offset);
      break;
    default:
      break;
  }
}

void handle_udp(const u_char *pkt_data, u_char offset) {
  ip_header *ip_h;
  udp_header *udp_h;
  u_short source_port, dest_port;

  ip_h = (ip_header *) (pkt_data + sizeof(ethernet_header)); //length of ethernet header (6B(MAC_S)+6B(MAC_D)+2B(ETHER_TYPE) = 14B)
  udp_h = (udp_header *) (pkt_data + offset);

  /* convert from network byte order to host byte order */
  source_port = ntohs( udp_h->source_port );
  dest_port = ntohs( udp_h->dest_port );

  /* print ip addresses and udp ports */
  printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d UDP \n",
         ip_h->source_addr.byte1,
         ip_h->source_addr.byte2,
         ip_h->source_addr.byte3,
         ip_h->source_addr.byte4,
         source_port,
         ip_h->dest_addr.byte1,
         ip_h->dest_addr.byte2,
         ip_h->dest_addr.byte3,
         ip_h->dest_addr.byte4,
         dest_port);
}

void handle_tcp(const u_char *pkt_data, u_char offset) {
  ip_header *ip_h;
  tcp_header *tcp_h;
  u_short source_port, dest_port;

  ip_h = (ip_header *) (pkt_data + sizeof(ethernet_header)); //length of ethernet header (6B(MAC_S)+6B(MAC_D)+2B(ETHER_TYPE) = 14B)
  tcp_h = (tcp_header *) (pkt_data + offset);

  /* convert from network byte order to host byte order */
  source_port = ntohs( tcp_h->source_port );
  dest_port = ntohs( tcp_h->dest_port );

  if (dest_port == 0x0080){
    printf("HTTP Request");
  }

  /* print ip addresses and udp ports */
  printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d TCP \n",
         ip_h->source_addr.byte1,
         ip_h->source_addr.byte2,
         ip_h->source_addr.byte3,
         ip_h->source_addr.byte4,
         source_port,
         ip_h->dest_addr.byte1,
         ip_h->dest_addr.byte2,
         ip_h->dest_addr.byte3,
         ip_h->dest_addr.byte4,
         dest_port);
}