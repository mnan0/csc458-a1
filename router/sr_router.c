#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
        
    struct sr_rt* next_node = sr->routing_table;
    uint8_t* empty_packet=NULL;
    while (next_node != NULL){
      /* Note: necessary to queue at beginning? */
      struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), next_node->dest.s_addr, empty_packet, 0, next_node->interface);
      /*TODO: Figure out what to do with the req*/
      /* Current theory: freeing occurs after ICMP or reply is received*/
      next_node = next_node->next;
    }
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* TODO: Convert from network byte order to host byte order */
  /* TODO: Checksums! Use cksum in sr_utils.c to compare to buf's checksum. Remember to set checksum field to zero 
  before passing the buf to cksum*/

  /*
  Cases: 
  1. IP Packet
    Case 1: Addressed to router
      > If it's ICMP echo req, send echo reply
      > If it's TCP/UDP, send ICMP port unreachable (type 3 code 3)
    Case 2: Not addressed to router 
      > Check routing table
        - No match: ICMP net unreachable
        - Match: Check ARP cache
          -> Hit: Sent the frame to the next hop
          -> Miss: Send ARP request and queue packets waiting
  2. ARP Packet
    > Reply to me: Cache and send outstanding packets
    > Request to me: Construct reply and send 
  */

  /*Unpack packet buf to get dhost from ethernet frame*/
  struct sr_ethernet_hdr* curr_packet_eth_hdr = (struct sr_ethernet_hdr*) packet;
  uint16_t ether_type = ntohs(curr_packet_eth_hdr->ether_type);

  if (ether_type == ethertype_arp){
    /*Incoming packet is an ARP packet*/
    struct sr_arp_hdr* curr_packet_arp_hdr = (struct sr_arp_hdr*) (packet + sizeof(struct sr_ethernet_hdr));
    unsigned short opcode = ntohs(curr_packet_arp_hdr->ar_op);
    uint32_t arp_target_ip = curr_packet_arp_hdr->ar_tip;
      /** break here and check endianness*/
    if (opcode == arp_op_request){
      /*ARP Request, need to create a reply and send packet*/
      struct sr_if* input_interface = sr_get_interface(sr, interface);
      if (arp_target_ip == input_interface->ip){
        /*This request is for us, send a reply*/
         /* Set up ethernet header */
          struct sr_ethernet_hdr* ethernet_hdr = malloc(sizeof(struct sr_ethernet_hdr));
          memcpy(ethernet_hdr->ether_dhost, curr_packet_arp_hdr->ar_sha, sizeof(curr_packet_arp_hdr->ar_sha));
          memcpy(ethernet_hdr->ether_shost, input_interface->addr, sizeof(input_interface->addr));
          ethernet_hdr->ether_type= htons(ethertype_arp);

          /* Set up ARP header */
          struct sr_arp_hdr* arp_hdr = malloc(sizeof(struct sr_arp_hdr));
          arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
          arp_hdr->ar_pro = htons(ethertype_ip);
          arp_hdr->ar_hln = sizeof(input_interface->addr);
          arp_hdr->ar_pln = sizeof(input_interface->ip);
          arp_hdr->ar_op = htons(aarp_op_reply);
          memcpy(arp_hdr->ar_sha,input_interface->addr,sizeof(input_interface->addr));
          memcpy(arp_hdr->ar_tha, curr_packet_arp_hdr->ar_sha, sizeof(curr_packet_arp_hdr->ar_sha));
          memcpy(&(arp_hdr->ar_sip),&(input_interface->ip),sizeof(uint32_t));
          memcpy(&(arp_hdr->ar_tip),&(curr_packet_arp_hdr->ar_sip),sizeof(uint32_t));
          
          uint8_t* buf = malloc(sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr));
          memcpy(buf, ethernet_hdr, sizeof(*ethernet_hdr));
          memcpy(buf + sizeof(*ethernet_hdr), arp_hdr, sizeof(*arp_hdr));
          free(ethernet_hdr);
          free(arp_hdr);

          /*print_hdrs(buf, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr));*/
          sr_send_packet(sr, buf, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr), input_interface->name);

          /* Free memory */
          free(buf);
      }
      else {
        perror("ARP Request not sent to correct router interface ip");
      }

    }

    else if (opcode == arp_op_reply){
      /*ARP Reply, cache result and send all packets assosiated with request*/
      
      struct sr_if* input_interface = sr_get_interface(sr, interface);
      if (arp_target_ip == input_interface->ip){
        /*This reply is for us, insert into cache*/
        sr_arpcache_insert(&(sr->cache), curr_packet_arp_hdr->ar_sha, curr_packet_arp_hdr->ar_sip);
      }
      else {
        perror("ARP Reply not sent to correct router interface ip");
      }
      // else {
      //   /*Reply is for someone else, check if next hop is available*/
      //   /*First we check if dest ip is in the routing table, if not, send ICMP type 3 code 0 */
      //   struct sr_rt* curr_rt_node = sr->routing_table;
      //   bool matching_dest_ip = false;
      //   while (curr_rt_node != NULL){
      //     if (curr_rt_node->dest.s_addr == arp_target_ip) {
      //       matching_dest_ip = true;
      //     }
      //   }
      //   if (!matching_dest_ip){
      //     /*No matching route, send ICMP type 3 code 0*/
          
      //   }
      //   else {
      //     /*Next we check if the dest ip/mac is in the cache, if not add a request and store the packet*/
      //     struct sr_arpentry* returned_entry = sr_arpcache_lookup(sr->cache, arp_target_ip);
      //     if (returned_entry == NULL){
      //       /* Create an ARP request*/
      //     }
      //     else {
      //       /*Can we forward the packet to its desired ip*/

      //       free(returned_entry);
      //     }

      //     /*When previous conditions are met, forward the packet*/
          
      //   }
      // }
      
    }

    else {
      perror("ARP packet recieved but opcode isn't request or reply");
    }

  }
  else if (ether_type == ethertype_ip){
    /*Incoming packet is an IP packet*/
    struct sr_ip_hdr* curr_packet_ip_hdr = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));
    /*Checksum first, then check if ICMP or not. Checksum again for ICMP packets*/

  }

  else {
    perror("Incoming packet is neither ethertype ARP nor IP");
  }

}/* end sr_ForwardPacket */

