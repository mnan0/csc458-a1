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
    while (next_node != NULL){
      /* TODO: Note: necessary to queue at beginning? */
      /*struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), next_node->dest.s_addr, empty_packet, 0, next_node->interface);*/
      /*TODO: Figure out what to do with the req*/
      /* Current theory: freeing occurs after ICMP or reply is received*/
      next_node = next_node->next;
    }
} /* -- sr_init -- */

/* 
Converts decimal to binary
From https://stackoverflow.com/questions/15114140/writing-binary-number-system-in-c-code
// static inline unsigned long long S_to_binary_(const char *s)
// {
//         unsigned long long i = 0;
//         while (*s) {
//                 i <<= 1;
//                 i += *s++ - '0';
//         }
//         return i;
// }
Method: sr_lpm()
Scope: local

Helper function to calculate longest prefix match
Returns the IP address in the routing table that most closely matches the given IP
*/
struct in_addr * sr_lpm(struct sr_instance * sr,uint32_t ip_dst){
  struct sr_rt * curr_rt = sr->routing_table;
  uint32_t masked=0;
  while (curr_rt != NULL){
    /* unsigned long long dest_binary = S_to_binary_((const char *)&(curr_rt->dest.s_addr));*/
    masked = curr_rt->mask.s_addr & curr_rt->dest.s_addr;
    if (masked == ip_dst){
      return &(curr_rt->dest);
    }
    curr_rt = curr_rt->next;
  }
  return NULL;
}
/*
Loop over the routing table, find the rt with destination matching rt_ip, then return the ip's interface list instance
*/
struct sr_if * get_if_list_for_rt_ip(struct sr_instance * sr, unsigned long rt_ip){
  struct sr_rt * curr_rt = sr->routing_table;
  while (curr_rt != NULL){
    if (curr_rt->dest.s_addr == rt_ip){
      return sr_get_interface(sr,curr_rt->interface);
      
    }
    curr_rt = curr_rt->next;
  }
  return NULL;
}

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
  struct sr_if* input_interface = sr_get_interface(sr, interface);

   /*-----------------------------------------ARP PACKET HANDLING----------------------------------*/
  
  if (ether_type == ethertype_arp){
    /*Incoming packet is an ARP packet*/
    struct sr_arp_hdr* curr_packet_arp_hdr = (struct sr_arp_hdr*) (packet + sizeof(struct sr_ethernet_hdr));
    unsigned short opcode = ntohs(curr_packet_arp_hdr->ar_op);
    uint32_t arp_target_ip = curr_packet_arp_hdr->ar_tip;
      /** break here and check endianness*/
    if (opcode == arp_op_request){
      /*ARP Request, need to create a reply and send packet*/
      if (arp_target_ip == input_interface->ip){
        /*This request is for us, send a reply*/
         /* printf("INCOMING ARP REQUEST PACKET FOR US!\n");*/
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
          arp_hdr->ar_op = htons(arp_op_reply);
          memcpy(arp_hdr->ar_sha,input_interface->addr,sizeof(input_interface->addr));
          memcpy(arp_hdr->ar_tha, curr_packet_arp_hdr->ar_sha, sizeof(curr_packet_arp_hdr->ar_sha));
          memcpy(&(arp_hdr->ar_sip),&(input_interface->ip),sizeof(uint32_t));
          memcpy(&(arp_hdr->ar_tip),&(curr_packet_arp_hdr->ar_sip),sizeof(uint32_t));
          
          uint8_t* buf = malloc(sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr));
          memcpy(buf, ethernet_hdr, sizeof(*ethernet_hdr));
          memcpy(buf + sizeof(*ethernet_hdr), arp_hdr, sizeof(*arp_hdr));
          
          /*print_hdrs(buf, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr));*/
          sr_send_packet(sr, buf, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr), input_interface->name);
          /*print_hdrs(buf, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr));*/
          /* Free memory */
          free(ethernet_hdr);
          free(arp_hdr);
          free(buf);
      }
      else {
        printf("ARP Request not sent to correct router interface ip");
      }

    }

    else if (opcode == arp_op_reply){
      /*ARP Reply, cache result and send all packets assosiated with request*/
      
      struct sr_if* input_interface = sr_get_interface(sr, interface);
      if (arp_target_ip == input_interface->ip){
        /*printf("INCOMING ARP REPLY PACKET FOR US!\n");*/
        /*This reply is for us, insert into cache*/
        struct sr_arpreq * arpreq_for_currip = sr_arpcache_insert(&(sr->cache), curr_packet_arp_hdr->ar_sha, curr_packet_arp_hdr->ar_sip);
        if (arpreq_for_currip){
          /*TODO: Send all packets that were queues on the req and destroy req*/
          struct sr_packet* curr_packet = arpreq_for_currip->packets;
          struct sr_arpentry* cache_entry = sr_arpcache_lookup(&(sr->cache), arpreq_for_currip->ip);
          if (!cache_entry){
            printf("No cache entry for request that was supposed to have just been inserted");
          }
          while (curr_packet != NULL){
            /*printf("SENDING PACKET FROM REQ QUEUE!\n");*/
            /*Need to change the MAC address on the packet before sending*/
            curr_packet_eth_hdr = (struct sr_ethernet_hdr*) curr_packet->buf;
            struct sr_if* output_interface = sr_get_interface(sr, curr_packet->iface);
            memcpy(curr_packet_eth_hdr->ether_dhost, cache_entry->mac , sizeof( cache_entry->mac));
            memcpy(curr_packet_eth_hdr->ether_shost, output_interface->addr, sizeof(output_interface->addr));

            print_hdrs(curr_packet->buf,sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_hdr));
            sr_send_packet(sr, curr_packet->buf, curr_packet->len, output_interface->name);
            curr_packet = curr_packet->next;
          }
          free(cache_entry);
          sr_arpreq_destroy(&(sr->cache), arpreq_for_currip);
        }
        else{
          printf("Router received ARP reply without asking for it.\n");
        }
      }
      else {
        printf("ARP Reply not sent to correct router interface ip");
      }      
    }

    else {
      printf("ARP packet recieved but opcode isn't request or reply");
    }

  }
  /*-----------------------------------------IP/ICMP PACKET HANDLING----------------------------------*/
  else if (ether_type == ethertype_ip){
    /*Incoming packet is an IP packet*/
    /*printf("INCOMING IP PACKET!\n");*/
    struct sr_ip_hdr* curr_packet_ip_hdr = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));
    /*Checksum first, then check if ICMP or not. Checksum again for ICMP packets*/
    if (curr_packet_ip_hdr->ip_ttl == 0){
      return;
    }
    /* If the ttl is 1 AND the destination IP is not part of this router's if list, then send type 11*/
    int dest_is_router_interface = 0;
    struct sr_if * current_router_interface = sr->if_list;
    while (current_router_interface != NULL){
      if (current_router_interface->ip == curr_packet_ip_hdr->ip_dst){
        dest_is_router_interface = 1;
      }
      current_router_interface = current_router_interface->next;
    }
    if (curr_packet_ip_hdr->ip_ttl == 1 && 
    ((dest_is_router_interface==0 && (curr_packet_ip_hdr->ip_p == 6 || curr_packet_ip_hdr->ip_p == 17)) || (curr_packet_ip_hdr->ip_p!=6 && curr_packet_ip_hdr->ip_p!=17))){
      /*TODO: Need to send a ICMP Time exceed type 11*/
        /* Set up ethernet header */
        /*curr_packet_ip_hdr->ip_ttl--;*/
        struct sr_ethernet_hdr* ethernet_hdr = malloc(sizeof(struct sr_ethernet_hdr));
        struct sr_if* new_source = get_if_list_for_rt_ip(sr, curr_packet_ip_hdr->ip_src);

        if (new_source == 0){
            printf("Packet interface not recognized by routing table.");
        }
        /*Unpack packet buf to get dhost from ethernet frame*/

        memcpy(ethernet_hdr->ether_dhost, curr_packet_eth_hdr->ether_shost, sizeof(curr_packet_eth_hdr->ether_shost));
        memcpy(ethernet_hdr->ether_shost, new_source->addr, sizeof(new_source->addr));
        ethernet_hdr->ether_type = htons(ethertype_ip);

        /*Set up IP header*/
        struct sr_ip_hdr* ip_hdr = malloc(sizeof(struct sr_ip_hdr));
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = htons(IP_DF); /* if this causes problems, try IP_RF*/
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
        ip_hdr->ip_v = 4;
        memcpy(&(ip_hdr->ip_src), &(new_source->ip), sizeof(new_source->ip));
        memcpy(&(ip_hdr->ip_dst), &(curr_packet_ip_hdr->ip_src), sizeof(curr_packet_ip_hdr->ip_src)); 
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
        

        /*Set up ICMP header*/
        struct sr_icmp_t3_hdr* icmp_hdr = malloc(sizeof(struct sr_icmp_t3_hdr));
        icmp_hdr->icmp_type = 11;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 1500;

        memcpy(icmp_hdr->data,  (uint8_t*) curr_packet_ip_hdr, sizeof(struct sr_ip_hdr));
        memcpy(icmp_hdr->data + sizeof(struct sr_ip_hdr), (uint8_t*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)),  ICMP_DATA_SIZE - sizeof(struct sr_ip_hdr));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)); 
        
        /*Construct buf and send packet*/
        uint8_t* buf = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
        memcpy(buf, ethernet_hdr, sizeof(struct sr_ethernet_hdr));
        memcpy(buf + sizeof(struct sr_ethernet_hdr), ip_hdr, sizeof(struct sr_ip_hdr));
        memcpy(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
        
        /*Check if we need to either send or add to queue*/
        struct sr_arpentry * matching_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
        if (!matching_entry){
          /*No matching ARP entry, need to add a request and queue the packet*/
          /*printf("Adding an ARP request to ");
          print_addr_ip_int(ip_hdr->ip_dst);
          printf("\n");*/
          sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), interface);
           /* Free memory */
          free(ethernet_hdr);
          free(ip_hdr);
          free(icmp_hdr);
          free(buf);
          return;
        }
        sr_send_packet(sr, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), interface);
        /* Free memory */
        free(matching_entry);
        free(ethernet_hdr);
        free(ip_hdr);
        free(icmp_hdr);
        free(buf);
        return;
    }
    uint16_t incoming_packet_sum = curr_packet_ip_hdr->ip_sum;
    
    curr_packet_ip_hdr->ip_sum = 0;
    uint16_t new_calculated_sum = cksum(curr_packet_ip_hdr, curr_packet_ip_hdr->ip_hl * 4);
    if (incoming_packet_sum == new_calculated_sum && sizeof(*curr_packet_ip_hdr) >= sizeof(struct sr_ip_hdr)){
      /*decrement ttl and recalculate cksum*/
      curr_packet_ip_hdr->ip_ttl--;
      curr_packet_ip_hdr->ip_sum = cksum(curr_packet_ip_hdr, curr_packet_ip_hdr->ip_hl * 4);

      /*Check if ICMP Echo request for us (is it for one of the router interfaces), checksum the ICMP header and send a reply*/
      /*int dest_is_router_interface = 0;
      struct sr_if * current_router_interface = sr->if_list;
      while (current_router_interface != NULL){
        if (current_router_interface->ip == curr_packet_ip_hdr->ip_dst){
          dest_is_router_interface = 1;
        }
        current_router_interface = current_router_interface->next;
      }*/
      if (curr_packet_ip_hdr->ip_p == ip_protocol_icmp && dest_is_router_interface==1/*&& curr_packet_ip_hdr->ip_dst == input_interface->ip*/){
        /*Incoming ICMP request destined for the router*/
        /*Checksum the ICMP and check that the request is an echo request*/
        struct sr_icmp_hdr* curr_packet_icmp_hdr = (struct sr_icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        uint16_t incoming_icmp_sum =  curr_packet_icmp_hdr->icmp_sum;
        curr_packet_icmp_hdr->icmp_sum = 0;
        uint16_t new_icmp_calculated_sum = cksum(curr_packet_icmp_hdr, ntohs(curr_packet_ip_hdr->ip_len) - sizeof(struct sr_ip_hdr));
        if (incoming_icmp_sum != new_icmp_calculated_sum || (ntohs(curr_packet_ip_hdr->ip_len) - sizeof(struct sr_ip_hdr)) < sizeof(struct sr_icmp_hdr)){
          /*Checksum failed, return early and drop packet*/
          return;
        }
        /*Check if reply destination in ARP cache, otherwise set up ARP request and store packet*/
        
        /*Send the echo reply*/

        /*The new source ip/MAC should be whatever interface handles the packets source ip*/
        struct sr_if* new_source = get_if_list_for_rt_ip(sr, curr_packet_ip_hdr->ip_src);
        memcpy(curr_packet_eth_hdr->ether_dhost, curr_packet_eth_hdr->ether_shost, sizeof(curr_packet_eth_hdr->ether_shost));
        memcpy(curr_packet_eth_hdr->ether_shost, new_source->addr, sizeof(new_source->addr));
        
        /*uint32_t temp_ip = curr_packet_ip_hdr->ip_dst;*/
        memcpy(&(curr_packet_ip_hdr->ip_dst), &(curr_packet_ip_hdr->ip_src), sizeof(curr_packet_ip_hdr->ip_src));
        memcpy(&(curr_packet_ip_hdr->ip_src), &(new_source->ip), sizeof(new_source->ip));
        curr_packet_ip_hdr->ip_sum = 0;
        curr_packet_ip_hdr->ip_sum = cksum(curr_packet_ip_hdr, curr_packet_ip_hdr->ip_hl * 4);

        curr_packet_icmp_hdr->icmp_code = 0;
        curr_packet_icmp_hdr->icmp_type = 0;
        curr_packet_icmp_hdr->icmp_sum = 0;
        curr_packet_icmp_hdr->icmp_sum = cksum(curr_packet_icmp_hdr, ntohs(curr_packet_ip_hdr->ip_len) - sizeof(struct sr_ip_hdr));

        /*END Echo reply construction*/

        /* free(matching_entry);*/
        /*check arp cache for mac address for dest. ip, if it's not there, send arp request and add this packet to req's packet list*/
        struct sr_arpentry * matching_entry = sr_arpcache_lookup(&(sr->cache), curr_packet_ip_hdr->ip_dst);
        if (!matching_entry){
          /*No matching ARP entry, need to add a request and queue the packet*/
          /*printf("Adding an ARP request to ");
          print_addr_ip_int(curr_packet_ip_hdr->ip_dst);
          printf("\n");*/
          sr_arpcache_queuereq(&(sr->cache), curr_packet_ip_hdr->ip_dst, packet, len, interface);
          return;
        }
        /*If we got here, we can send the packet!*/
        sr_send_packet(sr, packet, len, interface);
        free(matching_entry);
        return;
      }
      /*END ECHO REPLY CONSTRUCTION*/

      /*ICMP TYPE 3 CODE 3 CONSTRUCTION*/
      else if (/*curr_packet_ip_hdr->ip_dst == input_interface->ip*/ dest_is_router_interface==1 && (curr_packet_ip_hdr->ip_p == 6 || curr_packet_ip_hdr->ip_p == 17)) {
        /*TODO: TCP/UDP addressed to us, we need to send ICMP type 3 code 3*/

        /* Set up ethernet header */
        struct sr_ethernet_hdr* ethernet_hdr = malloc(sizeof(struct sr_ethernet_hdr));
        struct sr_if* new_source = get_if_list_for_rt_ip(sr, curr_packet_ip_hdr->ip_src);

        if (new_source == 0){
            printf("Packet interface not recognized by routing table.");
        }
        /*Unpack packet buf to get dhost from ethernet frame*/

        memcpy(ethernet_hdr->ether_dhost, curr_packet_eth_hdr->ether_shost, sizeof(curr_packet_eth_hdr->ether_shost));
        memcpy(ethernet_hdr->ether_shost, new_source->addr, sizeof(new_source->addr));
        ethernet_hdr->ether_type = htons(ethertype_ip);

        /*Set up IP header*/
        struct sr_ip_hdr* ip_hdr = malloc(sizeof(struct sr_ip_hdr));
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = htons(IP_DF); /* if this causes problems, try IP_RF*/
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
        ip_hdr->ip_v = 4;
        ip_hdr->ip_sum = 0;
        memcpy(&(ip_hdr->ip_src), &(new_source->ip), sizeof(new_source->ip));
        memcpy(&(ip_hdr->ip_dst), &(curr_packet_ip_hdr->ip_src), sizeof(curr_packet_ip_hdr->ip_src));
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4); 

        /*Set up ICMP header*/
        struct sr_icmp_t3_hdr* icmp_hdr = malloc(sizeof(struct sr_icmp_t3_hdr));
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 3;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 1500;
        memcpy(icmp_hdr->data, curr_packet_ip_hdr, sizeof(struct sr_ip_hdr));
        memcpy(icmp_hdr->data + sizeof(struct sr_ip_hdr), packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr),  ICMP_DATA_SIZE - sizeof(struct sr_ip_hdr));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)); 
        
        /*Construct buf and send packet*/
        uint8_t* buf = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
        memcpy(buf, ethernet_hdr, sizeof(struct sr_ethernet_hdr));
        memcpy(buf + sizeof(struct sr_ethernet_hdr), ip_hdr, sizeof(struct sr_ip_hdr));
        memcpy(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
        
        /*Check if we need to either send or add to queue*/
        struct sr_arpentry * matching_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
        if (!matching_entry){
          /*No matching ARP entry, need to add a request and queue the packet*/
          /*printf("Adding an ARP request to ");
          print_addr_ip_int(ip_hdr->ip_dst);
          printf("\n");*/
          sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), interface);
           /* Free memory */
          free(ethernet_hdr);
          free(ip_hdr);
          free(icmp_hdr);
          free(buf);
          return;
        }
  

        sr_send_packet(sr, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), interface);
        /* Free memory */
        free(matching_entry);
        free(ethernet_hdr);
        free(ip_hdr);
        free(icmp_hdr);
        free(buf);
        return;
      }
      
      
      /*If we get here, we need to forward a packet*/
      /*longest prefix match in routing table*/
      struct in_addr* best_match = sr_lpm(sr, curr_packet_ip_hdr->ip_dst);
      if (!best_match){
        /*No best match, need to send destination host unreachable ICMP type 3 code 0*/
        /* Set up ethernet header */
        /*curr_packet_ip_hdr->ip_ttl--;*/
        struct sr_ethernet_hdr* ethernet_hdr = malloc(sizeof(struct sr_ethernet_hdr));
        struct sr_if* new_source = get_if_list_for_rt_ip(sr, curr_packet_ip_hdr->ip_src);

        if (new_source == 0){
            printf("Packet interface not recognized by routing table.");
        }
        /*Unpack packet buf to get dhost from ethernet frame*/

        memcpy(ethernet_hdr->ether_dhost, curr_packet_eth_hdr->ether_shost, sizeof(curr_packet_eth_hdr->ether_shost));
        memcpy(ethernet_hdr->ether_shost, new_source->addr, sizeof(new_source->addr));
        ethernet_hdr->ether_type = htons(ethertype_ip);

        /*Set up IP header*/
        struct sr_ip_hdr* ip_hdr = malloc(sizeof(struct sr_ip_hdr));
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = htons(IP_DF); /* if this causes problems, try IP_RF*/
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
        ip_hdr->ip_v = 4;
        memcpy(&(ip_hdr->ip_src), &(new_source->ip), sizeof(new_source->ip));
        memcpy(&(ip_hdr->ip_dst), &(curr_packet_ip_hdr->ip_src), sizeof(curr_packet_ip_hdr->ip_src)); 
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
        

        /*Set up ICMP header*/
        struct sr_icmp_t3_hdr* icmp_hdr = malloc(sizeof(struct sr_icmp_t3_hdr));
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 1500;

        memcpy(icmp_hdr->data,  (uint8_t*) curr_packet_ip_hdr, sizeof(struct sr_ip_hdr));
        memcpy(icmp_hdr->data + sizeof(struct sr_ip_hdr), (uint8_t*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)),  ICMP_DATA_SIZE - sizeof(struct sr_ip_hdr));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)); 
        
        /*Construct buf and send packet*/
        uint8_t* buf = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
        memcpy(buf, ethernet_hdr, sizeof(struct sr_ethernet_hdr));
        memcpy(buf + sizeof(struct sr_ethernet_hdr), ip_hdr, sizeof(struct sr_ip_hdr));
        memcpy(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
        
        /*Check if we need to either send or add to queue*/
        struct sr_arpentry * matching_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
        if (!matching_entry){
          /*No matching ARP entry, need to add a request and queue the packet*/
          /*printf("Adding an ARP request to ");
          print_addr_ip_int(ip_hdr->ip_dst);
          printf("\n");*/
          sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), interface);
           /* Free memory */
          free(ethernet_hdr);
          free(ip_hdr);
          free(icmp_hdr);
          free(buf);
          return;
        }
        sr_send_packet(sr, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), interface);
        /* Free memory */
        free(matching_entry);
        free(ethernet_hdr);
        free(ip_hdr);
        free(icmp_hdr);
        free(buf);
        return;
      }
      /*check arp cache for mac address for dest. ip, if it's not there, send arp request and add this packet to req's packet list*/
      struct sr_arpentry * matching_entry = sr_arpcache_lookup(&(sr->cache), best_match->s_addr);
      struct sr_if * outgoing_interface = get_if_list_for_rt_ip(sr,best_match->s_addr);
      if (!matching_entry){
        /*No matching ARP entry, need to add a request and queue the packet*/
        /*printf("Adding an ARP request to ");
        print_addr_ip(*best_match);
        printf("\n");*/
        sr_arpcache_queuereq(&(sr->cache), best_match->s_addr, packet, len, outgoing_interface->name);
        return;
      }
       /*Rewrite packet ethernet header to be correct source and dest mac*/

      memcpy(curr_packet_eth_hdr->ether_dhost, matching_entry->mac, sizeof(matching_entry->mac));
      
      memcpy(curr_packet_eth_hdr->ether_shost, outgoing_interface->addr, sizeof(outgoing_interface->addr));
      sr_send_packet(sr, packet, len, outgoing_interface->name);
      free(matching_entry);
    }
  }

  else {
    printf("Incoming packet is neither ethertype ARP nor IP");
  }

}/* end sr_ForwardPacket */

