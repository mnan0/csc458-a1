#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    struct sr_arpreq *curr_req = sr->cache.requests;
    struct sr_arpreq *next_req = NULL;
    while(curr_req != NULL){
        /*It's possible curr_req will be destroyed in handle_arprequest and therefore we need to keep a ref to next*/
        next_req = curr_req->next;
        handle_arprequest(sr, curr_req);
        curr_req = next_req;
    }

}

void handle_arprequest(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(0);

    if (difftime(now, req->sent) >= 1.0){
        if (req->times_sent >= 5){
            /*Loop through each packet in req and send an icmp type 3 code 1*/
            struct sr_packet* curr_packet = req->packets;
            while (curr_packet != NULL){
      
                /*Unpack packet buf to get dhost from ethernet frame*/
                struct sr_ethernet_hdr* curr_packet_eth_hdr = (struct sr_ethernet_hdr*) (curr_packet->buf);
                struct sr_ip_hdr* curr_packet_ip_hdr = (struct sr_ip_hdr*) (curr_packet->buf + sizeof(struct sr_ethernet_hdr));
                
                /*Destination of the existing hdr should be the new source interface mac*/
                struct sr_if* outgoing_if = get_if_list_for_rt_ip(sr, curr_packet_ip_hdr->ip_src);
                
                if (!outgoing_if){
                    perror("Could not find packet's incoming interface.");
                }
                
                /* Set up ethernet header */
                struct sr_ethernet_hdr* ethernet_hdr = malloc(sizeof(struct sr_ethernet_hdr));

                memcpy(ethernet_hdr->ether_dhost, curr_packet_eth_hdr->ether_shost, sizeof(curr_packet_eth_hdr->ether_shost));
                memcpy(ethernet_hdr->ether_shost, outgoing_if->addr, sizeof(outgoing_if->addr));
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

                memcpy(&(ip_hdr->ip_src), &(outgoing_if->ip), sizeof(outgoing_if->ip));
                memcpy(&(ip_hdr->ip_dst), &(curr_packet_ip_hdr->ip_src), sizeof(curr_packet_ip_hdr->ip_src)); 
                ip_hdr->ip_sum=0;
                ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);


                /*Set up ICMP header*/
                struct sr_icmp_t3_hdr* icmp_hdr = malloc(sizeof(struct sr_icmp_t3_hdr));
                icmp_hdr->icmp_type = 3;
                icmp_hdr->icmp_code = 1;
                icmp_hdr->unused = 0;
                icmp_hdr->next_mtu = 1500;
                memcpy(icmp_hdr->data, curr_packet_ip_hdr, sizeof(struct sr_ip_hdr));
                memcpy(icmp_hdr->data + sizeof(struct sr_ip_hdr), curr_packet->buf  + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), ICMP_DATA_SIZE - sizeof(struct sr_ip_hdr));
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)); 
                
                /*Construct buf and send packet*/
                uint8_t* buf = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
                memcpy(buf, ethernet_hdr, sizeof(struct sr_ethernet_hdr));
                memcpy(buf + sizeof(struct sr_ethernet_hdr), ip_hdr, sizeof(struct sr_ip_hdr));
                memcpy(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
                sr_send_packet(sr, buf, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), outgoing_if->name);

                /* Free memory */
                free(ethernet_hdr);
                free(ip_hdr);
                free(icmp_hdr);
                free(buf);

                curr_packet = curr_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache),req);
        }
        else {
            /*Loop through all router interfaces and send an ARP request to each*/

            /*This should exist bc this won't run if packets aren't waiting*/
            struct sr_if * dest_interface = sr_get_interface(sr, req->packets->iface);
            if (!dest_interface){
                perror("No interfae found for ARP request construction in arpcache. No packets loaded up onto the req");
            }

            /* Set up ethernet header */
            struct sr_ethernet_hdr* ethernet_hdr = malloc(sizeof(struct sr_ethernet_hdr));
            uint8_t broadcast_mac[ETHER_ADDR_LEN] = {255,255,255,255,255,255};
            memcpy(ethernet_hdr->ether_dhost, broadcast_mac, sizeof(broadcast_mac));
            memcpy(ethernet_hdr->ether_shost,dest_interface->addr, sizeof(dest_interface->addr));
            ethernet_hdr->ether_type= htons(ethertype_arp);

            
            /* Set up ARP header */
            struct sr_arp_hdr* arp_hdr = malloc(sizeof(struct sr_arp_hdr));
            arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
            arp_hdr->ar_pro = htons(ethertype_ip);
            arp_hdr->ar_hln = sizeof(dest_interface->addr);
            arp_hdr->ar_pln = sizeof(dest_interface->ip);
            arp_hdr->ar_op = htons(arp_op_request);
            memcpy(arp_hdr->ar_sha,dest_interface->addr,sizeof(dest_interface->addr));
            memcpy(&(arp_hdr->ar_sip),&(dest_interface->ip),sizeof(uint32_t));
            memcpy(&(arp_hdr->ar_tip),&(req->ip),sizeof(uint32_t));
            
            uint8_t* buf = malloc(sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr));
            memcpy(buf, ethernet_hdr, sizeof(struct sr_ethernet_hdr));
            memcpy(buf + sizeof(struct sr_ethernet_hdr), arp_hdr, sizeof(struct sr_arp_hdr));
            

            sr_send_packet(sr, buf, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr),dest_interface->name);

            /* Free memory */
            free(ethernet_hdr);
            free(arp_hdr);
            free(buf);

            req->sent = now;
            req->times_sent++;
        }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                printf("Timing out cache");
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

