#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

void handle_arpreq(struct sr_instance * sr, struct sr_arpreq * req)
{
    if(difftime(time(NULL), req->sent) >= 0.9)
    {
        if(req->times_sent >= 5)
        {
            /* Send ICMP host unreachable */
            struct sr_packet * pkts = req->packets;

            while(pkts)
            {
                
                
                /* Loop through all packets and send ICMP host unreachable */
                uint8_t * packet = pkts->buf;
                
                struct sr_if * outgoing_if = sr_get_interface(sr, pkts->iface);
                
                /* Initialize current ether, ip header */
                struct sr_ethernet_hdr * ether_hdr = (sr_ethernet_hdr_t *)(packet);
                struct sr_ip_hdr * ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
                /*Create reply headers */
                struct sr_ethernet_hdr * ether_reply = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
                /*sr_fill_ether_hdr_reply(ether_hdr, ether_reply);*/

                sr_fill_ether_reply_arp(ether_hdr, ether_reply, outgoing_if);
                ether_reply->ether_type = htons(ethertype_ip);

                struct sr_ip_hdr * ip_reply = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
                sr_fill_ip_hdr_icmpt11(ip_hdr, ip_reply, ip_protocol_icmp, outgoing_if->ip, pkts->len - sizeof(sr_ethernet_hdr_t));

                struct sr_icmp_t3_hdr * icmp_t3_reply = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
                sr_fill_icmp_t3_reply(icmp_t3_reply,3, 1, packet, pkts->len);
                uint8_t * reply_packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

                memcpy(reply_packet, ether_reply, sizeof(sr_ethernet_hdr_t));
                memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), ip_reply, sizeof(sr_ip_hdr_t));
                memcpy(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_t3_reply, sizeof(sr_icmp_t3_hdr_t));
                struct sr_rt * outgoing_rt = find_rt_by_ip(sr, ip_reply->ip_dst);

                printf("outgoing_rt->interface: %s \n", outgoing_rt->interface);
                print_addr_ip_int(ip_reply->ip_dst);
                printf("Outgoing interface: %s \n", pkts->iface);

                sr_send_packet(sr, reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), pkts->iface);

                printf("Sent out below: \n");
                print_hdrs(reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +sizeof(sr_icmp_t3_hdr_t));
                free(ether_reply);
                free(ip_reply);
                free(icmp_t3_reply);
                free(reply_packet);




                pkts = pkts->next;
            }



            sr_arpreq_destroy(&(sr->cache), req);

        } else 
        {
            /* Send ARP req */
            

            /* Find the outgoing interface name given ip (gateway) */

            struct sr_rt* rt_walker = 0;
            char * if_name = (char *) malloc(sr_IFACE_NAMELEN * sizeof(char));
            rt_walker = sr->routing_table;
            print_addr_ip_int(req->ip);
           
            if (rt_walker == 0)
            {
                printf("rt_walker is zero!\n");
                return;
                                                                                    
            }
            printf("Before rt_walker \n");
            sr_print_routing_table(sr);

            while(rt_walker)
            {
                printf("In rt walker\n");
                if (rt_walker->gw.s_addr == req->ip)
                {
                    memcpy(if_name, rt_walker->interface, sr_IFACE_NAMELEN);
                    printf("Found IF name\n");
                    break;
                
                }
                rt_walker = rt_walker->next;
            }

            printf("After rt_walker \n");
            sr_print_routing_table(sr);
            
            printf("if_name: %s \n", if_name);
            
            struct sr_if * target_if = sr_get_interface(sr, if_name);
           
            assert(target_if);

            struct sr_ethernet_hdr * ether_reply = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));

            sr_fill_ether_req_arp(ether_reply, target_if);
            
            struct sr_arp_hdr * arp_req = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));
            sr_fill_arp_req(arp_req, target_if, ether_reply, req->ip);

            uint8_t * reply_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            memcpy(reply_packet, ether_reply, sizeof(sr_ethernet_hdr_t));
            memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), arp_req, sizeof(sr_arp_hdr_t));

            printf("send arp req target_if->name %s \n", target_if->name);

            sr_send_packet(sr, reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), target_if->name);
            
            
            printf("Sent out below ARP req: \n");
            print_hdrs(reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            free(ether_reply);
            free(arp_req);
            free(reply_packet);
            free(if_name);
            /*free(rt_walker);*/
            
            req->sent = time(NULL);
            req->times_sent++;

        }
    }
    
}



/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* For each request, in sr->cache, call handle_arpreq */
    struct sr_arpcache * cache = &(sr->cache);
    struct sr_arpreq * req = cache->requests;
    while(req)
    {
        handle_arpreq(sr, req);
        req = req->next;
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
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

