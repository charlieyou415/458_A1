/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

struct sr_if* find_tip_in_router(struct sr_instance *sr, uint32_t tip);

void sr_fill_icmp_echo_reply(uint8_t * packet, sr_ethernet_hdr_t *ether_hdr, sr_ethernet_hdr_t *ether_reply, sr_ip_hdr_t *ip_hdr, sr_ip_hdr_t * ip_reply, sr_icmp_hdr_t *icmp_hdr, sr_icmp_hdr_t * icmp_reply);

void sr_fill_ether_reply_arp(sr_ethernet_hdr_t *ether_hdr, sr_ethernet_hdr_t *ether_hdr_reply, struct sr_if *sr_if_con);

void sr_fill_arp_reply(sr_arp_hdr_t *arp_hdr,sr_arp_hdr_t *arp_hdr_reply, struct sr_if *sr_if_con);

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
    
    /* Add initialization code here! */

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

  /* Sanity check still needed!!!!!!!!!!!!!!*/
  /* ****************************************/


  
  
  /*print_hdrs(packet, len);*/
  
  /*printf("interface: %s", interface);*/
  uint16_t ether_type = ethertype(packet);
  /* Initialize ethernet header */
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;


 /* Determine the type of frame */
  if (ether_type == ethertype_arp){
	/* ARP packet */
	printf("ARP Packet \n");
	print_hdrs(packet, len);
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	unsigned short ar_op = ntohs(arp_hdr->ar_op);
	

	
	/* Determine if ARP req or reply */
	if (ar_op == arp_op_request){

		/* Find the interface matching with the ARP tip */
		struct sr_if* target_if = find_tip_in_router(sr, arp_hdr->ar_tip);
		/* Initialize a new ethernet header */
		struct sr_ethernet_hdr *ether_hdr_reply = (struct sr_ethernet_hdr *) malloc(sizeof(sr_ethernet_hdr_t));
		/* Initialize a new arp header/packet */
		struct sr_arp_hdr *arp_hdr_reply = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));
		/* Initialize a new PACKET, to hold ether_hdr + arp_packet */
		uint8_t * reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));		



		if(target_if){
		  printf("ARP to my IPs\n");
		  /* The requested tip is one of the router's interfaces, REPLY */
			/* Create a new ethernet header */
                	sr_fill_ether_reply_arp(ether_hdr, ether_hdr_reply, target_if);

                	/* Create a new arp packet */
                	sr_fill_arp_reply(arp_hdr, arp_hdr_reply, target_if);

                	/* Put the new ethernet hdr + arp packet together */
                	memcpy(reply_packet, ether_hdr_reply, sizeof(sr_ethernet_hdr_t));
                	memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), arp_hdr_reply, sizeof(sr_arp_hdr_t));
			printf("ARP Reply sent: \n");
			print_hdrs(reply_packet, len);
                	/* Send the packet back */
                	sr_send_packet(sr, reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), target_if->name);
		} else {
		 printf("ARP not to my IPs\n");
		  /* The requested tip is not one of the router's interfaces, BROADCAST */
			struct sr_if* if_walker = 0;
			if_walker = sr->if_list;
			while(if_walker)
			{
				if(!strncmp(if_walker->name, interface, sr_IFACE_NAMELEN))
				{
					sr_fill_ether_reply_arp(ether_hdr, ether_hdr_reply, if_walker);
					sr_fill_arp_reply(arp_hdr, arp_hdr_reply, if_walker);
					memcpy(reply_packet, ether_hdr_reply, sizeof(sr_ethernet_hdr_t));
					memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), arp_hdr_reply, sizeof(sr_arp_hdr_t));												                        				printf("ARP Reply sent: \n");
                        		print_hdrs(reply_packet, len);


					sr_send_packet(sr, reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), if_walker->name);
				}
			}
			
		}
		
		
				
	
		free(ether_hdr_reply);
		free(arp_hdr_reply);
		free(reply_packet);




	} else if (ar_op == arp_op_reply){
		printf("ARP Reply \n");
	}

  } else if (ether_type == ethertype_ip){
	/*IP packet */
	printf("IP Packet \n");
	/* Construct an IP hdr */
	struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	/*print_hdrs(packet, len);*/
	printf("Received below:\n");
	print_hdrs(packet, len);


	/* Check if the target ip is for me (In one of my interfaces) */
	struct sr_if * target_if = find_tip_in_router(sr, ip_hdr->ip_dst);
	

	/* If the IP packet is for me */
	if (target_if){
		printf("IP Packet for me\n");
		uint8_t ip_proto = ip_hdr->ip_p;
		/* Initialize a new reply_packet for ICMP */
        	uint8_t * reply_packet = (uint8_t *) malloc(len * sizeof(uint8_t));
		/* ICMP packet */
		printf("ip_proto: %u \n", ip_proto);
		printf("ip_protocol: %u \n", ip_protocol_icmp);
		if(ip_proto == ip_protocol_icmp)
		{
			printf("ICMP Packet\n");
			struct sr_icmp_hdr * icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(sr_ethernet_hdr_t)  + sizeof(sr_ip_hdr_t));
			printf("ICMP Type: %u \n", icmp_hdr->icmp_type);
			printf("ICMP Code: %u \n", icmp_hdr->icmp_code);
			if((icmp_hdr->icmp_type == 8) && (icmp_hdr->icmp_code == 0))
			/* If it's an ICMP Req message, construct a reply */
			{
				printf("ICMP Req\n");
				/* Create a new ethernet header */
				struct sr_ethernet_hdr * ether_reply = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
				/* Create a new ip header */
				struct sr_ip_hdr * ip_reply = (sr_ip_hdr_t *) malloc(sizeof(sr_ip_hdr_t));
				/* Create a new icmp header */
				struct sr_icmp_hdr * icmp_reply = (struct sr_icmp_hdr *) malloc(sizeof(sr_icmp_hdr_t));
				sr_fill_icmp_echo_reply(packet, ether_hdr, ether_reply, ip_hdr, ip_reply, icmp_hdr, icmp_reply);
				/* Combine ethernet + ip + icmp headers */
				memcpy(reply_packet, packet, len);
				memcpy(reply_packet, ether_reply, sizeof(sr_ethernet_hdr_t));
				memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), ip_reply, sizeof(sr_ip_hdr_t));
				memcpy(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_reply, sizeof(sr_icmp_hdr_t));
				

				printf("target_if->name: %s \n", target_if->name);

				sr_send_packet(sr, reply_packet, len, target_if->name);
				printf("Sent out below: \n");
				print_hdrs(reply_packet, len);
				free(ether_reply);
				free(ip_reply);
				free(icmp_reply);
				free(reply_packet);
									
			}
		} else {
		printf("TCP or UDP Packet\n");
		/* TCP or UDP Packet */
		}
		
	} else {
	/* If the IP packet is not for me */
	}

  }


  /* fill in code here */

}/* end sr_ForwardPacket */



struct sr_if* find_tip_in_router(struct sr_instance *sr, uint32_t tip)
{
	struct sr_if* if_walker = 0;
	assert(sr);
	assert(tip);
	
	if_walker = sr->if_list;
	while(if_walker)
	{
		if(if_walker->ip == tip){
	  		return if_walker;
	  	}
		if_walker = if_walker->next;
	}
	return 0;
}


void sr_fill_icmp_echo_reply(uint8_t * packet, sr_ethernet_hdr_t *ether_hdr, sr_ethernet_hdr_t *ether_reply, sr_ip_hdr_t *ip_hdr, sr_ip_hdr_t * ip_reply, sr_icmp_hdr_t *icmp_hdr, sr_icmp_hdr_t * icmp_reply)
{

	/* Copy existing icmp hdr */
	memcpy(icmp_reply, icmp_hdr, sizeof(sr_icmp_hdr_t));
	icmp_reply->icmp_type = 0;
	icmp_reply->icmp_code = 0;
	icmp_reply->icmp_sum = cksum(icmp_reply, sizeof(sr_icmp_hdr_t));

        /* copy existing ip header */
        memcpy(ip_reply, ip_hdr, sizeof(sr_ip_hdr_t));
        /* Switch source/dest IP address */
        ip_reply->ip_src = ip_hdr->ip_dst;
        ip_reply->ip_dst = ip_hdr->ip_src;
        ip_reply->ip_ttl = 64;
        ip_reply->ip_sum = cksum(ip_reply, sizeof(sr_ip_hdr_t));

        /* Copy existing ethernet header */
        memcpy(ether_reply, ether_hdr, sizeof(sr_ethernet_hdr_t));
        /* Switch source/dest mac addresses */
        memcpy(ether_reply->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(ether_reply->ether_shost, ether_hdr->ether_dhost, ETHER_ADDR_LEN);


}


void sr_fill_ether_reply_arp(sr_ethernet_hdr_t *ether_hdr, sr_ethernet_hdr_t *ether_hdr_reply, struct sr_if *sr_if_con)
{
  memcpy(ether_hdr_reply->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ether_hdr_reply->ether_shost, sr_if_con->addr, ETHER_ADDR_LEN);
  ether_hdr_reply->ether_type = htons(ethertype_arp);
}

void sr_fill_arp_reply(sr_arp_hdr_t *arp_hdr,sr_arp_hdr_t *arp_hdr_reply, struct sr_if *sr_if_con)
{
  /* Need to construct a new arp hdr */
  arp_hdr_reply->ar_hrd = arp_hdr->ar_hrd;
  arp_hdr_reply->ar_pro = arp_hdr->ar_pro;
  arp_hdr_reply->ar_hln = arp_hdr->ar_hln;
  arp_hdr_reply->ar_pln = arp_hdr->ar_pln;
  /* Change op_code to reply */
  arp_hdr_reply->ar_op = htons(arp_op_reply);
  /* Copy the router's interface address as sender's address */
  memcpy(arp_hdr_reply->ar_sha, sr_if_con->addr, ETHER_ADDR_LEN);
  /* Copy the router's interface ip as sender's ip */ 
  arp_hdr_reply->ar_sip = sr_if_con->ip;
  /* Copy the old sender hw address as target hw addr */
  memcpy(arp_hdr_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  /* copy the old sender ip as target ip */
  arp_hdr_reply->ar_tip = arp_hdr->ar_sip;
}
