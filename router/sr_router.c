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
  
 /* Determine the type of frame */
  if (ether_type == ethertype_arp){
	/* ARP packet */
	printf("ARP Packet \n");
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));
	unsigned short ar_op = ntohs(arp_hdr->ar_op);
	
	struct sr_if *sr_if_con = sr_get_interface(sr, interface);

	uint32_t ip = ntohl(sr_if_con->ip);
	printf("Connected IF IP: %x \n", ip);
	printf("Connected IF Name: %s \n", sr_if_con->name);
	printf("Connected IF addr: %s \n", sr_if_con->addr);
	
	/* Determine if ARP req or reply */
	if (ar_op == arp_op_request){
	 	printf("ARP Req \n");
		printf("ARP sip: %x \n", ntohl(arp_hdr->ar_sip));
		printf("ARP tip: %x \n", ntohl(arp_hdr->ar_tip));
	} else if (ar_op == arp_op_reply){
		printf("ARP Reply \n");
	}

  } else if (ether_type == ethertype_ip){
	/*IP packet */
	printf("IP Packet \n");
  }


  /* fill in code here */

}/* end sr_ForwardPacket */

/* Handle ARP request helper */
void sr_handle_arp_req(sr_arp_hdr_t *arp_hdr, struct sr_if *sr_if)
{

}
