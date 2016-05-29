/*--------------------------------------------------------------------------

Copyright (c) <2015>, <Wi6labs>, <Telecom Bretagne>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Telecom Bretagne, wi6labs nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL TELECOM BRETAGNE OR WI6LABS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Description:
LoRaFabian Beacon Answer code. LoRa RX setq sx1272 in receive mode on the
channel configured in sx1272_contiki_radio.c

-----------------------------------------------------------------------------*/                                                             

#include "contiki.h"
#include "leds-arch.h"
#include "stm32f10x.h"
#include <dev/leds.h>
#include <stdio.h>
#include "layer802154_radio_lora.h"
#include "arduino_spi.h"
#include "debug_on_arduino.h"
//#include "er-coap.h"
//#include "er-coap-constants.h"
#include "frame_manager.h"
#include "frame802154_lora.h"
#include "cfs/cfs.h"
#include <string.h>
#include "eap_responder.h"
#include "_cantcoap.h"
#include "uthash.h"

static struct etimer rx_timer;
static struct etimer timer_payload_beacon;
process_event_t event_data_ready;
process_event_t event_timeout;

//The response to the beacon
char coap_payload_beacon[150];

int is_associated = 0;
static int is_beacon_receive = 0;
uint32_t nonce_c, nonce_s;
unsigned long bt_begin_time, bt_end_time;

u8 received[170];

CoapPDU *coap_request;

void frame_manager_init()
{
  process_start(&lorafab_bcn_process, NULL);
}

/**
 * \brief: update the hostname with /HOSTNAME file
 */
void updateHOSTNAME()
{
  char dns[150];//The content of the file
  int fd;
  //Read in /HOSTNAME_LORA
  fd = cfs_open("/HOSTNAME_LORA", CFS_READ);
  if(fd >= 0) {
    //Read 500 char
    cfs_read(fd, dns, sizeof(dns));
    cfs_close(fd);
    //Get the real hostname
    int size = 0;
    //Because the space significate the end of the hostname
    while(dns[size] != '\0')
      ++size;
    //final = the real url
    char final[size];
    int i;
    for(i = 0; i != sizeof(final) +1; ++i)
      final[i] = dns[i];

    strcpy(coap_payload_beacon, "{\"n\":\"");
    strcat(coap_payload_beacon, final);
    strcat(coap_payload_beacon, "\"}");
  }
  else {
    printf("ERREUR LORS DE LA LECTURE\n\r");
    strcpy(coap_payload_beacon, "{\"n\":\"default.test\"}");
    return;
  }
  printf("HOSTNAME : %s\n\r", coap_payload_beacon);
}

/**
 * \brief: Send the coap_payload_beacon to layer802154
 */
void
coap_beacon_send_response() {
  //updateHOSTNAME();
  strcpy(coap_payload_beacon, "alpha.t.eu.org");
  //strcpy(coap_payload_beacon, "usera2");
  printf("HOSTNAME : %s\n\r", coap_payload_beacon);
  uint8_t tx_buffer[512];

  size_t coap_packet_size;

  unsigned short random_a = random_rand();
  char MAC[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  getMac(MAC);


  unsigned short random_b = random_a ^ MAC[sizeof(MAC)-1]; //
  reset(coap_request);
  setVersion(coap_request,1);
  setType(coap_request,COAP_CONFIRMABLE);
  setCode(coap_request,COAP_POST);
  int token=1;
  setToken(coap_request,(uint8_t*)&token,4);
  setMessageID(coap_request,htons(0x0000));



  //int noresponseValue = 0x7f;
  //_setURI(coap_request,"/b",2);
  _setURI(coap_request,"/boot",5);

  //nonce_s = rand();
  //printf("nonce_s added = %02x\n\r",nonce_s);
  //addOption(coap_request,COAP_OPTION_NONCE,4,&nonce_s);
  //addOption(coap_request,COAP_OPTION_NO_RESPONSE,1,&noresponseValue);


  //CoAP message Response we set the payload
  //setPayload(coap_request, (uint8_t *)coap_payload_beacon, strlen(coap_payload_beacon));

  coap_packet_size = getPDULength(coap_request); 
  int tx_buffer_index = coap_packet_size;
  printf("We are sending the response to the coap beacon\n\r");

  //Note: We don't parse the beacon message yet, so the GATEWAY_ADDR
  //is defined in frame802154_lora.c
  layer802154_send(getPDUPointer(coap_request), tx_buffer_index, GATEWAY_ADDR, SIGNALISATION_ON, DST_SHORT_FLAG);
  printf("\n\r+++ clock after sending the beacon response %u\n", clock_time());

  //Note: We don't parse the beacon message yet, so we assume that
  //the node is registered after the first response
  //TODO: implement State Machine
  is_associated = 1;
  is_beacon_receive = 0;   // start responding to beacon, upon timeout
  
  process_post_synch(&eap_responder_process, event_timeout,NULL);

}

/**
 * \brief: Check if the payload is a beacon payload
 * \param: rx_msg, the payload
 * \param: size, the payload length
 */
int respond_if_coap_beacon(u8 rx_msg[], int size) {
  printf("\n\r\tPayload: ");
  int iaux;
  for(iaux = 0 ; iaux<size ; iaux++)
    printf("%02x", rx_msg[iaux]);

  _CoapPDU_buf_withCPDU(coap_request, (uint8_t*)rx_msg, size);	

  printf("\n\r\tPayload is CoAP Beacon?: ");
  if(validate(coap_request))  {
   int check_coap_beacon = (getType(coap_request) == COAP_NON_CONFIRMABLE) && 
    					((getCode(coap_request) == COAP_POST) && 
    						(getPayloadLength(coap_request) == 0)); 
    if(check_coap_beacon){
      printf("\n\r\tThis is the LoRA CoAP Beacon\n\r");
      return 1;
    } else if((getCode(coap_request) == COAP_POST)
                            && (getPayloadLength(coap_request) != 0)
                                && (authenticated != TRUE) && (memcmp(rx_msg, received, size) !=0)) {
                               // && (authenticated != TRUE)) {
	// the duplicate packets from different antennas receive within short interval of time
	// the retransmitted packets would arrive a bit later than these duplicate packets
	// but in case of the antennas that are far apart, the packets would receive at a bigger time interval and
	//  might seem like a retransmitted packet
        printf("EAP CoAP Message of len=%d.\n\r",getPayloadLength(coap_request));
        // post an event to EAP responder and pass the coap pckt
        process_post_synch(&eap_responder_process, event_data_ready,coap_request);
    } else {
        printf("Other CoAP Message\n\r");
    }
  } else
      printf("Not LoRa Beacon. CoAP parse ERROR\n\r");
  printf("\n\r");
  memcpy(received, rx_msg, size);
  return 0;
}

/*---------------------------------------------------------------------------*/
PROCESS(lorafab_bcn_process, "LoRaFabian Beacon process");
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(lorafab_bcn_process, ev, data) {
  PROCESS_BEGIN();

  int pending = 0;
  int i;
  int size;

  leds_init();
  leds_toggle(LEDS_ALL);
  arduino_spi_init();
  layer802154_init();
  //Start infinite RX
  layer802154_on();

  etimer_set(&rx_timer, 5*CLOCK_SECOND);
  event_data_ready = process_alloc_event();
  event_timeout = process_alloc_event();
  coap_request = _CoapPDU();
  printf("\n\r Value of a CLOCK SECOND = %d\n\r", CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT();
    printf("\n\rbeacon receive = %d is_associated = %d \n\r",is_beacon_receive, is_associated);
    if(is_beacon_receive && !is_associated && etimer_expired(&timer_payload_beacon))
    {
      etimer_stop(&timer_payload_beacon);
      coap_beacon_send_response();
    }

    if(etimer_expired(&rx_timer)) {
      leds_toggle(LEDS_ALL);

      pending = layer802154_pending_packet();
      printf("pending_packet: %d\n\r", pending);

      if(pending) {
        frame802154_lora_t frame = layer802154_read();
        size = frame.payload_len;

        if(frame.header_len == -1)
          printf("Error: buffer is too small for headers");
        else {
          //For the arduino
          int packetSize = size + frame.header_len;
          //Verify the destination of a message
          bool br_msg = is_broadcast_addr(&frame);
          bool my_mac = is_my_mac(&frame);
          if(br_msg) {
            printf("Broadcast message");
	    printf("\n\rclock at beginning of bootstrapping %u\n", clock_time());
	    bt_begin_time = clock_time();
            if(!is_signaling(&frame) || debug_on_arduino)
              set_arduino_read_buf(frame.packet, packetSize);
          }
          else if(my_mac) {
            printf("Message is for me");
	    printf("\n\rclock at beginning of eap %u\n", clock_time());
            set_arduino_read_buf(frame.payload, frame.payload_len);
           }
          else {
            printf("Message is not for me");
            if(debug_on_arduino)
              set_arduino_read_buf(frame.packet, packetSize);
          }

          //To avoid collision
          if(respond_if_coap_beacon(frame.payload, size) && !is_associated)
          {
            is_beacon_receive = 1;
            //int random_timer = (random_rand()%30);
            int random_timer = 1;
            etimer_set(&timer_payload_beacon, random_timer*CLOCK_SECOND);
          }
        }
      }
      etimer_reset(&rx_timer);
    }
  }
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
