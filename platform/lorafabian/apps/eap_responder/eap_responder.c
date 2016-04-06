#include "contiki.h"
#include <stdint.h> 
//#include "er-coap.h"
//#include "er-coap-constants.h"
#include "eap-peer.c"
#include "eap-psk.c"
#include "eax.c"
#include "eap_responder.h"
#include "layer802154_radio_lora.h"
#include "frame_manager.h"
#include "_cantcoap.h"



uint8_t authenticated = FALSE;
static struct etimer et;
uint8_t state;

CoapPDU *coap_response, *p;

void eap_responder_init()
{
  process_start(&eap_responder_process, NULL); 
}

void eap_responder_sm_init() {

  printf("\n\r eap_responder init statemachine\n\r");
  eapRestart = TRUE;
  eap_peer_sm_step(NULL);
}

void eap_responder_timer_init() {
  printf("\n\r eap_responder timer reset\n\r");
  etimer_set(&et, 45*CLOCK_SECOND);
}

static void eventhandler(process_event_t ev, process_data_t data) {

  int i;
  uint8_t tx_buffer[512];
  size_t coap_packet_size;
  int tx_buffer_index;
   
  // TODO implement the check for retransmission 
   
  p = (CoapPDU *)data;
    
  reset(coap_response);
  setVersion(coap_response,1);
  setType(coap_response,COAP_ACKNOWLEDGEMENT);
  setCode(coap_response,COAP_CHANGED);
  int token=1;
  setToken(coap_response,(uint8_t*)&token,0);
  setMessageID(coap_response, getMessageID(p));

  if (!eapKeyAvailable) {
       eapReq = TRUE;
       eap_peer_sm_step (getPayloadPointer(p));
       setPayload(coap_response, eapRespData, NTOHS(((struct eap_msg *) eapRespData)->length));

       coap_packet_size = getPDULength(coap_response);
       tx_buffer_index = coap_packet_size; 
  } else {
       printf ("EAP EXCHANGE FINISHED\n\r");
       // verify if its EAP method = 03, as in EAP Success!	
       if (*(getPayloadPointer(p)) == 0x03) {
       	authenticated = TRUE;
       }
  } 
  // send the coap msgs with the SIGNALIZATIO BIT set.
  printf("WE ARE SENDING RESPONSE TO COAP PUT\n\r");
  layer802154_send(getPDUPointer(coap_response), tx_buffer_index, GATEWAY_ADDR, SIGNALISATION_ON, DST_SHORT_FLAG);
  eap_responder_timer_init();
  
  
  // TODO copy the last sent packet in case of retransmission
}

/*
static void timeout_handler() {
  // if the node is not authenticated within this timeout interval;
  // start responding to beacons again after the timeout
  if(!state) {
	authenticated = FALSE;
	is_associated = 0;
	printf("\n\rEAP PROCESS TIMED OUT!\n\r");
  // TODO eap_responder_sm_init(), try removing the state
  }
  etimer_set(&et, 45*CLOCK_SECOND);
  state = 0;
}
*/

static void timeout_handler() {
  // if the node is not authenticated within this timeout interval;
  // start responding to beacons again after the timeout
  authenticated = FALSE;
  is_associated = 0;
  eap_responder_sm_init();
  printf("\n\rEAP PROCESS TIMED OUT, timer reset!\n\r");
  etimer_set(&et, 45*CLOCK_SECOND);
}

PROCESS(eap_responder_process, "EAP responder process");
PROCESS_THREAD(eap_responder_process, ev, data)
{
  PROCESS_BEGIN();
  etimer_set(&et, 1*CLOCK_SECOND);
  state = 1;
  coap_response = _CoapPDU();
  while (1)
    {
      PROCESS_YIELD();

      if(etimer_expired(&et)) {
	timeout_handler();
      } else if(ev == event_data_ready) {
        eventhandler(ev, data);
      } else if(ev == event_timeout) {
	eap_responder_timer_init();
      }
      if(authenticated) {
	printf("\n\rEAP PROCESS EXITED\n\r");
	PROCESS_EXIT();
      }
    }
  PROCESS_END();
}
