#include "contiki.h"
#include <stdint.h> 
#include "er-coap.h"
#include "er-coap-constants.h"
#include "eap-peer.c"
#include "eap-psk.c"
#include "eax.c"
#include "eap_responder.h"
#include "test.h"
#include "layer802154_radio_lora.h"
//#include "_cantcoap.h"



static uint8_t authenticated = FALSE; 
void eap_responder_init()
{
  process_start(&eap_responder_process, NULL); 
  eapRestart = TRUE;
  eap_peer_sm_step(NULL);

}

static void eventhandler(process_event_t ev, process_data_t data) {

  int i;
  coap_packet_t *p;
  static coap_packet_t coap_response[1];
  uint8_t tx_buffer[512];
  size_t coap_packet_size;
  int tx_buffer_index;

  p = (coap_packet_t *)data;
  printf("Size of the PAYLoad = %d\n\r",p->payload_len);
    
  coap_init_message(coap_response, COAP_TYPE_ACK, 0, p->mid);
  coap_set_status_code (coap_response, CHANGED_2_04);
  if (!eapKeyAvailable) {
       printf ("EAP EXCHANGE IN COURSE \n\r");
       eapReq = TRUE;
       eap_peer_sm_step (p->payload);
       coap_set_payload(coap_response, eapRespData, NTOHS(((struct eap_msg *) eapRespData)->length));
       coap_packet_size = coap_serialize_message(coap_response, (void *)(tx_buffer ));
       tx_buffer_index = coap_packet_size; 
  } else {
       printf ("EAP EXCHANGE FINISHED\n\r");
       // verify if its EAP method = 03, as in EAP Success!	
       if (*(p->payload) == 0x03) {
       	authenticated = TRUE;
       }
  } 
  // send the coap msgs with the SIGNALIZATIO BIT set.
  printf("WE SENDING RESPONSE TO COAP PUT\n\r");
  layer802154_send(tx_buffer, tx_buffer_index, GATEWAY_ADDR, SIGNALISATION_ON, DST_SHORT_FLAG);
}

PROCESS(eap_responder_process, "EAP responder process");
PROCESS_THREAD(eap_responder_process, ev, data)
{
  PROCESS_BEGIN();
  while (1)
    {
      PROCESS_WAIT_EVENT_UNTIL (ev == event_data_ready);
      printf("\n\rEAP PROCESS EVENT SIGNALLED\n\r");
      eventhandler(ev, data);
      if(authenticated) {
      		printf("\n\rEAP PROCESS EXITED\n\r");
		PROCESS_EXIT();
      }
    }
  PROCESS_END();
}
