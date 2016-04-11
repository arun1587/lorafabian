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

# define SEQ_LEN 22
# define KEY_LEN 16
# define AUTH_LEN 16


uint8_t authenticated = FALSE;
static struct etimer et;
uint8_t state;
unsigned char auth_key[KEY_LEN] = {0};
unsigned char sequence[SEQ_LEN] = {0};

uint8_t authKeyAvailable;

CoapPDU *coap_response, *p;

void eap_responder_init()
{
  process_start(&eap_responder_process, NULL); 
}

void eap_responder_sm_init() {

  printf("\n\r eap_responder init statemachine\n\r");
  memset( & msk_key, 0, MSK_LENGTH);
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

  unsigned char *ptr;
  uint8_t mac2check[AUTH_LEN] = {0};
  memset(mac2check, 0, AUTH_LEN);
  uint8_t mac[AUTH_LEN] = {0};
  memset(mac, 0, 16);
  unsigned char _auth_key[KEY_LEN] = {0};
  memset(_auth_key, 0, KEY_LEN);
   
  // TODO implement the check for retransmission 
   
  p = (CoapPDU *)data;
    
  reset(coap_response);
  setVersion(coap_response,1);
  setType(coap_response,COAP_ACKNOWLEDGEMENT);
  setCode(coap_response,COAP_CHANGED);
  int token=1;
  setToken(coap_response,(uint8_t*)&token,0);
  setMessageID(coap_response, getMessageID(p));
  eapReq = TRUE;

  if (!eapKeyAvailable) {
       eap_peer_sm_step (getPayloadPointer(p));
       setPayload(coap_response, eapRespData, NTOHS(((struct eap_msg *) eapRespData)->length));

       coap_packet_size = getPDULength(coap_response);
       tx_buffer_index = coap_packet_size; 
  } else {
       printf ("EAP EXCHANGE FINISHED\n\r");
       ptr = (unsigned char * ) & sequence;

       unsigned char label[] = "IETF COAP AUTH";
       memcpy(ptr, label, (size_t)14);
       ptr += 14;

       memcpy(&nonce_c, getOptionPointer(p, COAP_OPTION_NONCE), (size_t) getOptionLength(p, COAP_OPTION_NONCE));
       memcpy(ptr, &nonce_c, sizeof(uint32_t));
       ptr += 4;

       memcpy(ptr, &nonce_s, sizeof(uint32_t));

       do_omac(msk_key, sequence, SEQ_LEN, _auth_key);
       authKeyAvailable = TRUE;

       // Verify the AUTH Option
       // Copy the mac
       memcpy( &mac2check, getPDUPointer(p) + getPDULength(p)-16-5, 16);
       // Zeroing the mac in meesage
       memcpy(getPDUPointer(p) + getPDULength(p)-16-5, &mac, 16);
       // Setting the MAC
       do_omac(_auth_key, getPDUPointer(p), getPDULength(p), mac);

       if (memcmp( &mac2check, &mac, AUTH_LEN) != 0) {
       	printf("error\n\r");
       }

       memset(mac2check, 0, AUTH_LEN);

       // verify if its EAP method = 03, as in EAP Success!	
       if (*(getPayloadPointer(p)) == 0x03) {
       	authenticated = TRUE;
       }
  } 

/*

        if ((getCode(request) == COAP_POST)) {

            if (!state) {
                state++;
                _setURI(response, & URI[0], 4);
            }
            if (!authKeyAvailable) {
                if (eapResp) {
                    uint16_t len = ntohs(((struct eap_msg * )eapRespData)-> length);
                    setPayload(response, eapRespData, len);
                }
            } else {
                addOption(response, COAP_OPTION_AUTH, AUTH_LEN, (uint8_t*)&mac2check);

                do_omac(_auth_key, getPDUPointer(response),
                    getPDULength(response), mac2check);
                memcpy(getPDUPointer(response) + getPDULength(response)-16, &mac2check, 16);
            }

            uip_udp_packet_send(client_conn, getPDUPointer(response), (size_t) getPDULength(response));

            memcpy(sent, getPDUPointer(response), (size_t) getPDULength(response));
            sent_len = getPDULength(response);

        }
*/
  
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
