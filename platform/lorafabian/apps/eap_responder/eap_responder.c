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

uint8_t lstate;
unsigned char auth_key[KEY_LEN] = {0};
unsigned char sequence[SEQ_LEN] = {0};

char URI[8] = {
    '/',
    'b',
    0,
    0,
    0,
    0,
    0,
    0
};

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
  uint8_t responsecode = COAP_CHANGED;
  p = (CoapPDU *)data;
    
  if (!lstate) {
	responsecode = COAP_CREATED;
	// EAP Restart
	//memset( & msk_key, 0, MSK_LENGTH);
	//eapRestart = TRUE;
	//eap_peer_sm_step(NULL);
	// creating the id of the service
	URI[2] = '/';
	unsigned int random = rand() * 1000;
	URI[3] = '0' + (random % 10);
  }
  if (eapKeyAvailable) {
       printf ("EAP EXCHANGE FINISHED\n\r");
       // verify if its EAP method = 03, as in EAP Success!	
       if (*(getPayloadPointer(p)) == 0x03) {
       		authenticated = TRUE;
       		ptr = (unsigned char *)&sequence;

      	 	unsigned char label[] = "IETF COAP AUTH";
       		memcpy(ptr, label, (size_t)14);
       		ptr += 14;

       		memcpy(&nonce_c, getOptionPointer(p, COAP_OPTION_NONCE), (size_t)getOptionLength(p, COAP_OPTION_NONCE));
     		memcpy(ptr, &nonce_c, sizeof(uint32_t));
       		ptr += 4;

       		memcpy(ptr, &nonce_s, sizeof(uint32_t));

       		do_omac(msk_key, sequence, SEQ_LEN, _auth_key);
       		authKeyAvailable = TRUE;

       		// Verify the AUTH Option
       		// Copy the mac
       		memcpy(&mac2check, getPDUPointer(p)+getPDULength(p)-16-5, 16);
       		// Zeroing the mac in message
       		memcpy(getPDUPointer(p)+getPDULength(p)-16-5, &mac, 16);
       		// Setting the MAC
       		do_omac(_auth_key, getPDUPointer(p), getPDULength(p), mac);

       		if (memcmp(&mac2check, &mac, AUTH_LEN) != 0) {
       			printf("error\n\r");
       		}

       		memset(mac2check, 0, AUTH_LEN);
       }

  } 

  eapReq = TRUE;
  eap_peer_sm_step (getPayloadPointer(p));
  
  // Building Response
  reset(coap_response);
  setVersion(coap_response,1);
  setType(coap_response,COAP_ACKNOWLEDGEMENT);
  setCode(coap_response,COAP_CHANGED);
  int token=1;
  setToken(coap_response,(uint8_t*)&token,0);
  setMessageID(coap_response, getMessageID(p));
 

  if (!lstate) {
  	lstate++;
 	_setURI(coap_response, & URI[0], 4);
  }

  if (!authKeyAvailable) {
	if(eapResp) {
  		setPayload(coap_response, eapRespData, NTOHS(((struct eap_msg *)eapRespData)->length));
    	}
  } else {
    	printf("adding the Authkey!!\n\r");
    	addOption(coap_response, COAP_OPTION_AUTH, AUTH_LEN, (uint8_t*)&mac2check);
    	do_omac(_auth_key, getPDUPointer(coap_response),
    	getPDULength(coap_response), mac2check);
    	memcpy(getPDUPointer(coap_response)+getPDULength(coap_response)-16, &mac2check, 16);
  }

  coap_packet_size = getPDULength(coap_response);
  tx_buffer_index = coap_packet_size; 

  // send the coap msgs with the SIGNALIZATION BIT set.
  printf("WE ARE SENDING RESPONSE TO COAP POST\n\r");
  printf("\n\rtick after building eap_response %u\n\r", clock_time());
  layer802154_send(getPDUPointer(coap_response), tx_buffer_index, GATEWAY_ADDR, SIGNALISATION_ON, DST_SHORT_FLAG);
  printf("\n\rtick after send eap_responder %u\n\r", clock_time());
  eap_responder_timer_init();

}

static void timeout_handler() {
  // if the node is not authenticated within this timeout interval;
  // start responding to beacons again after the timeout
  authenticated = FALSE;
  is_associated = 0;
  
  lstate = 0;
  memset(&auth_key, 0, AUTH_LEN);
  memset(&sequence, 0, SEQ_LEN);
  authKeyAvailable = 0;
  eap_responder_sm_init();
  printf("\n\rEAP PROCESS TIMED OUT, timer reset!\n\r");
  etimer_set(&et, 45*CLOCK_SECOND);
}

PROCESS(eap_responder_process, "EAP responder process");
PROCESS_THREAD(eap_responder_process, ev, data)
{
  PROCESS_BEGIN();
  etimer_set(&et, 1*CLOCK_SECOND);
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
        printf("+++ clock at end of bootstrapping %u\n", clock_time());
	//PROCESS_EXIT();
	etimer_stop(&et);
      }
    }
  PROCESS_END();
}
