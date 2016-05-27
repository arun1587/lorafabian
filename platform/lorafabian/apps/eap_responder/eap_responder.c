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

# define SEQ_LEN 26  /*LABEL:14 + NONCE_S:4 + NONCE_C:4 + TOKEN_COAP:4*/
# define KEY_LEN 16
# define AUTH_LEN 16


uint8_t authenticated = FALSE;
static struct etimer et;

uint8_t lstate;
unsigned char auth_key[KEY_LEN] = {0};
unsigned char sequence[SEQ_LEN] = {0};
unsigned long tot_time;
/*
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
*/

char URI[8] = {'/','b','o','o','t', 0, 0, 0};
uint8_t authKeyAvailable = 0;

CoapPDU *coap_response, *p;

void printf_hex(unsigned char *hex, unsigned int l){
    int i;
    if (hex != NULL){
        for (i=0; i < l; i++)
            printf("%02x",hex[i]);

        printf("\n\r");
    }
}

void eap_responder_init()
{
  process_start(&eap_responder_process, NULL); 
}

void eap_responder_sm_init() {

  printf("\n\r eap_responder init statemachine\n\r");
  memset(&msk_key, 0, MSK_LENGTH);
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
  uint8_t mac2check[16]	={0};
  uint8_t mac[16]	={0};
  uint8_t responsecode = COAP_CHANGED;
  p = (CoapPDU *)data;
  

  if(!lstate) {
    //state = 1;
    nonce_s = rand();
    //printf("NONCE_S generated = %02x\n\r", nonce_s);
    responsecode = COAP_CREATED;
    
    // We create the sequence
    memcpy(&nonce_c, getPayloadPointer(p),(size_t)getPayloadLength(p));
    //printf("NONCE_C received = %02x\n\r", nonce_c);
    ptr = (unsigned char*)&sequence;
    
    unsigned char label[] = "IETF COAP AUTH";
    memcpy(ptr,label,(size_t)14);
    ptr += 14;
    
    memcpy(ptr,getTokenPointer(p),(size_t)getTokenLength(p));
    ptr += 4;
    
    memcpy(ptr, &(nonce_c),sizeof(uint32_t));
    ptr += 4;
    
    memcpy(ptr, &(nonce_s),sizeof(uint32_t));
    
    
    // EAP Restart
    memset(&msk_key,0, MSK_LENGTH);
    eapRestart=TRUE;
    eap_peer_sm_step(NULL);
    authKeyAvailable = 0; 
    // creating the id of the service
    URI[5] = '/';
    URI[6] = '0' + (rand() % 9);
 }

 else{
    if(eapKeyAvailable){
        
  	//printf("SEQUENCE = ");      
  	//printf_hex(sequence, SEQ_LEN);      
        do_omac(msk_key, sequence, SEQ_LEN, auth_key);
        authKeyAvailable = TRUE;
  	//printf("MSK AVAILABLE = ");      
  	//printf_hex(msk_key, 16);      
  	//printf("AUTH KEY = ");      
  	//printf_hex(auth_key, 16);      
        // Verify the AUTH Option
        
        // Copy the mac
        memcpy(&mac2check,getPDUPointer(p)+getPDULength(p)-16-5,16);
  	//printf("MAC2CHECK =");      
  	//printf_hex(mac2check, 16);      
        // Zeroing the mac in meesage
        memcpy(getPDUPointer(p)+getPDULength(p)-16-5,&mac,16);
        // Setting the MAC
        do_omac(auth_key, getPDUPointer(p),getPDULength(p), mac);
	//printf("MAC =");
  	//printf_hex(mac, 16);      
        
        if(memcmp(&mac2check, &mac,16) != 0)
        {
            printf("error\n\r");
        }
        
        memset(mac2check,0,16);
        
        
    }
    
  eapReq = TRUE;
  eap_peer_sm_step (getPayloadPointer(p));
 } 
  // Building Response
  reset(coap_response);
  setVersion(coap_response,1);
  setType(coap_response,COAP_ACKNOWLEDGEMENT);
  setCode(coap_response,responsecode);
  int token=1;
  setToken(coap_response, getTokenPointer(p), (uint8_t)getTokenLength(p));
  setMessageID(coap_response, getMessageID(p));
  if (!lstate) {
  	lstate++;
	_setURI(coap_response,&URI[0],7);
        setPayload(coap_response, (uint8_t *)&nonce_s, getPayloadLength(p));
  }

  if (!authKeyAvailable) {
	if(eapResp) {
  		setPayload(coap_response, eapRespData, NTOHS(((struct eap_msg *)eapRespData)->length));
    	}
  } else {
    	printf("adding the Authkey!!\n\r");
    	addOption(coap_response, COAP_OPTION_AUTH, AUTH_LEN, (uint8_t*)&mac2check);
    	do_omac(auth_key, getPDUPointer(coap_response),
    	getPDULength(coap_response), mac2check);
    	memcpy(getPDUPointer(coap_response)+getPDULength(coap_response)-16, &mac2check, 16);
  }

  coap_packet_size = getPDULength(coap_response);
  tx_buffer_index = coap_packet_size; 

  // send the coap msgs with the SIGNALIZATION BIT set.
  printf("WE ARE SENDING RESPONSE TO COAP POST\n\r");
  //printf("\n\rtick after building eap_response %u\n\r", clock_time());
  layer802154_send(getPDUPointer(coap_response), tx_buffer_index, GATEWAY_ADDR, SIGNALISATION_ON, DST_SHORT_FLAG);
  if (authKeyAvailable) {
	bt_end_time = clock_time();
	tot_time = bt_end_time - bt_begin_time;
  	printf("\n\rclock at the end of bootstrapping %u\n\r", clock_time());
  	printf("\n\rclock total bootstrapping time %u - %u = %u\n\r",bt_end_time, bt_begin_time, tot_time);
  }
  eap_responder_timer_init();

}

static void timeout_handler() {
  // if the node is not authenticated within this timeout interval;
  // start responding to beacons again after the timeout
  authenticated = FALSE;
  is_associated = 0;
  
  lstate = 0;
  memset(&msk_key,0, MSK_LENGTH);
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
        printf("clock at end of bootstrapping %u\n", clock_time());
	//PROCESS_EXIT();
	etimer_stop(&et);
      }
    }
  PROCESS_END();
}
