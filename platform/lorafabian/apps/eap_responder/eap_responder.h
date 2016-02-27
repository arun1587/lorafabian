#ifndef EAP_RESPONDER_H_
#define EAP_RESPONDER_H_ 

void eap_responder_init();
void eap_responder_sm_init();
void eap_responder_timer_init();

extern struct process eap_responder_process;
extern process_event_t event_data_ready;
extern process_event_t event_timeout;
extern uint8_t authenticated;

#endif 

