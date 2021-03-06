#include <stdbool.h>
#include <string.h>
#include "coap.h"

#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

const uint16_t rsplen=100;
static char rsp[100] = "";
void build_rsp(void);

#ifdef ARDUINO
static int led = 7;
void endpoint_setup(void)
{                
    pinMode(led, OUTPUT);     
    build_rsp();
}
#else
#include <stdio.h>
void endpoint_setup(void)
{
    build_rsp();
}
#endif

static const coap_endpoint_path_t path_well_known_core = {2, {".well-known", "core"}};
static int handle_get_well_known_core(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint8_t id_hi, uint8_t id_lo)
{
    return coap_make_response(scratch, outpkt, (const uint8_t *)rsp, strlen(rsp), id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_CONTENT, COAP_CONTENTTYPE_APPLICATION_LINKFORMAT);
}

static const coap_endpoint_path_t path_get_light = {1, {"light"}};

static int handle_get_light(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint8_t id_hi, uint8_t id_lo)
{
  Serial.print("Get Light :");
  int value = analogRead(0);
  Serial.println(value);
  
  char lightMsg[250] = "<html xmlns=\"http://www.w3.org/1999/xhtml\"><link rel=\"stylesheet\" type=\"text/css\" href=\"http://enconn.fr/demo/lora.css\"/>";
  
  if(value > 150)
    strcat(lightMsg, "<div id=\"day\"><h1>Light : ");
  else
    strcat(lightMsg, "<div id=\"night\"><h1>Light : ");
  
  strcat(lightMsg, String(value).c_str());
  strcat(lightMsg, "</h1>");
  if(value > 150)
    strcat(lightMsg, "<div id=\"on\"></div>");
  else
    strcat(lightMsg, "<div id=\"off\"></div>");
  strcat(lightMsg, "</div></html>");  
  
  return coap_make_response(scratch, outpkt, (const uint8_t *)lightMsg, strlen(lightMsg), id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_CONTENT, COAP_CONTENTTYPE_APPLICATION_XML);
  
}

const coap_endpoint_t endpoints[] =
{
    {COAP_METHOD_GET, handle_get_well_known_core, &path_well_known_core, "ct=40"},
    {COAP_METHOD_GET, handle_get_light, &path_get_light, "ct=0"},
    {(coap_method_t)0, NULL, NULL, NULL}
};

void build_rsp(void)
{
    uint16_t len = rsplen;
    const coap_endpoint_t *ep = endpoints;
    int i;

    len--; // Null-terminated string

    while(NULL != ep->handler)
    {
        if (NULL == ep->core_attr) {
            ep++;
            continue;
        }

        if (0 < strlen(rsp)) {
            strncat(rsp, ",", len);
            len--;
        }

        strncat(rsp, "<", len);
        len--;

        for (i = 0; i < ep->path->count; i++) {
            strncat(rsp, "/", len);
            len--;

            strncat(rsp, ep->path->elems[i], len);
            len -= strlen(ep->path->elems[i]);
        }

        strncat(rsp, ">;", len);
        len -= 2;

        strncat(rsp, ep->core_attr, len);
        len -= strlen(ep->core_attr);

        ep++;
    }
}

