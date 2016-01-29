/* 
 *  Copyright (C) Pedro Moreno Sánchez on 25/04/12.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  
 *  https://sourceforge.net/projects/openpana/
 */

#ifndef __EAP_PSK
#define __EAP_PSK

#include "eap-peer.h"
//#include "ahi_aes.h"
#include "aes.h"
#include "eax.h"

#define ID_P_LENGTH 6

//uint8_t psk_key_available;

uint8_t check(const uint8_t * eapReqData);
void process(const uint8_t * eapReqData, uint8_t * methodState, uint8_t * decision);
void buildResp( uint8_t * eapRespData, uint8_t reqId);
//uint8_t * getKey();
//uint8_t isKeyAvailable();
void initMethodEap();

//unsigned char msk_key [64]; //It is the msk_key
static unsigned char tek_key [16];
//static unsigned char emsk_key [64];

static unsigned char ak [16];
static unsigned char kdk [16];
//static unsigned char psk [16];
static uint8_t step;
static unsigned char rand_s[16];
static unsigned char rand_p[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static unsigned char id_s[16];
static unsigned short id_s_length;
//static unsigned char id_p[ID_P_LENGTH]= {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static unsigned char ct[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//Nonce defined in the RFC EAP-PSK for the protected-channel computing
static unsigned char nonce [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static unsigned char data_ciphered [16];
static unsigned char tag_bug[16];
static unsigned char header [22];
static unsigned char msg[1] = {0x80};


#endif
