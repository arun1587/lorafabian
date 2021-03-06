/*--------------------------------------------------------------------------

              j]_                   .___                                   
._________    ]0Mm                .=]MM]=                                  
M]MM]MM]M]1  jMM]P               d]-' NM]i                                 
-~-~   4MM1  d]M]1              d]'   jM]'                                 
       j]MT .]M]01       d],  .M]'    d]#                                  
       d]M1 jM4M]1  .,  d]MM  d]I    .]M'                                  
       ]0]  M/j]0(  d]L NM]f d]P     jM-                                   
       M]M .]I]0M  _]MMi -' .]M'                                           
       M]0 jM MM]  jM-M>   .]M/                                            
       ]0F MT ]M]  M>      d]M1        .,                                  
      j0MT.]' M]M j]1 .mm .]MM ._d]_,   J,                                 
      jM]1jM  ]01 =] .]M/ jM]Fd]M]MM]   .'                                 
      j]M1#T .M]1.]1 jM]' M]0M/^ "M]MT  j         .",    .__,  _,-_        
      jMM\]' J]01jM  M]M .]0]P    ]0]1  i         1 1   .'  j .'  "1       
      j]MJ]  jM]1]P .]M1 jMMP     MM]1  I        J  t   1   j J    '       
      =M]dT  jM]q0' dM]  M]MT     ]MM  j        j   j  j    J 1            
      ]M]M`  j]0j#  ]MF  ]M]'    .M]P  J       .'   j  J  .J  4_,          
      M]0M   =MM]1 .M]'  MM]     jM](  1       r    j  1  --,   "!         
      ]0MT   ]M]M  jM@   ]M]     M]P  j       J     j j     4     1        
      MM]'   M]0P  j]1  .M]M    j]M'  J      j'     ",?     j     1        
     _]M]    M]0`  jM1 .MNMM,  .]M'   1     .'       11     1    j'        
     jM]1   jM]@   j]L_]'?M]M__MP'    \     J        1G    J    .'         
     j]0(   jM]1   "M]P'  "N]M/-      "L__J L________'?L__- *__,'          
     "-'    "--                                                            
                                                                           
----------------------------------------------------------------------------

Copyright (c) <2014>, <Wi6labs>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the wi6labs nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL WI6LABS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Description: Arduino SPI interface
-----------------------------------------------------------------------------*/                                                             
#ifndef __ARDUINO_SPI_H__
#define __ARDUINO_SPI_H__

void arduino_spi_init( void );

#define ARDUINO_CMD_BUF_MAX_LEN 256


extern u8 arduino_cmd_buf[ARDUINO_CMD_BUF_MAX_LEN];
extern u16 arduino_cmd_len;
extern u8 shield_status ;
extern u16 lora_data_available;
extern u8 * arduino_read_buf;
extern u16 arduino_read_buf_len;

// Arduino commands
#define ARDUINO_CMD_AVAILABLE  0x00
#define ARDUINO_CMD_READ       0x01
#define ARDUINO_CMD_WRITE      0x02

#define ARDUINO_CMD_DEBUG      0x20
#define ARDUINO_CMD_HOSTNAME   0x21
#define ARDUINO_CMD_GET_MAC    0x22

#define ARDUINO_CMD_FREQ       0x30
#define ARDUINO_CMD_GET_FREQ   0x31
#define ARDUINO_CMD_RF_CFG     0x32
#define ARDUINO_CMD_BW_CFG     0x33
#define ARDUINO_CMD_GET_BW_CFG 0x34
#define ARDUINO_CMD_SF_CFG     0x35
#define ARDUINO_CMD_GET_SF_CFG 0x36
#define ARDUINO_CMD_CR_CFG     0x37
#define ARDUINO_CMD_GET_CR_CFG 0x38
#define ARDUINO_CMD_LAST_SNR   0x39
#define ARDUINO_CMD_LAST_RSSI  0x3A

#define ARDUINO_CMD_TEST       0xFF 

// Command status
#define ARDUINO_CMD_STATUS_OK                 0x80
#define ARDUINO_CMD_STATUS_NO_DATA_AVAILABLE  0x01
#define ARDUINO_CMD_STATUS_UNKNOWN            0x02 
#define ARDUINO_CMD_STATUS_LENGTH_MISMATCH    0x03

#define ARDUINO_CMD_STATUS_NO_STATUS          0xAA 

void set_arduino_read_buf(u8 * buf, u16 len);
void set_last_cmd_status(u8 status);


extern struct process arduino_cmd_process;

#endif // __ARDUINO_SPI_H__

