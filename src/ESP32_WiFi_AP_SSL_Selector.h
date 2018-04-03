/*
  ESP32_WiFi_AP_SSL_Selector.h
  Beta version 1.0

This library is used by the Arduino core for the ESP32 ( use SPIFFS ).

The MIT License (MIT)

Copyright (c) 2018 Mgo-tec

My Blog Site --> https://www.mgo-tec.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

WiFi.h - Included WiFi library for esp32
Based on WiFi.h from Arduino WiFi shield library.
Copyright (c) 2011-2014 Arduino.  All right reserved.
Modified by Ivan Grokhotkov, December 2014
Licensed under the LGPL-2.1

FS.h - file system wrapper
Copyright (c) 2015 Ivan Grokhotkov. All rights reserved.
Licensed under the LGPL-2.1

Reference LGPL-2.1 license statement --> https://opensource.org/licenses/LGPL-2.1   

SPIFFS.h - Included SPIFFS library for esp32
Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
Licensed under the Apache License, Version 2.0 (the "License");

ssl.h - Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
Licensed under the Apache License, Version 2.0

Reference Apache License --> http://www.apache.org/licenses/LICENSE-2.0

sockets.h - Copyright (c) 2001-2004 Swedish Institute of Computer Science. All rights reserved.
This file is part of the lwIP TCP/IP stack.
Author: Adam Dunkels <adam@sics.se>

openssl_server_example_main.c ( ESP-IDF ) - Modification.
Licensed under The Public Domain
*/

#ifndef _WIFI_AP_SSL_SELECTOR_H_INCLUDED
#define _WIFI_AP_SSL_SELECTOR_H_INCLUDED

#include "FS.h"
#include "SPIFFS.h"
#include <WiFi.h>
#include "openssl/ssl.h"
#include "lwip/sockets.h"

extern WiFiClient __client1;
extern WiFiServer __server1;

class ESP32_WiFi_AP_SSL_Selector
{
private:
  uint16_t _https_port;
  uint16_t _ssl_recv_buf_len;
  IPAddress _local_ip;
  IPAddress _gateway;
  IPAddress _subnet;
  IPAddress _primaryDNS; //optional
  IPAddress _secondaryDNS; //optional

  boolean _STA_StaticIP_OK = false;

  SSL_CTX *_ctx;
  SSL *_ssl;

  int _sockfd, _new_sockfd;
  socklen_t _addr_len;
  struct sockaddr_in _sock_addr;

  uint8_t _ssid_num;
  String _ssid_rssi_str[30];
  String _ssid_str[30];
  String _Selected_SSID_str = " ";
  String _Sel_PASS_str = " ";

  uint32_t _scanLastTime = 0;
  boolean _First_Scan_Set = true;

  boolean _ssl_redirect = false;
  boolean _wifi_rescan = false;

public:
  ESP32_WiFi_AP_SSL_Selector();

  void Init(uint16_t HTTPS_port, uint16_t ssl_recv_buf_len, char spiffs_ssid_c[], char spiffs_pass_c[]);
  void Init_StaticIP(uint16_t HTTPS_port, uint16_t ssl_recv_buf_len, IPAddress Local_IP, IPAddress Gateway, IPAddress Subnet, IPAddress PriDNS, IPAddress SecDNS, char spiffs_ssid_c[], char spiffs_pass_c[]);
  void softAP_http_server();
  void openssl_init(const char* cert_path, const char* prvt_key_path);
  int8_t SSL_softAP_WiFi_Selector(const char* APconfigFile_path, char* ssid1, char* pass1);

  int8_t WiFi_STA_Connect(char* ssid1, char* pass1, uint32_t timeout);
  String HTML_Res_Head();
  String HTML_Http_Body(String meta_str, String message_str);
  String HTML_Submit_Button(String name1, String font_color, String back_color, String message, String button_name);
  void html_send(String now_ssid_str, String message2, String msg2_color);
  void favicon_response();
  void wifi_scan(uint32_t scan_interval);
  uint16_t SPIFFS_read_PKI_File(const char * path, char pki_cstr[]);
  void SPIFFS_writeFile(const char * path, String c_ssid_pass);
  void deleteFile(const char * path);
  void SPIFFS_readFile(const char * path, char ssid_c[], char pass_c[]);

};

#endif
