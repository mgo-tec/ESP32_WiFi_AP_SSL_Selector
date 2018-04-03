/*
  ESP32_WiFi_AP_SSL_Selector.cpp
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

Modify SPIFFS_test of sample sketch ( Arduino core for the ESP32 ).
*/

#include "ESP32_WiFi_AP_SSL_Selector.h"

ESP32_WiFi_AP_SSL_Selector::ESP32_WiFi_AP_SSL_Selector(){}

//******************************************
void ESP32_WiFi_AP_SSL_Selector::Init(uint16_t HTTPS_port, uint16_t ssl_recv_buf_len, char spiffs_ssid_c[], char spiffs_pass_c[]){
  _STA_StaticIP_OK = false;
  _https_port = HTTPS_port;
  _ssl_recv_buf_len = ssl_recv_buf_len;
  _Selected_SSID_str = String(spiffs_ssid_c);
  _Sel_PASS_str = String(spiffs_pass_c);

  _primaryDNS = {8,8,8,8}; //optional
  _secondaryDNS = {8,8,4,4}; //optional

  __server1.begin();
  Serial.println(F("-----------HTTP server(80) begin-----------"));
  delay(100);
}
//******************************************
void ESP32_WiFi_AP_SSL_Selector::Init_StaticIP(uint16_t HTTPS_port, uint16_t ssl_recv_buf_len, IPAddress Local_IP, IPAddress Gateway, IPAddress Subnet, IPAddress PriDNS, IPAddress SecDNS, char spiffs_ssid_c[], char spiffs_pass_c[]){
  _STA_StaticIP_OK = true;
  _https_port = HTTPS_port;
  _ssl_recv_buf_len = ssl_recv_buf_len;
  _local_ip = Local_IP;
  _gateway = Gateway;
  _subnet = Subnet;
  _primaryDNS = PriDNS;
  _secondaryDNS = SecDNS;
  _Selected_SSID_str = String(spiffs_ssid_c);
  _Sel_PASS_str = String(spiffs_pass_c);

  __server1.begin();
  Serial.println(F("-----------HTTP server(80) begin-----------"));
  delay(100);
}
//******************************************
void ESP32_WiFi_AP_SSL_Selector::softAP_http_server(){
  if(_ssl_redirect == true) return;

  String html_meta = "<meta http-equiv='refresh' content='0; URL=\"https://192.168.4.1\"' />\r\n";
  String html_msg = "ESP32 softAP mode<br>SSL Server Connecting...";

  __client1 = __server1.available();

  if (__client1) {
    Serial.println(F("HTTP New Client."));
    String currentLine = "";
    uint32_t LastTime = millis();
    while (__client1.connected()) {
      if( (millis()-LastTime) > 30000 ){ //timeout setting
        Serial.println("-------------softAP__client1 timeout");
        break;
      }
      if (__client1.available()) {
        currentLine = __client1.readStringUntil('\n');
        if(currentLine.indexOf("\r") == 0) break;
        Serial.println(currentLine);
        if(currentLine.indexOf("GET / HTTP/1.1") >= 0){
          currentLine = __client1.readStringUntil('\n');
          if(currentLine.indexOf("Host: 192.168.4.1") >= 0){
            Serial.println(F("------------ HTTP request received ---------------"));    
            __client1.println( ESP32_WiFi_AP_SSL_Selector::HTML_Res_Head() );
            __client1.println( ESP32_WiFi_AP_SSL_Selector::HTML_Http_Body(html_meta, html_msg) );
            __client1.println();
            currentLine = "";
            _ssl_redirect = true;
            break;
          }else{
            break;
          }
        }else if(currentLine.indexOf("GET /favicon") >= 0){
          __client1.print("HTTP/1.1 404 Not Found\r\n");
          __client1.println("Connection:close\r\n\r\n");
          break;
        }
      }
    }
    char c = 0x00;
    while(__client1.available()){
      c = __client1.read();
      Serial.print(c);
    }
    delay(10);
    __client1.stop();
    delay(10);
  }
}
//******************************************
void ESP32_WiFi_AP_SSL_Selector::openssl_init(const char* cert_path, const char* prvt_key_path){
  int ret;
  uint16_t len = 0;
  char cert_or_prvt_temp[4096] = {};

  log_e("SSL server context create ......");
    Serial.println(F("SSL server context create ......"));

    _ctx = SSL_CTX_new(TLS_server_method());

    if (!_ctx) {
        log_e("failed1");
        goto failed1;
    }
    log_e("OK-1");

    log_e("SSL server context set own certification......");

    len = ESP32_WiFi_AP_SSL_Selector::SPIFFS_read_PKI_File(cert_path, cert_or_prvt_temp);
    Serial.printf("cert_length = %d\r\n", len);
    log_v("cert\r\n%s", (const char*)cert_or_prvt_temp);

    ret = SSL_CTX_use_certificate_ASN1(_ctx, len, (const unsigned char*)cert_or_prvt_temp);
    if (!ret) {
        log_e("failed");
        goto failed2;
    }
    log_e("OK-2");

    log_e("SSL server context set private key......");

    len = ESP32_WiFi_AP_SSL_Selector::SPIFFS_read_PKI_File(prvt_key_path, cert_or_prvt_temp);
    Serial.printf("prvt_length = %d\r\n", len);
    log_v("prvt key\r\n%s", (const char*)cert_or_prvt_temp);

    ret = SSL_CTX_use_PrivateKey_ASN1(0, _ctx, (const unsigned char*)cert_or_prvt_temp, len);
    if (!ret) {
        log_e("failed");
        goto failed2;
    }
    log_e("OK-3");

    log_e("SSL server create socket ......");

    _sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (_sockfd < 0) {
        log_e("failed");
        goto failed2;
    }
    log_e("OK-4");

    log_e("SSL server socket bind ......");

    memset(&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_addr.s_addr = 0;
    _sock_addr.sin_port = htons(_https_port);

    ret = bind(_sockfd, (struct sockaddr*)&_sock_addr, sizeof(_sock_addr));
    Serial.print(F("------------------- bind ret = ")); Serial.println(ret);
    if (ret > 0) {
        log_e("failed");
        goto failed3;
    }
    log_e("OK-5");

    log_e("SSL server socket listen ......");

    ret = listen(_sockfd, 32);
    if (ret) {
        log_e("failed");
        goto failed3;
    }
    log_e("OK-6");
    return;

failed3:
    log_e("----------------goto failed3:");
    close(_sockfd);
    lwip_close_r(_sockfd);
    _sockfd = -1;
failed2:
    log_e("----------------goto failed2:");
    SSL_CTX_free(_ctx);
    _ctx = NULL;
failed1:
    log_e("----------------goto failed1:");
    //vTaskDelete(NULL);
    return ;
}
//************************************************
int8_t ESP32_WiFi_AP_SSL_Selector::SSL_softAP_WiFi_Selector(const char* APconfigFile_path, char* ssid1, char* pass1){
    if(_ssl_redirect == false) return -1;

    int ret;
    char recv_buf[_ssl_recv_buf_len];
    String html_tag1, html_tag2;
    int16_t getTXT_pass ,getTXT_select, getTXT_disconnect;
    String req_str;
    String str_w;
    String NowTime;
    boolean softAP_server_end_OK = false;
    //※型宣言はgoto文の前に無ければならない。gotoをまたいで宣言不可なので注意

reconnect:
    Serial.println(F("----------------SSL reconnect in"));

    log_e("SSL server create ......");
    _ssl = SSL_new(_ctx);
    if (!_ssl) {
        log_e("failed");
        goto failed3;
    }
    log_e("OK-7");

    log_e("SSL server socket accept client ......");

    _new_sockfd = accept(_sockfd, (struct sockaddr *)&_sock_addr, &_addr_len);
    if (_new_sockfd < 0) {
        log_e("failed" );
        goto failed4;
    }
    log_e("OK-8");

    SSL_set_fd(_ssl, _new_sockfd);

    log_e("SSL server accept client ......");

    ret = SSL_accept(_ssl);
    if (!ret) {
        log_e("failed");
        goto failed5;
    }
    log_e("OK-9");
    log_e("SSL server read message ......");

    do {
        memset(recv_buf, 0, _ssl_recv_buf_len); //recv_buf を0x00で初期化
        ret = SSL_read(_ssl, recv_buf, _ssl_recv_buf_len - 1);
        if (ret <= 0) {
            break;
        }
        log_e("SSL read: %s", recv_buf);
        if (strstr(recv_buf, "GET / HTTP/1.1")) {
            Serial.println(F("------------GET request receive[GET / HTTP/1.1]"));
            log_e("SSL get matched message");
            log_e("SSL write message");

            if(WiFi.status() == WL_CONNECTED){
              ESP32_WiFi_AP_SSL_Selector::html_send(WiFi.SSID(), "ESP32 STA connect OK!", "#0F0");
              Serial.println(F("------------ESP32 STA connect OK!-------------"));
            }else{
              ESP32_WiFi_AP_SSL_Selector::html_send("---", "ESP32 STA Cannot Connect<br>", "#F00");
            }
 
            break;
        }else if (strstr(recv_buf, "GET /?")) {
          log_e("SSL get matched message");
          log_e("SSL write message");

          req_str = String(recv_buf);

          Serial.println(F("--------------- SUBMIT Receive from Clinet"));
          getTXT_pass = req_str.indexOf("&pass1=");
          getTXT_select = req_str.indexOf("GET /?ssid_select=");
          getTXT_disconnect = req_str.indexOf("GET /?disconnect=");

          if(req_str.indexOf("GET /?reconnect=")>=0){
            Serial.println(F("------------GET request receive[GET /?reconnect]"));
            ESP32_WiFi_AP_SSL_Selector::WiFi_STA_Connect(ssid1, pass1, 20000);

            if(WiFi.status() == WL_CONNECTED){
              ESP32_WiFi_AP_SSL_Selector::html_send(WiFi.SSID(), "ESP32 STA Reconnect OK!", "#0F0");
              Serial.println(F("------------ESP32 STA Reconnect OK!-------------"));
            }else{
              ESP32_WiFi_AP_SSL_Selector::html_send("---", "ESP32 STA Cannot connect<br>", "#F00");
              Serial.println(F("------------ESP32 STA Cannot connect"));
            }

            req_str = "";
            _ssl_redirect = true;
            break;
          }

          if(req_str.indexOf("GET /?re_scan=")>=0){
            Serial.println(F("------------GET request receive[GET /?re_scan]"));
            _First_Scan_Set = true;
            ESP32_WiFi_AP_SSL_Selector::wifi_scan(20000);
            ESP32_WiFi_AP_SSL_Selector::html_send("---", "Wi-Fi ReScan OK!", "#AAF");

            Serial.println(F("-----------------WiFi ReScan OK!"));
            _wifi_rescan = false;
            _ssl_redirect = true;

            break;
          }

          if(req_str.indexOf("GET /?exit=")>=0){
            Serial.println(F("------------GET request receive[GET /?exit]"));
            String html_res_head = ESP32_WiFi_AP_SSL_Selector::HTML_Res_Head();
            String msg_str = "ESP32 softAP mode<br>SSL Server EXIT";
            String html_res_body = ESP32_WiFi_AP_SSL_Selector::HTML_Http_Body("", msg_str);

            SSL_write(_ssl, html_res_head.c_str(), html_res_head.length());
            SSL_write(_ssl, html_res_body.c_str(), html_res_body.length());
            _wifi_rescan = true;
            _ssl_redirect = false;
            softAP_server_end_OK = true;
            Serial.println(F("------------softAP server end()--------------"));
            break;
          }

          if(getTXT_pass > 0){
            _Sel_PASS_str = req_str.substring(getTXT_pass + 7, req_str.indexOf("&ssid_sel_submit")) + "\0";
          }
          if(getTXT_select >= 0){
            _Selected_SSID_str = req_str.substring(getTXT_select + 18, getTXT_pass) + "\0";
          }
          if(getTXT_disconnect < 0){
            Serial.println(F("----------------- GET SSID & Password"));
            Serial.printf("Selected_SSID_str = %s\r\n", _Selected_SSID_str.c_str());
            Serial.printf("Sel_SSID_PASS_str = %s\r\n", _Sel_PASS_str.c_str());

            str_w = _Selected_SSID_str + "\r\n" + _Sel_PASS_str + "\r\n\0";

            ESP32_WiFi_AP_SSL_Selector::SPIFFS_writeFile(APconfigFile_path, str_w);
            delay(100);

            ESP32_WiFi_AP_SSL_Selector::SPIFFS_readFile(APconfigFile_path, ssid1, pass1);
            Serial.print(F("SPIFFS read ssid = ")); Serial.println(ssid1);
            Serial.print(F("SPIFFS read pass = ")); Serial.println(pass1);

            if(WiFi.status() == WL_CONNECTED){
              if(String(pass1) != WiFi.psk()){
                ESP32_WiFi_AP_SSL_Selector::html_send(WiFi.SSID(), "Incorrect Password", "#F00");
                _ssl_redirect = true;
                req_str = "";
                break;
              }
            }
            Serial.printf("\r\n%s Connecting ...\r\n", _Selected_SSID_str.c_str());

            delay(10); // Important! This delay is necessary to connect to the Access Point.
 
            ESP32_WiFi_AP_SSL_Selector::WiFi_STA_Connect(ssid1, pass1, 20000);
            if(WiFi.status() != WL_CONNECTED){
              ESP32_WiFi_AP_SSL_Selector::html_send("---", "ESP32 STA cannot connect", "#F00");
              _ssl_redirect = true;
              break;
            }

            ESP32_WiFi_AP_SSL_Selector::html_send(WiFi.SSID(), "ESP32 STA connect OK!", "#0F0");
            Serial.println(F("------------ESP32 STA connect OK!-------------"));

            _ssl_redirect = true;
            req_str = "";
            break;
          }else{
            ESP32_WiFi_AP_SSL_Selector::html_send("---", "ESP32 STA Disconnect!", "#F00");
            WiFi.disconnect(false); //false=WiFi_ON , true=WiFi_OFF
            Serial.println(F("================ Wi-Fi STA mode Disconnect ================"));
            delay(300);
            req_str = "";
            _ssl_redirect = true;
            break;
          }

          req_str = "";
          break;
        }else if(strstr(recv_buf, "GET /favicon")){
          ESP32_WiFi_AP_SSL_Selector::favicon_response();
          req_str = "";
          break;
        }
    } while (1);

    Serial.println(F("----------------SSL_shutdown"));
    SSL_shutdown(_ssl);
failed5:
    log_e("----------------goto failed5:");
    close(_new_sockfd);
    _new_sockfd = -1;
failed4:
    log_e("----------------goto failed4:");
    SSL_free(_ssl);
    _ssl = NULL;
    delay(200); //これ重要。これが無いとうまくWebページが表示されない。

    if(softAP_server_end_OK == true) return 2;
    if(_wifi_rescan == true) return 1;

    if(_ssl_redirect == true){
      goto reconnect;
    }else{
      return 1;
    }

failed3:
    log_e("----------------goto failed3:");
    close(_sockfd);
    lwip_close_r(_sockfd);
    _sockfd = -1;

    return 1;
}
//*******************************************
int8_t ESP32_WiFi_AP_SSL_Selector::WiFi_STA_Connect(char* ssid1, char* pass1, uint32_t timeout){
  Serial.println(F("Connecting ..."));

  if(_STA_StaticIP_OK == true){
    Serial.println(F("Static IP set up ..."));
    if (!WiFi.config(_local_ip, _gateway, _subnet, _primaryDNS, _secondaryDNS)) {
      Serial.println(F("STA Failed to configure"));
    }
  }

  WiFi.begin(ssid1, pass1);
  uint32_t LastTime = millis();

  while(WiFi.status() != WL_CONNECTED){
    delay(500);
    Serial.print(".");
    if(millis()-LastTime > timeout){
      Serial.println(F("---------STA cannot connected time out------------"));
      return -1;
    }
  }

  _local_ip = WiFi.localIP();
  _gateway = WiFi.gatewayIP();
  _subnet = WiFi.subnetMask();

  _STA_StaticIP_OK = true;

  Serial.println(F("\r\nWiFi connected"));
  Serial.print(F("Local IP address: ")); Serial.println(_local_ip);
  //Serial.print(F("WiFi STA status: ")); Serial.println(WiFi.status());
  Serial.print(F("SSID = ")); Serial.println(WiFi.SSID());
  //Serial.print(F("PSK = ")); Serial.println(WiFi.psk()); //display password
  //Serial.print(F("ESP Mac Address: "));
  //Serial.println(WiFi.macAddress());
  Serial.print(F("Subnet Mask: "));
  Serial.println(_subnet);
  Serial.print(F("Gateway IP: "));
  Serial.println(_gateway);
  delay(500);
  return 1;
}
//*******************************************
String ESP32_WiFi_AP_SSL_Selector::HTML_Res_Head(){
  String html_res_head = "HTTP/1.1 200 OK\r\n";
         html_res_head += "Content-type:text/html\r\n";
         html_res_head += "Connection:close\r\n\r\n";
  return html_res_head;
}
//******************************************
String ESP32_WiFi_AP_SSL_Selector::HTML_Http_Body(String meta_str, String message_str){
  String str = "<!DOCTYPE html>\r\n";
         str += "<html>\r\n<head>\r\n";
         str += meta_str + "\r\n";
         str += "<meta name='viewport' content='initial-scale=1.3'>\r\n";
         str += "</head>\r\n";
         str += "<body style='font-size:100%;'>\r\n";
         str += message_str + "<br>\r\n";
         str += "\r\n</body>\r\n</html>\r\n";
  return str;
}
//*******************************************
String ESP32_WiFi_AP_SSL_Selector::HTML_Submit_Button(String name1, String font_color, String back_color, String message, String button_name){
  String str = "<form name='F_";
         str += name1;
         str += "'>\r\n";
         str += "  <button type='submit' name='";
         str += name1;
         str += "' value='send' style='color:";
         str += font_color;
         str += "; background-color:";
         str += back_color;
         str += "; border-radius:10px;' onclick='document.getElementById(\"ssid_sel_txt\").innerHTML=\"";
         str += message;
         str += "\";'>";
         str += button_name;
         str += "</button>\r\n";
         str += "</form>\r\n";
  return str;
}
//*******************************************
void ESP32_WiFi_AP_SSL_Selector::html_send(String now_ssid_str, String message2, String msg2_color){
  String str = "";
  String selected_str = "";

  str = ESP32_WiFi_AP_SSL_Selector::HTML_Res_Head();
  SSL_write(_ssl, str.c_str(), str.length());

  str = "<!DOCTYPE html>\r\n<html>\r\n";
  str += "<head>\r\n";
  str += "<meta name='viewport' content='initial-scale=1.3'>\r\n";
  str += "</head>\r\n";
  str += "<body style='background:#000; color:#fff; font-size:1em;'>\r\n";
  str += "ESP32 (ESP-WROOM-32)<br>\r\n";
  str += "Access Point Selector beta 1.0<br>\r\n";
  SSL_write(_ssl, str.c_str(), str.length());

  str = "<form name='F_ssid_select'>\r\n";
  str += "  <select name='ssid_select'>\r\n";
  for(int i=0; i<_ssid_num; i++){
    if(_Selected_SSID_str == _ssid_str[i]){
      selected_str = " selected";
    }else{
      selected_str = "";
    }
    str += "    <option value='" + _ssid_str[i] + "'" + selected_str + ">" + _ssid_rssi_str[i] + "</option>\r\n";
  }
  str += "</select><br>\r\n";
  str += "Password<br><input type='password' name='pass1'>\r\n";
  str += "<br><button type='submit' name='ssid_sel_submit' value='send' style='background-color:#AFA; border-radius:10px;' onclick='document.getElementById(\"ssid_sel_txt\").innerHTML=document.F_ssid_select.ssid_select.value;'>STA Connection GO!</button>\r\n";
  str += "</form><hr>\r\n";

  SSL_write(_ssl, str.c_str(), str.length());

  str = ESP32_WiFi_AP_SSL_Selector::HTML_Submit_Button("re_scan", "#000", "#DDD", "Wi-Fi ReScaning...", "Wi-Fi ReScan");
  str += "<hr>\r\n";
  str += "<div style='display:inline-flex'>\r\n";
  str += ESP32_WiFi_AP_SSL_Selector::HTML_Submit_Button("disconnect", "#000", "#F99", "ESP32 STA Disconnecting...", "STA Disconnect");
  str += "&nbsp;\r\n";
  str += ESP32_WiFi_AP_SSL_Selector::HTML_Submit_Button("reconnect", "#000", "#AAF", "ESP32 STA Reconnecting...", "STA Reconnect");
  str += "</div><hr>\r\n";
  str += ESP32_WiFi_AP_SSL_Selector::HTML_Submit_Button("exit", "#000", "#DDD", "softAP EXITing...", "softAP EXIT");
  str += "<hr>\r\n";
  str += "(Selected SSID)<br><span id='ssid_sel_txt'  style='font-size:80%;'>";
  str += now_ssid_str;
  str += "</span>\r\n";

  SSL_write(_ssl, str.c_str(), str.length());

  str = "<p style='color:" + msg2_color + "; font-size:80%'>" + message2 + "</p>\r\n";

  if(WiFi.status() == WL_CONNECTED){
    str += "<span style='font-size:80%'>ESP32 STA IP = ";
    IPAddress LIP = WiFi.localIP();
    str += LIP.toString(); //※これ、重要。IPアドレス整数をドット表記String型に変更する関数。
    str += "</span>\r\n";
  }

  str += "\r\n</body>\r\n</html>\r\n\r\n";

  SSL_write(_ssl, str.c_str(), str.length());
}
//*******************************************
void ESP32_WiFi_AP_SSL_Selector::favicon_response(){
  Serial.println(F("-----------------------Favicon GET Request Received"));

  String str1 = "HTTP/1.1 404 Not Found\r\n";
  String str2 = "Connection:close\r\n\r\n";
  SSL_write(_ssl, str1.c_str(), str1.length());
  SSL_write(_ssl, str2.c_str(), str2.length());
}
//*******************************************
void ESP32_WiFi_AP_SSL_Selector::wifi_scan(uint32_t scan_interval){
  if( (_First_Scan_Set == true) || ((millis() - _scanLastTime) > scan_interval) ){
    Serial.println(F("scan start"));

    // WiFi.scanNetworks will return the number of networks found
    _ssid_num = WiFi.scanNetworks();
    Serial.println(F("scan done\r\n"));
    if (_ssid_num == 0) {
      Serial.println(F("no networks found\r\n"));
    } else {
      Serial.printf("%d networks found\r\n\r\n", _ssid_num);
      for (int i = 0; i < _ssid_num; ++i) {
        _ssid_str[i] = WiFi.SSID(i);
        String wifi_auth_open = ((WiFi.encryptionType(i) == WIFI_AUTH_OPEN)?" ":"*");
        _ssid_rssi_str[i] = _ssid_str[i] + " (" + WiFi.RSSI(i) + "dBm)" + wifi_auth_open;
        Serial.printf("%d: %s\r\n", i, _ssid_rssi_str[i].c_str());
        delay(10);
      }
    }
    Serial.println();
    _scanLastTime = millis();
    _First_Scan_Set = false;
  }
}
//******************************************
uint16_t ESP32_WiFi_AP_SSL_Selector::SPIFFS_read_PKI_File(const char * path, char pki_cstr[]){
  Serial.print(F("SPIFFS file reading --- ")); Serial.println(path);
  File file = SPIFFS.open(path, FILE_READ);
  if(!file){
    Serial.println(F("Failed to open file for writing"));
    return 0;
  }
  uint16_t i = 0;

  while(file.available()){
    pki_cstr[i] = file.read();
    if(pki_cstr[i] == '\0') break;
    i++;
  }
  pki_cstr[i] = '\0';

  delay(10);
  file.close();
  delay(10);
  return i;
}
//*******************************************
void ESP32_WiFi_AP_SSL_Selector::SPIFFS_writeFile(const char * path, String c_ssid_pass){
  Serial.printf("SPIFFS writing file: %s\n", path);

  deleteFile(path);
  delay(10);
  File file = SPIFFS.open(path, FILE_WRITE);
  if(!file){
    Serial.println(F("Failed to open file for writing"));
    return;
  }
  if(file.print(c_ssid_pass)){
    Serial.println(c_ssid_pass);
    Serial.println(F("SPIFFS file written\r\n"));
  } else {
    Serial.println(F("SPIFFS write failed\r\n"));
  }
  delay(10);
  file.close();
  delay(10);
}
//*******************************************
void ESP32_WiFi_AP_SSL_Selector::deleteFile(const char * path){
  Serial.printf("Deleting file: %s\r\n", path);
  if(SPIFFS.remove(path)){
    Serial.println(F("- file deleted"));
  } else {
    Serial.println(F("- delete failed"));
  }
  delay(10);
}
//*******************************************
void ESP32_WiFi_AP_SSL_Selector::SPIFFS_readFile(const char * path, char ssid_c[], char pass_c[]){
  Serial.printf("SPIFFS reading file: %s\n", path);

  File file = SPIFFS.open(path);
  if(!file || file.isDirectory()){
    Serial.println(F("SPIFFS Failed to open file for reading"));
    return;
  }

  int i=0, j=0;
  while(file.available()){
    ssid_c[i] = file.read();
    if(ssid_c[i] == '\0') break;
    if(ssid_c[i] == '\r'){
      ssid_c[i] = '\0';
      char c = file.read();
      if(c == '\n'){
        break;
      }
    }
    i++;
    if( i>63 ) break;
  }
  while(file.available()){
    pass_c[j] = file.read();
    if(pass_c[j] == '\0') break;
    if(pass_c[j] == '\r'){
      pass_c[j] = '\0';
      char c = file.read();
      if(c == '\n'){
        break;
      }
    }
    j++;
    if( j>63 ) break;
  }
  if(i < 1) Serial.println(F("Nothing ssid"));
  if(j < 1) Serial.println(F("Nothing password"));
  delay(10);
  file.close();
  delay(10);
}