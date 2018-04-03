#include <WiFi.h>
#include "ESP32_WiFi_AP_SSL_Selector.h"

const char *ap_ssid = "xxxxxxxx"; //ESP32 softAP SSID
const char *ap_pass = "xxxxxxxx"; //ESP32 softAP password

IPAddress local_IP(192, 168, 13, 10); //your ESP32 STA mode Static Local IP
IPAddress gateway(192, 168, 13, 1); //your Wi-Fi router default gateway
IPAddress subnet(255, 255, 255, 0);
IPAddress primaryDNS(8, 8, 8, 8); //optional
IPAddress secondaryDNS(8, 8, 4, 4); //optional

ESP32_WiFi_AP_SSL_Selector EWASS;

const uint16_t https_port = 443;
uint16_t ssl_recv_buf_len = 1024;

const char* softAP_cert_filePath = "/cert/esp32softap_server.pem";
const char* softAP_prvt_filePath = "/cert/esp32softap_server.key";

const char* AP_config_file = "/APconfig/APconfig.txt"; //ssid, password save file

char spiffs_read_ssid[64] = {};
char spiffs_read_pass[64] = {};

WiFiClient __client1;
WiFiServer __server1(80);

boolean softAP_server_status = true;

//**************************************
void setup() {
  Serial.begin(115200);
  delay(500);

  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS failed, or not present");
    return;
  }

  EWASS.SPIFFS_readFile(AP_config_file, spiffs_read_ssid, spiffs_read_pass);
  Serial.print("SPIFFS read ssid = "); Serial.println(spiffs_read_ssid);
  Serial.print("SPIFFS read pass = "); Serial.println(spiffs_read_pass);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(ap_ssid, ap_pass);
  delay(100);

  Serial.println("Setup done");
  
  IPAddress myIP = WiFi.softAPIP();
  Serial.println(myIP);
  delay(1000);

  EWASS.Init_StaticIP(https_port, ssl_recv_buf_len, local_IP, gateway, subnet, primaryDNS, secondaryDNS, spiffs_read_ssid, spiffs_read_pass);
  //EWASS.Init(https_port, ssl_recv_buf_len, spiffs_read_ssid, spiffs_read_pass); //Not Static IP

  EWASS.WiFi_STA_Connect(spiffs_read_ssid, spiffs_read_pass, 20000);
  delay(1000);
  

  Serial.println("--------------- SSL init");
  EWASS.openssl_init(softAP_cert_filePath, softAP_prvt_filePath);
}
//**********************************************
void loop() {
  EWASS.wifi_scan(20000); //20秒以上にすること
  if( softAP_server_status ){
    EWASS.softAP_http_server();
  }else{
    http_sta_server_test();
  }
  if( EWASS.SSL_softAP_WiFi_Selector(AP_config_file, spiffs_read_ssid, spiffs_read_pass) == 2){
    softAP_server_status = false;
    Serial.println("------------ softAP--->STA change!");
  }
}
//*********************************************
void http_sta_server_test(){
  __client1 = __server1.available();

  if (__client1) {
    String html_str = "<!DOCTYPE html>\r\n<html>\r\n";
          html_str += "<head>\r\n";
          html_str += "<meta name='viewport' content='initial-scale=1.3'>\r\n";
          html_str += "</head>\r\n";
          html_str += "<body style='background:#DDF; color:#00F; font-size:1em;'>\r\n";
          html_str += "My ESP32 STA mode HTTP server<br>\r\n";
          html_str += "<p style='font-size:2em'>Hello! World!</p>\r\n";
          html_str += EWASS.HTML_Submit_Button("exit_sta", "#000", "#DDD", "", "EXIT STA");
          html_str += "</body></html>\r\n\r\n";
    Serial.println(F("my_sta_HTTP New Client."));
    String currentLine = "";

    uint32_t LastTime = millis();
    while (__client1.connected()) {
      if( (millis()-LastTime) > 30000 ){ //timeout setting
        Serial.println("-------------__client1 timeout");
        break;
      }
      if (__client1.available()) {
        currentLine = __client1.readStringUntil('\n');
        if(currentLine.indexOf("\r") == 0) break;
        Serial.println(currentLine);
        if(currentLine.indexOf("GET / HTTP/1.1") >= 0){
          Serial.println(F("------------ my_sta_HTTP request received ---------------"));    
          __client1.println( EWASS.HTML_Res_Head() );
          __client1.println( html_str );
          __client1.println();
          currentLine = "";
          break;
        }else if(currentLine.indexOf("GET /?exit_sta=") >= 0){
          Serial.println(F("------------ request received [GET /?exit_sta=]---------------"));    
          softAP_server_status = true;
          __client1.println( EWASS.HTML_Http_Body("", "EXIT STA mode") );
          break;
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
