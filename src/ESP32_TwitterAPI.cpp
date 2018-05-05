/*
  ESP32_TwitterAPI.cpp - for Arduino core for the ESP32 ( Use SPI library ).
  Beta version 1.1
mgo-tec modified for code created by chaeplin for ESP32.

Reference: https://gist.github.com/chaeplin/32dd002ddc5fe92d026055130a519b72
Reference: https://github.com/igrr/axtls-8266/blob/master/crypto/hmac.c
hmac.c  License axTLS 1.4.9 Copyright (c) 2007-2016, Cameron Rich
ssl_hmac_sha1 function modified by mogotec for mbedtls.

axTLS linsence imported.

axTLS uses a BSD style license:

Copyright (c) 2008, Cameron Rich All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer. Redistributions in binary
form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials
provided with the distribution. Neither the name of the axTLS Project nor
the names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#include "ESP32_TwitterAPI.h"

ESP32_TwitterAPI::ESP32_TwitterAPI(){}

//********************************************
void ESP32_TwitterAPI::TwitterAPI_Key_Set(const char *consu_key, const char *consu_sec, const char *ac_tok, const char *ac_sec){
  _Consumer_key    = consu_key;
  _Consumer_secret = consu_sec;
  _Access_token    = ac_tok;
  _Access_secret   = ac_sec;
}
//********************************************
void ESP32_TwitterAPI::TwitterAPI_begin(const char *b_host){
  _Base_host = b_host;
}
//**********ツイート取得************************
bool ESP32_TwitterAPI::TrendTweet_Get(const char *ca, const char *base_URL, const char *base_URI, String woeID, uint8_t Max_data, String Utf8_Str[]) {
  _Base_URL = base_URL;
  _Base_URI = base_URI;
  _Woeid = woeID;
  
  uint32_t value_timestamp  = now();
  uint32_t value_nonce      = 1111111111 + value_timestamp;

  Serial.println(F("--------------------------"));
  String status_all = "";
  String parameter_str = make_parameter_str(status_all, value_nonce, value_timestamp);
  String sign_base_str = make_sign_base_str(parameter_str);
  String oauth_signature = make_signature(_Consumer_secret, _Access_secret, sign_base_str);
  String OAuth_header = make_OAuth_header(oauth_signature, value_nonce, value_timestamp);

  Serial.print(F("OAuth_header = "));
  Serial.println(OAuth_header);

  bool connection = TrendTweet_HTTP_Request(ca, OAuth_header, status_all, Max_data, Utf8_Str);
  if(connection == false){
    Utf8_Str[0] = "Twitter API connection failed";
  }
  return connection;
}
//*************** HTTP GET Request***************************************
bool ESP32_TwitterAPI::TrendTweet_HTTP_Request(const char *RootCA, String OAuth_header, String status_all, uint8_t max_data, String Utf8_Str[]){
  bool connection = false;
  String unicode_str[max_data];
  WiFiClientSecure client;

  if( strlen( RootCA ) > 0 ) client.setCACert(RootCA);

  if (client.connect(_Base_host, httpsPort)) {
    Serial.print(_Base_host); Serial.print(F("-------------"));
    Serial.println(F("connected"));

    String str01 = String(_Key_http_method) + " " + String(_Base_URI) + "?id=" + String(_Woeid) + " HTTP/1.1\r\n";
    str01 += "Accept-Charset: UTF-8\r\n";
    str01 += "Accept-Language: ja,en\r\n";
    String str02 = "Authorization: " + OAuth_header + "\r\n";
    str02 += "Connection: close\r\n";
    str02 += "Content-Length: 0\r\n";
    str02 += "Content-Type: application/x-www-form-urlencoded\r\n";
    str02 += "Host: " + String(_Base_host) + "\r\n\r\n";

    client.print( str01 );
    client.print( str02 );

    Serial.println(F("-------------------- HTTP GET Request Send"));
    Serial.print( str01 );
    Serial.print( str02 );

    String res_str = "";
    String name_str = "";

    uint16_t from, to;
    uint8_t n_cnt = 0;
    String name_begin_str = "\"name\":\"";
    int16_t name_begin_flag = 0;

    Serial.println(F("--------------------HTTP Response"));

    while(client.connected()){
      while (client.available()) {
        res_str = client.readStringUntil('\n');
        Serial.println(res_str);
        if(res_str.indexOf("\r") <= 2){
          Serial.println(F("-------------JSON GET ALL------------"));
          while(client.connected()){
            while(client.available()){
              res_str = client.readStringUntil(',');
              name_begin_flag = res_str.indexOf(name_begin_str);

              if( name_begin_flag >= 0){
                from = name_begin_flag + name_begin_str.length();
                to = res_str.length() - 1;
                name_str = res_str.substring(from,to) + '\0';
                Serial.println(name_str);
                name_str.replace("#", ""); //ハッシュタグ消去

                if(n_cnt < max_data){
                  unicode_str[n_cnt] = name_str;
                }
                name_str = "";
                n_cnt++;
                res_str = "";
              }
            }
          }
        }
      }
    }
    client.flush();
    delay(10);
    client.stop();
    delay(10);
    Serial.println(F("--------------------Client Stop"));
    connection = true;
  }else {
    // if you didn't get a connection to the server2:
    Serial.println(F("connection failed"));
    connection = false;
  }

  if(connection == true){
    int i;
    Serial.println(F("----------GET Twitter Trends Unicode ( UTF16 )-------------"));
    for(i=0; i<max_data; i++){
      Serial.println(unicode_str[i]);
    }
    Serial.println(F("----------GET Twitter Trends Unicode ( UTF-8 )-------------"));
    for(i=0; i<max_data; i++){
      Utf8_Str[i] = UTF16toUTF8( unicode_str[i] );
      Serial.println( Utf8_Str[i] );
    }
  }

  return connection;
}
//*************************************************
String ESP32_TwitterAPI::make_parameter_str(String status_all, uint32_t value_nonce, uint32_t value_timestamp) {
  String parameter_str = "id=" + _Woeid;
  parameter_str += "&";
  parameter_str += _Key_consumer_key;
  parameter_str += "=" ;
  parameter_str += _Consumer_key;
  parameter_str += "&";
  parameter_str += _Key_nonce;
  parameter_str += "=";
  parameter_str += value_nonce;
  parameter_str += "&";
  parameter_str += _Key_signature_method;
  parameter_str += "=";
  parameter_str += _Value_signature_method;
  parameter_str += "&";
  parameter_str += _Key_timestamp;
  parameter_str += "=";
  parameter_str += value_timestamp;
  parameter_str += "&";
  parameter_str += _Key_token;
  parameter_str += "=";
  parameter_str += _Access_token;
  parameter_str += "&";
  parameter_str += _Key_version;
  parameter_str += "=";
  parameter_str += _Value_version;
  Serial.print(F("parameter_str = "));
  Serial.println(parameter_str);
  return parameter_str;
}
//*************************************************
String ESP32_TwitterAPI::make_sign_base_str(String parameter_str) {  
  String sign_base_str = _Key_http_method;
  sign_base_str += "&";
  sign_base_str += URLEncode(_Base_URL);
  sign_base_str += "&";
  sign_base_str += URLEncode(parameter_str.c_str());
  Serial.print(F("sign_base_str = "));
  Serial.println(sign_base_str);
  return sign_base_str;
}
//*************************************************
String ESP32_TwitterAPI::make_signature(const char* secret_one, const char* secret_two, String sign_base_str) {
  String signing_key = URLEncode(secret_one);
  signing_key += "&";
  signing_key += URLEncode(secret_two);
  Serial.print(F("signing_key = "));
  Serial.println(signing_key);

  unsigned char digestkey[32];
  mbedtls_sha1_context context;

  mbedtls_sha1_starts(&context);
  mbedtls_sha1_update(&context, (uint8_t*) signing_key.c_str(), (int)signing_key.length());
  mbedtls_sha1_finish(&context, digestkey);

  uint8_t digest[32];
  ssl_hmac_sha1((uint8_t*) sign_base_str.c_str(), (int)sign_base_str.length(), digestkey, SHA1_SIZE, digest);

  String oauth_signature = URLEncode(base64::encode(digest, SHA1_SIZE).c_str());
  Serial.print(F("oauth_signature = "));
  Serial.println(oauth_signature);
  return oauth_signature;
}
//*************************************************
String ESP32_TwitterAPI::make_OAuth_header(String oauth_signature, uint32_t value_nonce, uint32_t value_timestamp) {
  String OAuth_header = "OAuth ";
  OAuth_header += "id=\"";
  OAuth_header += _Woeid;
  OAuth_header += "\", ";
  OAuth_header += _Key_consumer_key;
  OAuth_header += "=\"";
  OAuth_header += _Consumer_key;
  OAuth_header += "\",";
  OAuth_header += _Key_nonce;
  OAuth_header += "=\"";
  OAuth_header += value_nonce;
  OAuth_header += "\",";
  OAuth_header += _Key_signature;
  OAuth_header += "=\"";
  OAuth_header += oauth_signature;
  OAuth_header += "\",";
  OAuth_header += _Key_signature_method;
  OAuth_header += "=\"";
  OAuth_header += _Value_signature_method;
  OAuth_header += "\",";
  OAuth_header += _Key_timestamp;
  OAuth_header += "=\"";
  OAuth_header += value_timestamp;
  OAuth_header += "\",";
  OAuth_header += _Key_token;
  OAuth_header += "=\"";
  OAuth_header += _Access_token;
  OAuth_header += "\",";
  OAuth_header += _Key_version;
  OAuth_header += "=\"";
  OAuth_header += _Value_version;
  OAuth_header += "\"";
  return OAuth_header;
}
//*************************************************
String ESP32_TwitterAPI::URLEncode(const char* msg) {
  const char *hex = "0123456789ABCDEF";
  String encodedMsg = "";

  while (*msg != '\0') {
    if ( ('a' <= *msg && *msg <= 'z')
         || ('A' <= *msg && *msg <= 'Z')
         || ('0' <= *msg && *msg <= '9')
         || *msg  == '-' || *msg == '_' || *msg == '.' || *msg == '~' ) {
      encodedMsg += *msg;
    } else {
      encodedMsg += '%';
      encodedMsg += hex[*msg >> 4];
      encodedMsg += hex[*msg & 0xf];
    }
    msg++;
  }
  return encodedMsg;
}
//*************************************************
void ESP32_TwitterAPI::ssl_hmac_sha1(uint8_t *msg, int length, const uint8_t *key, int key_len, unsigned char *digest) {
  mbedtls_sha1_context context;
  uint8_t k_ipad[64] = {0};
  uint8_t k_opad[64] = {0};
  int i;

  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  for (i = 0; i < 64; i++)
  {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  mbedtls_sha1_starts(&context);
  mbedtls_sha1_update(&context, k_ipad, 64);
  mbedtls_sha1_update(&context, msg, length);
  mbedtls_sha1_finish(&context, digest);
  mbedtls_sha1_starts(&context);
  mbedtls_sha1_update(&context, k_opad, 64);
  mbedtls_sha1_update(&context, digest, SHA1_SIZE);
  mbedtls_sha1_finish(&context, digest);
}
//********** Unicode ( UTF16 ) to UTF-8 convert ********************************
String ESP32_TwitterAPI::UTF16toUTF8(String str){
  str.replace("\\u","\\");
  str += '\0';
  uint16_t len = str.length();
  char16_t utf16code[len];

  int i=0;
  String str4 = "";
  for(int j=0; j<len; j++){
    if(str[j] == 0x5C){ //'\'を消去
      j++;
      for(int k=0; k<4; k++){
        str4 += str[j+k];
      }
      utf16code[i] = strtol(str4.c_str(), NULL, 16); //16進文字列を16進数値に変換
      str4 = "";
      j = j+3;
      i++;
    }else if(str[j] == 0x23){ //'#'を消去
      utf16code[i] = 0xFF03; //全角＃に変換
      i++;
    }else{
      utf16code[i] = (char16_t)str[j];
      i++;
    }
  }

  std::u16string u16str(utf16code);
  std::string u8str = utf16_to_utf8(u16str);
  String ret_str = String(u8str.c_str());
  //URLに影響のある特殊文字を全角に変換
  ret_str.replace("+", "＋");
  ret_str.replace("&", "＆");
  ret_str.replace("\\", "￥");

  return ret_str;
}
//********* UTF16 -> UTF8 cnvert ******************************************
std::string utf16_to_utf8(std::u16string const& src){
  std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
  return converter.to_bytes(src);
}