/*
  ESP32_TwitterAPI.h - for Arduino core for the ESP32 ( Use SPI library ).
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

#ifndef _ESP32_TWITTERAPI_H_INCLUDED
#define _ESP32_TWITTERAPI_H_INCLUDED

#include <WiFiClientSecure.h>
#include <WiFiMulti.h>
#include <WiFiUdp.h>
//Time library -> http://playground.arduino.cc/code/time
#include "TimeLib.h"

#include <base64.h>
#include "mbedtls/sha1.h"

//xtensa-esp32 library (UTF16 to UTF8 converter)
#include <codecvt>
#include <string>
#include <cassert>
#include <locale>

std::string utf16_to_utf8(std::u16string const& src);

class ESP32_TwitterAPI
{
private:

#define SHA1_SIZE 20
  const char *_Consumer_key;
  const char *_Consumer_secret;
  const char *_Access_token;
  const char *_Access_secret;

  const char *_Base_host;
  const char *_Base_URL;
  const char *_Base_URI;

  String _Woeid; //WOEID

  const int httpsPort           = 443;

  const char *_Key_http_method        = "GET";
  const char *_Key_consumer_key       = "oauth_consumer_key";
  const char *_Key_nonce              = "oauth_nonce";
  const char *_Key_signature_method   = "oauth_signature_method";
  const char *_Key_timestamp          = "oauth_timestamp";
  const char *_Key_token              = "oauth_token";
  const char *_Key_version            = "oauth_version";
  const char *_Key_status             = "status";
  const char *_Key_signature          = "oauth_signature";
  const char *_Value_signature_method = "HMAC-SHA1";
  const char *_Value_version          = "1.0";

public:
  ESP32_TwitterAPI();

  void TwitterAPI_Key_Set(const char *consu_key, const char *consu_sec, const char *ac_tok, const char *ac_sec);
  void TwitterAPI_begin(const char *b_host);
  bool TrendTweet_Get(const char *ca, const char *base_URL, const char *base_URI, String woeID, uint8_t Max_data, String Utf8_Str[]);
  bool TrendTweet_HTTP_Request(const char *RootCA, String OAuth_header, String status_all, uint8_t max_data, String Utf8_Str[]);
  String make_parameter_str(String status_all, uint32_t value_nonce, uint32_t value_timestamp);
  String make_sign_base_str(String parameter_str);
  String make_signature(const char* secret_one, const char* secret_two, String sign_base_str);
  String make_OAuth_header(String oauth_signature, uint32_t value_nonce, uint32_t value_timestamp);
  String URLEncode(const char* msg);
  void ssl_hmac_sha1(uint8_t *msg, int length, const uint8_t *key, int key_len, unsigned char *digest);
  String UTF16toUTF8(String str);

};

#endif