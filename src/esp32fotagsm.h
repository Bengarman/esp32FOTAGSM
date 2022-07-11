/*
   esp32 firmware OTA
   Date: December 2018   
   Purpose: Perform an OTA update from a bin located on a webserver (HTTP Only)
*/

#ifndef esp32FOTAGSM_h
#define esp32FOTAGSM_h

#include "Arduino.h"

#if (!defined(SRC_TINYGSMCLIENT_H_))
#define TINY_GSM_MODEM_SIM7600
#define TINY_GSM_RX_BUFFER 1024
#include <TinyGsmClient.h>
#endif  // SRC_TINYGSMCLIENT_H_

class esp32FOTAGSM
{
public:
  esp32FOTAGSM(String firwmareType, int firwmareVersion, bool certCheck);
  void forceUpdate(String firwmareHost, int firwmarePort, String firwmarePath);
  void execOTA();
  bool execHTTPcheck();
  bool useDeviceID;
  // String checkURL; 	// ArduinoHttpClient requires host, port and resource instead
  String checkHOST; 	// example.com
  int checkPORT;		// 80  
  String checkRESOURCE; // /customer01/firmware.json
  uint8_t * checkPublicKey; // /customer01/firmware.json
  void setModem(TinyGsm& modem);
  bool validate_sig( unsigned char *signature, uint32_t firmware_size );

private:
  String getDeviceID();
  String _firwmareType;
  int _firwmareVersion;
  bool _check_sig;
  String _host;
  String _bin;
  int _port;
  TinyGsm*	_modem;
};

#endif
