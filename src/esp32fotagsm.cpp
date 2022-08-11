/*
   esp32 firmware OTA
   Date: December 2018
   Purpose: Perform an OTA update from a bin located on a webserver (HTTP Only)
*/

#include "esp32fotagsm.h"
#include "Arduino.h"
// #include <WiFi.h>   // CHANGE
// #include <HTTPClient.h>	// CHANGE
#include <ArduinoHttpClient.h> // Kevin
#include <Update.h>
#include "ArduinoJson.h"

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "esp_ota_ops.h"

#if (!defined(SRC_TINYGSMCLIENT_H_))
#define TINY_GSM_MODEM_SIM7600
#include <TinyGsmClient.h>
#endif  // SRC_TINYGSMCLIENT_H_

esp32FOTAGSM::esp32FOTAGSM(String firwmareType, int firwmareVersion, bool certCheck)
{
    _firwmareType = firwmareType;
    _firwmareVersion = firwmareVersion;
    _check_sig = certCheck;
    useDeviceID = false;
}

static void splitHeader(String src, String &header, String &headerValue)
{
    int idx = 0;

    idx = src.indexOf(':');
    header = src.substring(0, idx);
    headerValue = src.substring(idx + 1, src.length());
    headerValue.trim();

    return;
}
bool esp32FOTAGSM::validate_sig( unsigned char *signature, uint32_t firmware_size ) {
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_md_context_t rsa;

    { // Open RSA public key:
        
        mbedtls_pk_init( &pk );
        if( ( ret = mbedtls_pk_parse_public_key( &pk, ( uint8_t * ) checkPublicKey, sizeof( char ) + strlen( ( const char * ) checkPublicKey ) ) ) != 0 ) {
            Serial.println( "Reading public key failed\n  ! mbedtls_pk_parse_public_key \n\n");
            return false;
        }
    }

    if( !mbedtls_pk_can_do( &pk, MBEDTLS_PK_RSA ) ) {
        log_e( "Public key is not an rsa key -0x%x\n\n", -ret );
        return false;
    }


    const esp_partition_t* partition = esp_ota_get_next_update_partition(NULL);
   
    if( !partition ) {
        log_e( "Could not find update partition!" );
        return false;
    }

    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    mbedtls_md_init( &rsa );
    mbedtls_md_setup( &rsa, mdinfo, 0 );
    mbedtls_md_starts( &rsa );
    
    int bytestoread = SPI_FLASH_SEC_SIZE;
    int bytesread = 0;
    int size = firmware_size;

    uint8_t *_buffer = (uint8_t*)malloc(SPI_FLASH_SEC_SIZE);
    if(!_buffer){
        log_e( "malloc failed" );
        return false;
    }
    //Serial.printf( "Reading partition (%i sectors, sec_size: %i)\r\n", size, bytestoread );
    while( bytestoread > 0 ) {
      //Serial.printf( "Left: %i (%i)               \r", size, bytestoread );
    
      if( ESP.partitionRead( partition, bytesread, (uint32_t*)_buffer, bytestoread ) ) {
	// Debug output for the purpose of comparing with file
        /*for( int i = 0; i < bytestoread; i++ ) {
          if( ( i % 16 ) == 0 ) {
            Serial.printf( "\r\n0x%08x\t", i + bytesread );
          }
          Serial.printf( "%02x ", (uint8_t*)_buffer[i] );
        }*/

        mbedtls_md_update( &rsa, (uint8_t*)_buffer, bytestoread );

        bytesread = bytesread + bytestoread;
        size = size - bytestoread;

        if( size <= SPI_FLASH_SEC_SIZE ) {
            bytestoread = size;
        }
      } else {
        log_e( "partitionRead failed!" );
        return false;
      }
    }
    free( _buffer );

    unsigned char *hash = (unsigned char*)malloc( mdinfo->size );
    mbedtls_md_finish( &rsa, hash );

    ret = mbedtls_pk_verify( &pk, MBEDTLS_MD_SHA256,
        hash, mdinfo->size,
	(unsigned char*)signature, 512
    );

    free( hash );
    mbedtls_md_free( &rsa );
    mbedtls_pk_free( &pk );
    if( ret == 0 ) {
        return true;
    }
    // overwrite the frist few bytes so this partition won't boot!

    ESP.partitionEraseRange( partition, 0, ENCRYPTED_BLOCK_SIZE);

    return false;
}

// OTA Logic
void esp32FOTAGSM::execOTA()
{
	// CHANGE
	// https://github.com/blynkkk/blynk-library/blob/master/src/Adapters/BlynkGsmClient.h#L99
	// WiFiClient client;
	// TinyGsmClient client(_modem); => not able to compile
	TinyGsmClient client;
	bool isClientOK = client.init(_modem);
	// Serial.println("isClientOK: "+ String(isClientOK));
	
    int contentLength = 0;
    bool isValidContentType = false;
    bool gotHTTPStatus = false;

    Serial.println("Connecting to: " + String(_host));
	
	// https://github.com/espressif/arduino-esp32/issues/325
	// Written only : 0/564608. Retry?
	// Error Occurred. Error #: 8
	// client.setTimeout(5000); // Kevin, a bit longer wait
	client.setTimeout(60000); // Kevin, muchlonger wait
	
    // Connect to Webserver
    if (client.connect(_host.c_str(), _port))
    {
		// client.setTimeout(60000); // Kevin, longer wait // REMOVED
		
        // Connection Succeed.
        // Fetching the bin
        Serial.println("Fetching Bin: " + String(_bin));

        // Get the contents of the bin file
        client.print(String("GET ") + _bin + " HTTP/1.1\r\n" +
                     "Host: " + _host + "\r\n" +
                     "Cache-Control: no-cache\r\n" +
                     "Connection: close\r\n\r\n");

        unsigned long timeout = millis();
        while (client.available() == 0)
        {
            // if (millis() - timeout > 5000) // CHANGE 
			if (millis() - timeout > 60000) // Kevin: More timeout
            {
                Serial.println("Client Timeout !");
                client.stop();
                return;
            }
        }

        while (client.available())
        {
            String header, headerValue;
            // read line till /n
            String line = client.readStringUntil('\n');
            // remove space, to check if the line is end of headers
            line.trim();

            if (!line.length())
            {
                //headers ended
                break; // and get the OTA started
            }

            // Check if the HTTP Response is 200
            // else break and Exit Update
            if (line.startsWith("HTTP/1.1"))
            {
                if (line.indexOf("200") < 0)
                {
                    Serial.println("Got a non 200 status code from server. Exiting OTA Update.");
                    client.stop();
                    break;
                }
                gotHTTPStatus = true;
            }

            if (false == gotHTTPStatus)
            {
                continue;
            }

            splitHeader(line, header, headerValue);

            // extract headers here
            // Start with content length
            if (header.equalsIgnoreCase("Content-Length"))
            {
                contentLength = headerValue.toInt();
                Serial.println("Got " + String(contentLength) + " bytes from server");
                continue;
            }

            // Next, the content type
            if (header.equalsIgnoreCase("Content-type"))
            {
                String contentType = headerValue;
                Serial.println("Got " + contentType + " payload.");
                if (contentType == "application/octet-stream")
                {
                    isValidContentType = true;
                }else{
                    isValidContentType = true;
                }
            }
        }
    }
    else
    {
        // Connect to webserver failed
        // May be try?
        // Probably a choppy network?
        Serial.println("Connection to " + String(_host) + " failed. Please check your setup");
        // retry??
        if (_retryCount > 0){
            _retryCount --;
            execOTA();
        }    }

    // Check what is the contentLength and if content type is `application/octet-stream`
    Serial.println("contentLength : " + String(contentLength) + ", isValidContentType : " + String(isValidContentType));

    // check contentLength and content type
    if (contentLength && isValidContentType)
    {
        if( _check_sig ) {
           // If firmware is signed, extract signature and decrease content-length by 512 bytes for signature
           contentLength = contentLength - 512;
        }
        // Check if there is enough to OTA Update
        bool canBegin = Update.begin(contentLength);

        // If yes, begin
        if (canBegin)
        {
            unsigned char signature[512];
            if( _check_sig ) {
               client.readBytes( signature, 512 );
            }
            Serial.println("Begin OTA. This may take 2 - 5 mins to complete. Things might be quite for a while.. Patience!");
            // No activity would appear on the Serial monitor
            // So be patient. This may take 2 - 5mins to complete
            size_t written = Update.writeStream(client);

            if (written == contentLength)
            {
                Serial.println("Written : " + String(written) + " successfully");
            }
            else
            {
                Serial.println("Written only : " + String(written) + "/" + String(contentLength) + ". Retry?");
                // retry??
                // execOTA();
            }

            if (Update.end())
            {
                if( _check_sig ) {
                   if( !validate_sig( signature, contentLength )) {
                       
                        const esp_partition_t* partition = esp_ota_get_running_partition();
                        esp_ota_set_boot_partition( partition );

                        Serial.println( "Signature check failed!" );
                        ESP.restart();
                        return;
                   } else {
                        Serial.println( "Signature OK" );
                   }
                }
                Serial.println("OTA done!");
                if (Update.isFinished())
                {
                    Serial.println("Update successfully completed. Rebooting.");
                    ESP.restart();
                }
                else
                {
                    Serial.println("Update not finished? Something went wrong!");
                }
            }
            else
            {
                Serial.println("Error Occurred. Error #: " + String(Update.getError()));
            }
        }
        else
        {
            // not enough space to begin OTA
            // Understand the partitions and
            // space availability
            Serial.println("Not enough space to begin OTA");
            client.flush();
        }
    }
    else
    {
        Serial.println("There was no content in the response");
        client.flush();
    }
}

bool esp32FOTAGSM::execHTTPcheck()
{

    String useURL;

    if (useDeviceID)
    {
        // String deviceID = getDeviceID() ;
        // useURL = checkURL + "?id=" + getDeviceID();
		useURL = checkRESOURCE + "?id=" + getDeviceID(); // Kevin
    }
    else
    {
        // useURL = checkURL;
		useURL = checkRESOURCE; // Kevin
    }

    _port = 80;

    Serial.println("Getting HTTP");
    Serial.println(checkHOST);
    Serial.println(useURL);
    Serial.println("------");
	
	// CHANGE
	// if ((WiFi.status() == WL_CONNECTED))
	if (_modem->isGprsConnected())
    { //Check the current connection status

        // HTTPClient http;		   // TO CHANGE: Dont know if works

        // http.begin(useURL);        //Specify the URL
		// TinyGsmClient client((TinyGsm*)_modem);		// Kevin // Set o day bi bao loi. La thiet
		TinyGsmClient client;
		bool isClientOK = client.init(_modem);		// Kevin: return 1 => OK
		// Serial.println("isClientOK: "+ String(isClientOK));
		
		// HttpClient    http(client, _host, _port); // Kevin
		HttpClient    http(client, checkHOST, checkPORT); // Kevin
        // int httpCode = http.GET(); //Make the request
		// Serial.println("useURL: " + useURL);
		// Serial.println("GPRS connected");
				
		int err = http.get(useURL);  // Kevin
		// Serial.println("TinyGsmClient: " + String(client.connected()));
		if (err != 0) {
			Serial.println(F("failed to connect"));
			delay(10000);
			return false; // Error, nothing to update
		}
		else
		{
			// Hinh nhu cho nay ok
			// Serial.println("http err:" + String(err));
		}
		
		int httpCode = http.responseStatusCode();
		// Serial.println("httpCode:" + String(httpCode));
		
        if (httpCode == 200)
        { //Check is a file was returned

            // String payload = http.getString(); // CHANGE 
			String payload = http.responseBody();	// CHANGE

            int str_len = payload.length() + 1;
            char JSONMessage[str_len];
            payload.toCharArray(JSONMessage, str_len);

            StaticJsonDocument<300> JSONDocument; //Memory pool
            DeserializationError err = deserializeJson(JSONDocument, JSONMessage);

            if (err)
            { //Check for errors in parsing
                Serial.println("Parsing failed");
                delay(5000);
                return false;
            }

            const char *pltype = JSONDocument["type"];
            int plversion = JSONDocument["version"];
            const char *plhost = JSONDocument["host"];
            _port = JSONDocument["port"];
            const char *plbin = JSONDocument["bin"];

            String jshost(plhost);
            String jsbin(plbin);

            _host = jshost;
            _bin = jsbin;

            String fwtype(pltype);

            if (plversion > _firwmareVersion && fwtype == _firwmareType)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        else
        {
            // Serial.println("Error on HTTP request");
			Serial.print("Error on HTTP request. Error code:");
			Serial.println(httpCode);
            return false;
        }

        // http.end(); //Free the resources
		http.stop();   // Kevin
        return false;
    }
    return false;
}

String esp32FOTAGSM::getDeviceID()
{
    char deviceid[21];
    uint64_t chipid;
    chipid = ESP.getEfuseMac();
    sprintf(deviceid, "%" PRIu64, chipid);
    String thisID(deviceid);
    return thisID;
}

// Force a firmware update regartless on current version
void esp32FOTAGSM::forceUpdate(String firmwareHost, int firmwarePort, String firmwarePath)
{
    _host = firmwareHost;
    _bin = firmwarePath;
    _port = firmwarePort;
    _retryCount = 3;
    execOTA();
}

void esp32FOTAGSM::setModem(TinyGsm& modem)
{
	_modem = &modem;
}
