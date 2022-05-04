#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include "4bitLCD.h"
#include "wifi.h"
#include "SevSeg.h"

#include <sys/param.h>
#include <errno.h>
#include <esp_log.h>
#include <esp_err.h>
#include <assert.h>

#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_spiffs.h"
#include "mbedtls/md5.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "PredoHttpServer.h"
#include "esp_httpd_priv.h"


EventGroupHandle_t wifi_event_group;