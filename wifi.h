
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"

#ifndef WIFI_H
#define WIFI_H

#define WIFI_SSID           "ROLSTON"
#define WIFI_PASS           "rolston11"
#define MAXIMUM_RETRY       5
#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

void wifi_init_sta(EventGroupHandle_t s_wifi_event_group, unsigned short int *status);
void wifi_event_handler(void* s_wifi_event_group, esp_event_base_t event_base, int32_t event_id, void* event_data);
#endif
