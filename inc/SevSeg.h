#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "esp_task_wdt.h"

#ifndef SEVSEG_H
#define SEVSEG_H

#define PIN_A   5
#define PIN_B   19
#define PIN_C   18
#define PIN_D   22 
#define PIN_E   23 
#define PIN_F   21
#define PIN_G   3
#define PIN_D1  2
#define PIN_D2  17
#define PIN_D3  5
#define PIN_D4  19


void SevSegInit();

void SevSegSetDigit(int dig, int val);

void SevSegChar(char num);

void SevSegInt(int num);

void SevSegOut(int num);

#endif