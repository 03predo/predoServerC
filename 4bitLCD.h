#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "driver/gpio.h"
#include <rom/ets_sys.h>

#ifndef DECODELCD_H
#define DECODELCD_H

#define RS_PIN 33
#define RW_PIN 25
#define EN_PIN 26
#define D4_PIN 27
#define D5_PIN 14
#define D6_PIN 12
#define D7_PIN 13

void lcd_gpio_init();

void lcd_clear();

void lcd_put_cur(int col, int row);

void lcd_init ();

void lcd_send_string (char *text);

#endif