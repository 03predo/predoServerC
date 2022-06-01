#include "4bitLCD.h"


void lcd_gpio_init(){
    gpio_reset_pin(RS_PIN);
    gpio_reset_pin(RW_PIN);
    gpio_reset_pin(EN_PIN);
    gpio_reset_pin(D4_PIN);
    gpio_reset_pin(D5_PIN);
    gpio_reset_pin(D6_PIN);
    gpio_reset_pin(D7_PIN);
    gpio_set_direction(RS_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(RW_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(EN_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(D4_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(D5_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(D6_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(D7_PIN, GPIO_MODE_OUTPUT);   
}

void send_to_lcd(char data, int rs){
    gpio_set_level(RS_PIN, rs);
    gpio_set_level(D7_PIN, ((data>>3)&0x01));
    gpio_set_level(D6_PIN, ((data>>2)&0x01));
    gpio_set_level(D5_PIN, ((data>>1)&0x01));
    gpio_set_level(D4_PIN, ((data>>0)&0x01));
    
    gpio_set_level(EN_PIN, 1);
    ets_delay_us(80);
    gpio_set_level(EN_PIN, 0);
    ets_delay_us(80);
}

void lcd_send_cmd(char cmd){
    char datatosend;

    datatosend = ((cmd>>4)&0x0f);
    send_to_lcd(datatosend, 0);

    datatosend = ((cmd)&0x0f);
    send_to_lcd(datatosend, 0);
}

void lcd_send_data(char data){
    char datatosend;

    datatosend = ((data>>4)&0x0f);
    send_to_lcd(datatosend, 1);

    datatosend = ((data)&0x0f);
    send_to_lcd(datatosend, 1);
}

void lcd_clear(void){
    lcd_send_cmd(0x01);
    vTaskDelay(2/portTICK_PERIOD_MS);
}

void lcd_put_cur(int col, int row)
{
    switch (row)
    {
        case 0:
            col |= 0x80;
            break;
        case 1:
            col |= 0xC0;
            break;
    }

    lcd_send_cmd (col);
}

void lcd_init (void)
{
	// 4 bit initialisation
	lcd_send_cmd (0x20);  // 4bit mode
    vTaskDelay(10/portTICK_PERIOD_MS);
    lcd_send_cmd (0x28);  // 2-line
    vTaskDelay(10/portTICK_PERIOD_MS);
	lcd_send_cmd (0x01);  // clear display
	vTaskDelay(10/portTICK_PERIOD_MS);
	lcd_send_cmd (0x02); // return home
    vTaskDelay(10/portTICK_PERIOD_MS);
    lcd_send_cmd (0x0C); //Display on no cursor
    vTaskDelay(10/portTICK_PERIOD_MS);
	
}

void lcd_send_string (char *text)
{
	int i = 0;
    while(text[i]>0){
        lcd_send_data(text[i]);
        ++i;
    }
}

