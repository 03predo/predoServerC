#include "SevSeg.h"

void SevSegInit(){
    gpio_reset_pin(PIN_A); 
    gpio_reset_pin(PIN_B); 
    gpio_reset_pin(PIN_C); 
    gpio_reset_pin(PIN_D); 
    gpio_reset_pin(PIN_E); 
    gpio_reset_pin(PIN_F);  
    gpio_reset_pin(PIN_G); 
    gpio_reset_pin(PIN_D1); 
    gpio_reset_pin(PIN_D2); 
    gpio_reset_pin(PIN_D3); 
    gpio_reset_pin(PIN_D4); 

    gpio_set_direction(PIN_A, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_B, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_C, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_D, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_E, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_F, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_G, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_D1, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_D2, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_D3, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_D4, GPIO_MODE_OUTPUT);
    
}

void SevSegSetDigit(int dig, int val){

    if(dig == 1){
        val == 1 ? gpio_set_level(PIN_D1, 0) : gpio_set_level(PIN_D1, 1);
    }else if(dig == 2){
        val == 1 ? gpio_set_level(PIN_D2, 0) : gpio_set_level(PIN_D2, 1);
    }else if(dig == 3){
        val == 1 ? gpio_set_level(PIN_D3, 0) : gpio_set_level(PIN_D3, 1);
    }else if(dig == 4){
        val == 1 ? gpio_set_level(PIN_D4, 0) : gpio_set_level(PIN_D4, 1);
    }

}

void SevSegChar(char num){
    if(num == '0'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 0);
    }else if(num == '1'){
        gpio_set_level(PIN_A, 0);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 0);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 0);
    }else if(num == '2'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 0);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 1);
    }else if(num == '3'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 1);
    }else if(num == '4'){
        gpio_set_level(PIN_A, 0);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 0);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == '5'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 0);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == '6'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 0);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == '7'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 0);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 0);
    }else if(num == '8'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == '9'){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }
}

void SevSegInt(int num){
    if(num == 0){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 0);
    }else if(num == 1){
        gpio_set_level(PIN_A, 0);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 0);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 0);
    }else if(num == 2){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 0);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 1);
    }else if(num == 3){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 1);
    }else if(num == 4){
        gpio_set_level(PIN_A, 0);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 0);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == 5){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 0);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == 6){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 0);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == 7){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 0);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 0);
        gpio_set_level(PIN_G, 0);
    }else if(num == 8){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 1);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }else if(num == 9){
        gpio_set_level(PIN_A, 1);
        gpio_set_level(PIN_B, 1);
        gpio_set_level(PIN_C, 1);
        gpio_set_level(PIN_D, 1);
        gpio_set_level(PIN_E, 0);
        gpio_set_level(PIN_F, 1);
        gpio_set_level(PIN_G, 1);
    }
}


void SevSegOut(int num){
    if(num > 9999){
        SevSegSetDigit(1, 1);
        SevSegChar('0');
        SevSegSetDigit(2, 1);
        SevSegChar('0');
        SevSegSetDigit(3, 1);
        SevSegChar('0');
        SevSegSetDigit(4, 1);
        SevSegChar('0');
    }else{
        char numchar[12];
        sprintf(numchar, "%d", num);  
        int length = strlen(numchar);  
        for(int k = 1; k < length+1; ++k){
            SevSegChar(numchar[length-k]);
            SevSegSetDigit(5-k, 1);
            vTaskDelay(1/portTICK_PERIOD_MS);
            SevSegSetDigit(5-k, 0);
        }
    }
}




