#include "main.h"

static const char* TAG = "main";
char buf[500];
static bool server_on = true;


static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    return ESP_OK;
}

static httpd_uri_t predoFavicon = {
    .uri = "/favicon.ico",
    .method = HTTP_GET,
    .handler = favicon_get_handler
};

static esp_err_t predo_get_handler(httpd_req_t *req){

    httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
    lcd_init();
    lcd_send_string("GET REQUEST");
    return ESP_OK;
}

static httpd_uri_t predoServer = {
    .uri = "/predoServer",
    .method = HTTP_GET,
    .handler = predo_get_handler,
    .user_ctx = "PREDO SERVER"
};

static esp_err_t predo_server_stop(httpd_req_t *req){
    httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
    server_on = false;
    return ESP_OK;
}

static httpd_uri_t predoStop = {
    .uri = "/stop",
    .method = HTTP_GET,
    .handler = predo_server_stop,
    .user_ctx = "STOPPING SERVER"
};

void app_main(void){
    esp_log_level_set("main", ESP_LOG_DEBUG);
    esp_log_level_set("httpd", ESP_LOG_DEBUG);
    esp_log_level_set("httpd_sess", ESP_LOG_DEBUG);
    esp_log_level_set("httpd_uri", ESP_LOG_DEBUG);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,
      .format_if_mount_failed = false
    };

    // Use settings defined above to initialize and mount SPIFFS filesystem.
    // Note: esp_vfs_spiffs_register is an all-in-one convenience function.
    ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }

    lcd_gpio_init();
    lcd_init();

    SevSegInit();
    SevSegSetDigit(1, 0);
    SevSegSetDigit(2, 0);
    SevSegSetDigit(3, 0);
    SevSegSetDigit(4, 1);

    unsigned short int status = 0;
    wifi_init_sta(wifi_event_group, &status);

    lcd_put_cur(0, 0);
    if (status == 0) {
        lcd_send_string("CONNECTED");
    }else if(status == 1){
        lcd_send_string("CONECTION FAIL");
    }else{
        lcd_send_string("UNKNOWN");
    }
    
    FILE* f = fopen("/spiffs/index.html", "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open index.html");
        return;
    }

    memset(buf, 0, sizeof(buf));
    fread(buf, 1, sizeof(buf), f);
    fclose(f);

    char http_header[1024] = "HTTP/1.1 200 OK\r\n\n";
    strcat(http_header, buf);

    //create http_data object
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    config.lru_purge_enable = true;
    config.max_open_sockets = 3;
    
    ESP_LOGI(TAG, "testing for jenkins");
    if (HttpStart(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &predoServer);
        httpd_register_uri_handler(server, &predoStop);
        httpd_register_uri_handler(server, &predoFavicon);
        ESP_LOGI(TAG, "Server Started");
        SevSegInt(0);
    }else{
        ESP_LOGI(TAG, "Error starting server!");
        return;
    }
    while(server_on){
        vTaskDelay(100/portTICK_PERIOD_MS);
    }
    for(int k = 30; k > 0; --k){
        ESP_LOGD(TAG, "Stopping in %d seconds", k);
        vTaskDelay(1000/portTICK_PERIOD_MS);
    }
    httpd_stop(server);
    lcd_put_cur(0,0);
    lcd_send_string("SERVER STOPPED");
    return ;
}