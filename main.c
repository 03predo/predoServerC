#include "main.h"

static const char* TAG = "main";
char predoServerHTML[500];
char stopHTML[500];

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

    http_resp_send(req, predoServerHTML, HTTPD_RESP_USE_STRLEN);
    lcd_init();
    lcd_send_string("GET /predoServer");
    return ESP_OK;
}

static httpd_uri_t predoServer = {
    .uri = "/predoServer",
    .method = HTTP_GET,
    .handler = predo_get_handler,
    .user_ctx = "PREDO SERVER"
};

static esp_err_t predo_server_stop(httpd_req_t *req){
    http_resp_send(req, stopHTML, HTTPD_RESP_USE_STRLEN);
    http_queue_shutdown(req->handle);
    return ESP_OK;
}

static httpd_uri_t predoStop = {
    .uri = "/stop",
    .method = HTTP_GET,
    .handler = predo_server_stop,
    .user_ctx = "STOPPING SERVER"
};

void app_main(void){
    // esp_log_level_set("main", ESP_LOG_DEBUG);
    // esp_log_level_set("httpd", ESP_LOG_DEBUG);
    // esp_log_level_set("httpd_sess", ESP_LOG_DEBUG);
    // esp_log_level_set("httpd_uri", ESP_LOG_DEBUG);
    // esp_log_level_set("httpd_parse", ESP_LOG_DEBUG);
    // esp_log_level_set("httpd_parser", ESP_LOG_DEBUG);


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
    
    FILE* f = fopen("/spiffs/predoServer.html", "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open predoServer.html");
        return;
    }
    memset(predoServerHTML, 0, sizeof(predoServerHTML));
    fread(predoServerHTML, 1, sizeof(predoServerHTML), f);
    fclose(f);
    f = fopen("/spiffs/stop.html", "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open stop.html");
        return;
    }
    memset(stopHTML, 0, sizeof(stopHTML));
    fread(stopHTML, 1, sizeof(stopHTML), f);
    fclose(f);


    //create http_data object
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    config.lru_purge_enable = true;
    config.max_open_sockets = 3;

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
    }
    while(!(http_is_shutdown_complete(server))){
        vTaskDelay(100/portTICK_PERIOD_MS);
    }
    ESP_LOGI(TAG, LOG_FMT("server stopped"));
    return;
}