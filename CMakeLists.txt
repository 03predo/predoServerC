idf_component_register(SRCS "main.c" "wifi.c" "4bitLCD.c" "SevSeg.c" "httpd_main.c" "httpd_parse.c" "httpd_sess.c" "httpd_txrx.c" "httpd_uri.c"
                    INCLUDE_DIRS ".")


spiffs_create_partition_image(storage ../spiffs_image FLASH_IN_PROJECT)