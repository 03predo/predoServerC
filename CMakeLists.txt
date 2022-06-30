idf_component_register(SRCS "main.c" "src/wifi.c" "src/4bitLCD.c" "src/SevSeg.c" "src/httpd_main.c" "src/httpd_parse.c" "src/httpd_sess.c" "src/httpd_txrx.c" "src/httpd_uri.c" "src/http_parser.c"
                    INCLUDE_DIRS "." "inc")


spiffs_create_partition_image(storage ../spiffs_image FLASH_IN_PROJECT)