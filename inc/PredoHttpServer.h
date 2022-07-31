#ifndef _ESP_HTTP_SERVER_H_
#define _ESP_HTTP_SERVER_H_

#include <stdio.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <http_parser.h>
#include <sdkconfig.h>
#include <esp_err.h>

#define HTTPD_200      "200 OK"                     /*!< HTTP Response 200 */
#define HTTPD_204      "204 No Content"             /*!< HTTP Response 204 */
#define HTTPD_207      "207 Multi-Status"           /*!< HTTP Response 207 */
#define HTTPD_400      "400 Bad Request"            /*!< HTTP Response 400 */
#define HTTPD_404      "404 Not Found"              /*!< HTTP Response 404 */
#define HTTPD_408      "408 Request Timeout"        /*!< HTTP Response 408 */
#define HTTPD_500      "500 Internal Server Error"  /*!< HTTP Response 500 */

#define HTTPD_TYPE_JSON   "application/json"            /*!< HTTP Content type JSON */
#define HTTPD_TYPE_TEXT   "text/html"                   /*!< HTTP Content type text/HTML */
#define HTTPD_TYPE_OCTET  "application/octet-stream"    /*!< HTTP Content type octext-stream */

#define HTTPD_SOCK_ERR_FAIL      -1
#define HTTPD_SOCK_ERR_INVALID   -2
#define HTTPD_SOCK_ERR_TIMEOUT   -3

#define ESP_ERR_HTTPD_BASE              (0xb000)                    /*!< Starting number of HTTPD error codes */
#define ESP_ERR_HTTPD_HANDLERS_FULL     (ESP_ERR_HTTPD_BASE +  1)   /*!< All slots for registering URI handlers have been consumed */
#define ESP_ERR_HTTPD_HANDLER_EXISTS    (ESP_ERR_HTTPD_BASE +  2)   /*!< URI handler with same method and target URI already registered */
#define ESP_ERR_HTTPD_INVALID_REQ       (ESP_ERR_HTTPD_BASE +  3)   /*!< Invalid request pointer */
#define ESP_ERR_HTTPD_RESULT_TRUNC      (ESP_ERR_HTTPD_BASE +  4)   /*!< Result string truncated */
#define ESP_ERR_HTTPD_RESP_HDR          (ESP_ERR_HTTPD_BASE +  5)   /*!< Response header field larger than supported */
#define ESP_ERR_HTTPD_RESP_SEND         (ESP_ERR_HTTPD_BASE +  6)   /*!< Error occured while sending response packet */
#define ESP_ERR_HTTPD_ALLOC_MEM         (ESP_ERR_HTTPD_BASE +  7)   /*!< Failed to dynamically allocate memory for resource */
#define ESP_ERR_HTTPD_TASK              (ESP_ERR_HTTPD_BASE +  8)   /*!< Failed to launch server task/thread */

#define HTTPD_RESP_USE_STRLEN -1

#define HTTPD_MAX_REQ_HDR_LEN CONFIG_HTTPD_MAX_REQ_HDR_LEN
#define HTTPD_MAX_URI_LEN CONFIG_HTTPD_MAX_URI_LEN

#define HTTPD_DEFAULT_CONFIG() {                        \
        .task_priority      = tskIDLE_PRIORITY+5,       \
        .stack_size         = 4096,                     \
        .core_id            = tskNO_AFFINITY,           \
        .server_port        = 80,                       \
        .ctrl_port          = 32768,                    \
        .max_open_sockets   = 7,                        \
        .max_uri_handlers   = 8,                        \
        .max_resp_headers   = 8,                        \
        .backlog_conn       = 5,                        \
        .lru_purge_enable   = false,                    \
        .recv_wait_timeout  = 5,                        \
        .send_wait_timeout  = 5,                        \
}

typedef void* httpd_handle_t;

typedef void (*httpd_free_ctx_fn_t)(void *ctx);

typedef struct httpd_config {
    unsigned    task_priority;      /*!< Priority of FreeRTOS task which runs the server */
    size_t      stack_size;         /*!< The maximum stack size allowed for the server task */
    BaseType_t  core_id;            /*!< The core the HTTP server task will run on */
    uint16_t    server_port; // tcp port for receiving and transmitting HTTP traffic
    uint16_t    ctrl_port; // UDP Port number for asynchronously exchanging control signals between various components of the server    
    uint16_t    max_open_sockets;   /*!< Max number of sockets/clients connected at any time*/
    uint16_t    max_uri_handlers;   /*!< Maximum allowed uri handlers */
    uint16_t    max_resp_headers;   /*!< Maximum allowed additional headers in HTTP response */
    uint16_t    backlog_conn;       /*!< Number of backlog connections */
    bool        lru_purge_enable;   /*!< Purge "Least Recently Used" connection */
    uint16_t    recv_wait_timeout;  /*!< Timeout for recv function (in seconds)*/
    uint16_t    send_wait_timeout;  /*!< Timeout for send function (in seconds)*/

} httpd_config_t;

esp_err_t  HttpStart(httpd_handle_t *handle, const httpd_config_t *config);

typedef struct httpd_req {
    httpd_handle_t  handle;                     /*!< Handle to server instance */
    int             method;                     /*!< The type of HTTP request, -1 if unsupported method */
    const char      uri[HTTPD_MAX_URI_LEN + 1]; /*!< The URI of this request (1 byte extra for null termination) */
    size_t          content_len;                /*!< Length of the request body */
    const char     *content;
    void           *aux;                        /*!< Internally used members */
    void *user_ctx; //User context pointer passed during URI registration.
} httpd_req_t;

typedef struct httpd_uri {
    const char       *uri;    /*!< The URI to handle */
    enum http_method    method; /*!< Method supported by the URI */
    esp_err_t (*handler)(httpd_req_t *r);
    void *user_ctx;
} httpd_uri_t;

typedef enum {
    HTTPD_500_INTERNAL_SERVER_ERROR = 0,
    HTTPD_501_METHOD_NOT_IMPLEMENTED,
    HTTPD_505_VERSION_NOT_SUPPORTED,
    HTTPD_400_BAD_REQUEST,
    HTTPD_401_UNAUTHORIZED,
    HTTPD_403_FORBIDDEN,
    HTTPD_404_NOT_FOUND,
    HTTPD_405_METHOD_NOT_ALLOWED,
    HTTPD_408_REQ_TIMEOUT,
    HTTPD_411_LENGTH_REQUIRED,
    HTTPD_414_URI_TOO_LONG,
    HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE,
    HTTPD_ERR_CODE_MAX
} httpd_err_code_t;

esp_err_t httpd_register_uri_handler(httpd_handle_t handle, const httpd_uri_t *uri_handler);

esp_err_t http_resp_send(httpd_req_t *r, const char *buf, ssize_t buf_len);

esp_err_t httpd_resp_send_err(httpd_req_t *req, httpd_err_code_t error, const char *msg);

int httpd_send(httpd_req_t *r, const char *buf, size_t buf_len);

typedef void (*httpd_work_fn_t)(void *arg);

esp_err_t httpd_queue_work(httpd_handle_t handle, httpd_work_fn_t work, void *arg);

esp_err_t http_queue_shutdown(httpd_handle_t handle);

bool http_is_shutdown_complete(httpd_handle_t handle);

#endif
