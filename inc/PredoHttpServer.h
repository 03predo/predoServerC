#ifndef _ESP_HTTP_SERVER_H_
#define _ESP_HTTP_SERVER_H_

#include <stdio.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <http_parser.h>
#include <sdkconfig.h>
#include <esp_err.h>

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

/* ************** Group: Initialization ************** */
/** @name Initialization
 * APIs related to the Initialization of the web server
 * @{
 */

/**
 * @brief   HTTP Server Instance Handle
 *
 * Every instance of the server will have a unique handle.
 */
typedef void* httpd_handle_t;

/**
 * @brief  Prototype for freeing context data (if any)
 * @param[in] ctx   object to free
 */
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

#define HTTPD_MAX_REQ_HDR_LEN CONFIG_HTTPD_MAX_REQ_HDR_LEN
#define HTTPD_MAX_URI_LEN CONFIG_HTTPD_MAX_URI_LEN

typedef struct httpd_req {
    httpd_handle_t  handle;                     /*!< Handle to server instance */
    int             method;                     /*!< The type of HTTP request, -1 if unsupported method */
    const char      uri[HTTPD_MAX_URI_LEN + 1]; /*!< The URI of this request (1 byte extra for null termination) */
    size_t          content_len;                /*!< Length of the request body */
    void           *aux;                        /*!< Internally used members */
    void *user_ctx; //User context pointer passed during URI registration.
} httpd_req_t;

typedef struct httpd_uri {
    const char       *uri;    /*!< The URI to handle */
    enum http_method    method; /*!< Method supported by the URI */
    esp_err_t (*handler)(httpd_req_t *r);
    void *user_ctx;
} httpd_uri_t;

esp_err_t httpd_register_uri_handler(httpd_handle_t handle,
                                     const httpd_uri_t *uri_handler);


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


/** End of HTTP Error
 * @}
 */

/* ************** Group: TX/RX ************** */
/** @name TX / RX
 * Prototype for HTTPDs low-level send/recv functions
 * @{
 */

#define HTTPD_SOCK_ERR_FAIL      -1
#define HTTPD_SOCK_ERR_INVALID   -2
#define HTTPD_SOCK_ERR_TIMEOUT   -3

/**
 * @brief  Prototype for HTTPDs low-level send function
 *
 * @note   User specified send function must handle errors internally,
 *         depending upon the set value of errno, and return specific
 *         HTTPD_SOCK_ERR_ codes, which will eventually be conveyed as
 *         return value of httpd_send() function
 *
 * @param[in] hd        server instance
 * @param[in] sockfd    session socket file descriptor
 * @param[in] buf       buffer with bytes to send
 * @param[in] buf_len   data size
 * @param[in] flags     flags for the send() function
 * @return
 *  - Bytes : The number of bytes sent successfully
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket send()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket send()
 */
typedef int (*httpd_send_func_t)(httpd_handle_t hd, int sockfd, const char *buf, size_t buf_len, int flags);

/**
 * @brief  Prototype for HTTPDs low-level recv function
 *
 * @note   User specified recv function must handle errors internally,
 *         depending upon the set value of errno, and return specific
 *         HTTPD_SOCK_ERR_ codes, which will eventually be conveyed as
 *         return value of httpd_req_recv() function
 *
 * @param[in] hd        server instance
 * @param[in] sockfd    session socket file descriptor
 * @param[in] buf       buffer with bytes to send
 * @param[in] buf_len   data size
 * @param[in] flags     flags for the send() function
 * @return
 *  - Bytes : The number of bytes received successfully
 *  - 0     : Buffer length parameter is zero / connection closed by peer
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket recv()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket recv()
 */
typedef int (*httpd_recv_func_t)(httpd_handle_t hd, int sockfd, char *buf, size_t buf_len, int flags);

/**
 * @brief  Prototype for HTTPDs low-level "get pending bytes" function
 *
 * @note   User specified pending function must handle errors internally,
 *         depending upon the set value of errno, and return specific
 *         HTTPD_SOCK_ERR_ codes, which will be handled accordingly in
 *         the server task.
 *
 * @param[in] hd       server instance
 * @param[in] sockfd   session socket file descriptor
 * @return
 *  - Bytes : The number of bytes waiting to be received
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket pending()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket pending()
 */
typedef int (*httpd_pending_func_t)(httpd_handle_t hd, int sockfd);

/** End of TX / RX
 * @}
 */

/* ************** Group: Request/Response ************** */
/** @name Request / Response
 * APIs related to the data send/receive by URI handlers.
 * These APIs are supposed to be called only from the context of
 * a URI handler where httpd_req_t* request pointer is valid.
 * @{
 */

/**
 * @brief   Override web server's receive function (by session FD)
 *
 * This function overrides the web server's receive function. This same function is
 * used to read HTTP request packets.
 *
 * @note    This API is supposed to be called either from the context of
 *          - an http session APIs where sockfd is a valid parameter
 *          - a URI handler where sockfd is obtained using httpd_req_to_sockfd()
 *
 * @param[in] hd        HTTPD instance handle
 * @param[in] sockfd    Session socket FD
 * @param[in] recv_func The receive function to be set for this session
 *
 * @return
 *  - ESP_OK : On successfully registering override
 *  - ESP_ERR_INVALID_ARG : Null arguments
 */
esp_err_t httpd_sess_set_recv_override(httpd_handle_t hd, int sockfd, httpd_recv_func_t recv_func);

/**
 * @brief   Override web server's send function (by session FD)
 *
 * This function overrides the web server's send function. This same function is
 * used to send out any response to any HTTP request.
 *
 * @note    This API is supposed to be called either from the context of
 *          - an http session APIs where sockfd is a valid parameter
 *          - a URI handler where sockfd is obtained using httpd_req_to_sockfd()
 *
 * @param[in] hd        HTTPD instance handle
 * @param[in] sockfd    Session socket FD
 * @param[in] send_func The send function to be set for this session
 *
 * @return
 *  - ESP_OK : On successfully registering override
 *  - ESP_ERR_INVALID_ARG : Null arguments
 */
esp_err_t httpd_sess_set_send_override(httpd_handle_t hd, int sockfd, httpd_send_func_t send_func);

/**
 * @brief   Override web server's pending function (by session FD)
 *
 * This function overrides the web server's pending function. This function is
 * used to test for pending bytes in a socket.
 *
 * @note    This API is supposed to be called either from the context of
 *          - an http session APIs where sockfd is a valid parameter
 *          - a URI handler where sockfd is obtained using httpd_req_to_sockfd()
 *
 * @param[in] hd           HTTPD instance handle
 * @param[in] sockfd       Session socket FD
 * @param[in] pending_func The receive function to be set for this session
 *
 * @return
 *  - ESP_OK : On successfully registering override
 *  - ESP_ERR_INVALID_ARG : Null arguments
 */
esp_err_t httpd_sess_set_pending_override(httpd_handle_t hd, int sockfd, httpd_pending_func_t pending_func);

/**
 * @brief   Get the Socket Descriptor from the HTTP request
 *
 * This API will return the socket descriptor of the session for
 * which URI handler was executed on reception of HTTP request.
 * This is useful when user wants to call functions that require
 * session socket fd, from within a URI handler, ie. :
 *      httpd_sess_get_ctx(),
 *      httpd_sess_trigger_close(),
 *      httpd_sess_update_lru_counter().
 *
 * @note    This API is supposed to be called only from the context of
 *          a URI handler where httpd_req_t* request pointer is valid.
 *
 * @param[in] r The request whose socket descriptor should be found
 *
 * @return
 *  - Socket descriptor : The socket descriptor for this request
 *  - -1 : Invalid/NULL request pointer
 */
int httpd_req_to_sockfd(httpd_req_t *r);

/**
 * @brief   API to read content data from the HTTP request
 *
 * This API will read HTTP content data from the HTTP request into
 * provided buffer. Use content_len provided in httpd_req_t structure
 * to know the length of data to be fetched. If content_len is too
 * large for the buffer then user may have to make multiple calls to
 * this function, each time fetching 'buf_len' number of bytes,
 * while the pointer to content data is incremented internally by
 * the same number.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - If an error is returned, the URI handler must further return an error.
 *    This will ensure that the erroneous socket is closed and cleaned up by
 *    the web server.
 *  - Presently Chunked Encoding is not supported
 *
 * @param[in] r         The request being responded to
 * @param[in] buf       Pointer to a buffer that the data will be read into
 * @param[in] buf_len   Length of the buffer
 *
 * @return
 *  - Bytes : Number of bytes read into the buffer successfully
 *  - 0     : Buffer length parameter is zero / connection closed by peer
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket recv()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket recv()
 */
int httpd_req_recv(httpd_req_t *r, char *buf, size_t buf_len);

/**
 * @brief   Get the value string of a field from the request headers
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Once httpd_resp_send() API is called all request headers
 *    are purged, so request headers need be copied into separate
 *    buffers if they are required later.
 *  - If output size is greater than input, then the value is truncated,
 *    accompanied by truncation error as return value.
 *  - Use httpd_req_get_hdr_value_len() to know the right buffer length
 *
 * @param[in]  r        The request being responded to
 * @param[in]  field    The field to be searched in the header
 * @param[out] val      Pointer to the buffer into which the value will be copied if the field is found
 * @param[in]  val_size Size of the user buffer "val"
 *
 * @return
 *  - ESP_OK : Field found in the request header and value string copied
 *  - ESP_ERR_NOT_FOUND          : Key not found
 *  - ESP_ERR_INVALID_ARG        : Null arguments
 *  - ESP_ERR_HTTPD_INVALID_REQ  : Invalid HTTP request pointer
 *  - ESP_ERR_HTTPD_RESULT_TRUNC : Value string truncated
 */
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r, const char *field, char *val, size_t val_size);

/**
 * @brief   API to send a complete HTTP response.
 *
 * This API will send the data as an HTTP response to the request.
 * This assumes that you have the entire response ready in a single
 * buffer. If you wish to send response in incremental chunks use
 * httpd_resp_send_chunk() instead.
 *
 * If no status code and content-type were set, by default this
 * will send 200 OK status code and content type as text/html.
 * You may call the following functions before this API to configure
 * the response headers :
 *      httpd_resp_set_status() - for setting the HTTP status string,
 *      httpd_resp_set_type()   - for setting the Content Type,
 *      httpd_resp_set_hdr()    - for appending any additional field
 *                                value entries in the response header
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Once this API is called, the request has been responded to.
 *  - No additional data can then be sent for the request.
 *  - Once this API is called, all request headers are purged, so
 *    request headers need be copied into separate buffers if
 *    they are required later.
 *
 * @param[in] r         The request being responded to
 * @param[in] buf       Buffer from where the content is to be fetched
 * @param[in] buf_len   Length of the buffer, HTTPD_RESP_USE_STRLEN to use strlen()
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null request pointer
 *  - ESP_ERR_HTTPD_RESP_HDR    : Essential headers are too large for internal buffer
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request
 */
esp_err_t http_resp_send(httpd_req_t *r, const char *buf, ssize_t buf_len);

/**
 * @brief   API to send one HTTP chunk
 *
 * This API will send the data as an HTTP response to the
 * request. This API will use chunked-encoding and send the response
 * in the form of chunks. If you have the entire response contained in
 * a single buffer, please use httpd_resp_send() instead.
 *
 * If no status code and content-type were set, by default this will
 * send 200 OK status code and content type as text/html. You may
 * call the following functions before this API to configure the
 * response headers
 *      httpd_resp_set_status() - for setting the HTTP status string,
 *      httpd_resp_set_type()   - for setting the Content Type,
 *      httpd_resp_set_hdr()    - for appending any additional field
 *                                value entries in the response header
 *
 * @note
 * - This API is supposed to be called only from the context of
 *   a URI handler where httpd_req_t* request pointer is valid.
 * - When you are finished sending all your chunks, you must call
 *   this function with buf_len as 0.
 * - Once this API is called, all request headers are purged, so
 *   request headers need be copied into separate buffers if they
 *   are required later.
 *
 * @param[in] r         The request being responded to
 * @param[in] buf       Pointer to a buffer that stores the data
 * @param[in] buf_len   Length of the buffer, HTTPD_RESP_USE_STRLEN to use strlen()
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet chunk
 *  - ESP_ERR_INVALID_ARG : Null request pointer
 *  - ESP_ERR_HTTPD_RESP_HDR    : Essential headers are too large for internal buffer
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
esp_err_t httpd_resp_send_chunk(httpd_req_t *r, const char *buf, ssize_t buf_len);

/**
 * @brief   API to send a complete string as HTTP response.
 *
 * This API simply calls http_resp_send with buffer length
 * set to string length assuming the buffer contains a null
 * terminated string
 *
 * @param[in] r         The request being responded to
 * @param[in] str       String to be sent as response body
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null request pointer
 *  - ESP_ERR_HTTPD_RESP_HDR    : Essential headers are too large for internal buffer
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request
 */
static inline esp_err_t httpd_resp_sendstr(httpd_req_t *r, const char *str) {
    return http_resp_send(r, str, (str == NULL) ? 0 : HTTPD_RESP_USE_STRLEN);
}

/**
 * @brief   API to send a string as an HTTP response chunk.
 *
 * This API simply calls http_resp_send_chunk with buffer length
 * set to string length assuming the buffer contains a null
 * terminated string
 *
 * @param[in] r    The request being responded to
 * @param[in] str  String to be sent as response body (NULL to finish response packet)
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null request pointer
 *  - ESP_ERR_HTTPD_RESP_HDR    : Essential headers are too large for internal buffer
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request
 */
static inline esp_err_t httpd_resp_sendstr_chunk(httpd_req_t *r, const char *str) {
    return httpd_resp_send_chunk(r, str, (str == NULL) ? 0 : HTTPD_RESP_USE_STRLEN);
}

/* Some commonly used status codes */
#define HTTPD_200      "200 OK"                     /*!< HTTP Response 200 */
#define HTTPD_204      "204 No Content"             /*!< HTTP Response 204 */
#define HTTPD_207      "207 Multi-Status"           /*!< HTTP Response 207 */
#define HTTPD_400      "400 Bad Request"            /*!< HTTP Response 400 */
#define HTTPD_404      "404 Not Found"              /*!< HTTP Response 404 */
#define HTTPD_408      "408 Request Timeout"        /*!< HTTP Response 408 */
#define HTTPD_500      "500 Internal Server Error"  /*!< HTTP Response 500 */

/**
 * @brief   API to set the HTTP status code
 *
 * This API sets the status of the HTTP response to the value specified.
 * By default, the '200 OK' response is sent as the response.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - This API only sets the status to this value. The status isn't
 *    sent out until any of the send APIs is executed.
 *  - Make sure that the lifetime of the status string is valid till
 *    send function is called.
 *
 * @param[in] r         The request being responded to
 * @param[in] status    The HTTP status code of this response
 *
 * @return
 *  - ESP_OK : On success
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
esp_err_t httpd_resp_set_status(httpd_req_t *r, const char *status);

/* Some commonly used content types */
#define HTTPD_TYPE_JSON   "application/json"            /*!< HTTP Content type JSON */
#define HTTPD_TYPE_TEXT   "text/html"                   /*!< HTTP Content type text/HTML */
#define HTTPD_TYPE_OCTET  "application/octet-stream"    /*!< HTTP Content type octext-stream */

/**
 * @brief   API to set the HTTP content type
 *
 * This API sets the 'Content Type' field of the response.
 * The default content type is 'text/html'.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - This API only sets the content type to this value. The type
 *    isn't sent out until any of the send APIs is executed.
 *  - Make sure that the lifetime of the type string is valid till
 *    send function is called.
 *
 * @param[in] r     The request being responded to
 * @param[in] type  The Content Type of the response
 *
 * @return
 *  - ESP_OK   : On success
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *type);

/**
 * @brief   API to append any additional headers
 *
 * This API sets any additional header fields that need to be sent in the response.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - The header isn't sent out until any of the send APIs is executed.
 *  - The maximum allowed number of additional headers is limited to
 *    value of max_resp_headers in config structure.
 *  - Make sure that the lifetime of the field value strings are valid till
 *    send function is called.
 *
 * @param[in] r     The request being responded to
 * @param[in] field The field name of the HTTP header
 * @param[in] value The value of this HTTP header
 *
 * @return
 *  - ESP_OK : On successfully appending new header
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_RESP_HDR    : Total additional headers exceed max allowed
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
esp_err_t httpd_resp_set_hdr(httpd_req_t *r, const char *field, const char *value);

/**
 * @brief   For sending out error code in response to HTTP request.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Once this API is called, all request headers are purged, so
 *    request headers need be copied into separate buffers if
 *    they are required later.
 *  - If you wish to send additional data in the body of the
 *    response, please use the lower-level functions directly.
 *
 * @param[in] req     Pointer to the HTTP request for which the response needs to be sent
 * @param[in] error   Error type to send
 * @param[in] msg     Error message string (pass NULL for default message)
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
esp_err_t httpd_resp_send_err(httpd_req_t *req, httpd_err_code_t error, const char *msg);

/**
 * @brief   Helper function for HTTP 404
 *
 * Send HTTP 404 message. If you wish to send additional data in the body of the
 * response, please use the lower-level functions directly.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Once this API is called, all request headers are purged, so
 *    request headers need be copied into separate buffers if
 *    they are required later.
 *
 * @param[in] r The request being responded to
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
static inline esp_err_t httpd_resp_send_404(httpd_req_t *r) {
    return httpd_resp_send_err(r, HTTPD_404_NOT_FOUND, NULL);
}

/**
 * @brief   Helper function for HTTP 408
 *
 * Send HTTP 408 message. If you wish to send additional data in the body of the
 * response, please use the lower-level functions directly.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Once this API is called, all request headers are purged, so
 *    request headers need be copied into separate buffers if
 *    they are required later.
 *
 * @param[in] r The request being responded to
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
static inline esp_err_t httpd_resp_send_408(httpd_req_t *r) {
    return httpd_resp_send_err(r, HTTPD_408_REQ_TIMEOUT, NULL);
}

/**
 * @brief   Helper function for HTTP 500
 *
 * Send HTTP 500 message. If you wish to send additional data in the body of the
 * response, please use the lower-level functions directly.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Once this API is called, all request headers are purged, so
 *    request headers need be copied into separate buffers if
 *    they are required later.
 *
 * @param[in] r The request being responded to
 *
 * @return
 *  - ESP_OK : On successfully sending the response packet
 *  - ESP_ERR_INVALID_ARG : Null arguments
 *  - ESP_ERR_HTTPD_RESP_SEND   : Error in raw send
 *  - ESP_ERR_HTTPD_INVALID_REQ : Invalid request pointer
 */
static inline esp_err_t httpd_resp_send_500(httpd_req_t *r) {
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
}

/**
 * @brief   Raw HTTP send
 *
 * Call this API if you wish to construct your custom response packet.
 * When using this, all essential header, eg. HTTP version, Status Code,
 * Content Type and Length, Encoding, etc. will have to be constructed
 * manually, and HTTP delimeters (CRLF) will need to be placed correctly
 * for separating sub-sections of the HTTP response packet.
 *
 * If the send override function is set, this API will end up
 * calling that function eventually to send data out.
 *
 * @note
 *  - This API is supposed to be called only from the context of
 *    a URI handler where httpd_req_t* request pointer is valid.
 *  - Unless the response has the correct HTTP structure (which the
 *    user must now ensure) it is not guaranteed that it will be
 *    recognized by the client. For most cases, you wouldn't have
 *    to call this API, but you would rather use either of :
 *          httpd_resp_send(),
 *          httpd_resp_send_chunk()
 *
 * @param[in] r         The request being responded to
 * @param[in] buf       Buffer from where the fully constructed packet is to be read
 * @param[in] buf_len   Length of the buffer
 *
 * @return
 *  - Bytes : Number of bytes that were sent successfully
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket send()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket send()
 */
int httpd_send(httpd_req_t *r, const char *buf, size_t buf_len);

/**
 * A low level API to send data on a given socket
 *
 * @note This API is not recommended to be used in any request handler.
 * Use this only for advanced use cases, wherein some asynchronous
 * data is to be sent over a socket.
 *
 * This internally calls the default send function, or the function registered by
 * httpd_sess_set_send_override().
 *
 * @param[in] hd        server instance
 * @param[in] sockfd    session socket file descriptor
 * @param[in] buf       buffer with bytes to send
 * @param[in] buf_len   data size
 * @param[in] flags     flags for the send() function
 * @return
 *  - Bytes : The number of bytes sent successfully
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket send()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket send()
 */
int httpd_socket_send(httpd_handle_t hd, int sockfd, const char *buf, size_t buf_len, int flags);

/**
 * A low level API to receive data from a given socket
 *
 * @note This API is not recommended to be used in any request handler.
 * Use this only for advanced use cases, wherein some asynchronous
 * communication is required.
 *
 * This internally calls the default recv function, or the function registered by
 * httpd_sess_set_recv_override().
 *
 * @param[in] hd        server instance
 * @param[in] sockfd    session socket file descriptor
 * @param[in] buf       buffer with bytes to send
 * @param[in] buf_len   data size
 * @param[in] flags     flags for the send() function
 * @return
 *  - Bytes : The number of bytes received successfully
 *  - 0     : Buffer length parameter is zero / connection closed by peer
 *  - HTTPD_SOCK_ERR_INVALID  : Invalid arguments
 *  - HTTPD_SOCK_ERR_TIMEOUT  : Timeout/interrupted while calling socket recv()
 *  - HTTPD_SOCK_ERR_FAIL     : Unrecoverable error while calling socket recv()
 */
int httpd_socket_recv(httpd_handle_t hd, int sockfd, char *buf, size_t buf_len, int flags);

/** End of Request / Response
 * @}
 */

/* ************** Group: Session ************** */
/** @name Session
 * Functions for controlling sessions and accessing context data
 * @{
 */
/**
 * @brief   Update LRU counter for a given socket
 *
 * LRU Counters are internally associated with each session to monitor
 * how recently a session exchanged traffic. When LRU purge is enabled,
 * if a client is requesting for connection but maximum number of
 * sockets/sessions is reached, then the session having the earliest
 * LRU counter is closed automatically.
 *
 * Updating the LRU counter manually prevents the socket from being purged
 * due to the Least Recently Used (LRU) logic, even though it might not
 * have received traffic for some time. This is useful when all open
 * sockets/session are frequently exchanging traffic but the user specifically
 * wants one of the sessions to be kept open, irrespective of when it last
 * exchanged a packet.
 *
 * @note    Calling this API is only necessary if the LRU Purge Enable option
 *          is enabled.
 *
 * @param[in] handle    Handle to server returned by httpd_start
 * @param[in] sockfd    The socket descriptor of the session for which LRU counter
 *                      is to be updated
 *
 * @return
 *  - ESP_OK : Socket found and LRU counter updated
 *  - ESP_ERR_NOT_FOUND   : Socket not found
 *  - ESP_ERR_INVALID_ARG : Null arguments
 */
//esp_err_t httpd_sess_update_lru_counter(httpd_handle_t handle, int sockfd);

/**
 * @brief   Returns list of current socket descriptors of active sessions
 *
 * @param[in] handle    Handle to server returned by httpd_start
 * @param[in,out] fds   In: Size of provided client_fds array
 *                      Out: Number of valid client fds returned in client_fds,
 * @param[out] client_fds  Array of client fds
 *
 * @note Size of provided array has to be equal or greater then maximum number of opened
 *       sockets, configured upon initialization with max_open_sockets field in
 *       httpd_config_t structure.
 *
 * @return
 *  - ESP_OK              : Successfully retrieved session list
 *  - ESP_ERR_INVALID_ARG : Wrong arguments or list is longer than provided array
 */
esp_err_t httpd_get_client_list(httpd_handle_t handle, size_t *fds, int *client_fds);

/** End of Session
 * @}
 */

/* ************** Group: Work Queue ************** */
/** @name Work Queue
 * APIs related to the HTTPD Work Queue
 * @{
 */

/**
 * @brief   Prototype of the HTTPD work function
 *          Please refer to httpd_queue_work() for more details.
 * @param[in] arg   The arguments for this work function
 */
typedef void (*httpd_work_fn_t)(void *arg);

/**
 * @brief   Queue execution of a function in HTTPD's context
 *
 * This API queues a work function for asynchronous execution
 *
 * @note    Some protocols require that the web server generate some asynchronous data
 *          and send it to the persistently opened connection. This facility is for use
 *          by such protocols.
 *
 * @param[in] handle    Handle to server returned by httpd_start
 * @param[in] work      Pointer to the function to be executed in the HTTPD's context
 * @param[in] arg       Pointer to the arguments that should be passed to this function
 *
 * @return
 *  - ESP_OK   : On successfully queueing the work
 *  - ESP_FAIL : Failure in ctrl socket
 *  - ESP_ERR_INVALID_ARG : Null arguments
 */
esp_err_t httpd_queue_work(httpd_handle_t handle, httpd_work_fn_t work, void *arg);

esp_err_t http_queue_shutdown(httpd_handle_t handle);

/** End of Group Work Queue
 * @}
 */

bool http_is_shutdown_complete(httpd_handle_t handle);


#endif /* ! _ESP_HTTP_SERVER_H_ */
