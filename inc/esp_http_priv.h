/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef _HTTPD_PRIV_H_
#define _HTTPD_PRIV_H_

#include <stdbool.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <esp_log.h>
#include <esp_err.h>

#include "PredoHttpServer.h"
#include "osal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARSER_BLOCK_SIZE  128

#define HTTPD_SCRATCH_BUF  MAX(HTTPD_MAX_REQ_HDR_LEN, HTTPD_MAX_URI_LEN)

#define LOG_FMT(x)      "%s: " x, __func__

struct thread_data {
    othread_t handle;   //Handle to thread/task
    enum {
        THREAD_IDLE = 0,
        THREAD_RUNNING,
        THREAD_STOPPING,
        THREAD_STOPPED,
    } status;           //State of the thread
};

struct sock_db {
    int fd;                                 //The file descriptor for this socket
    void *ctx;                              //A custom context for this socket
    bool ignore_sess_ctx_changes;           /*!< Flag indicating if session context changes should be ignored */
    httpd_handle_t handle;                  /*!< Server handle */
    httpd_free_ctx_fn_t free_ctx;      /*!< Function for freeing the context */
    httpd_free_ctx_fn_t free_transport_ctx; /*!< Function for freeing the 'transport' context */
    httpd_send_func_t send_fn;              /*!< Send function for this socket */
    httpd_recv_func_t recv_fn;              /*!< Receive function for this socket */
    httpd_pending_func_t pending_fn;        /*!< Pending function for this socket */
    uint64_t lru_counter;                   /*!< LRU Counter indicating when the socket was last used */
    bool lru_socket;                        /*!< Flag indicating LRU socket */
    char pending_data[PARSER_BLOCK_SIZE];   /*!< Buffer for pending data to be received */
    size_t pending_len;                     /*!< Length of pending data to be received */
};

struct httpd_req_aux {
    struct sock_db *sd;                             /*!< Pointer to socket database */
    char            scratch[HTTPD_SCRATCH_BUF + 1]; /*!< Temporary buffer for our operations (1 byte extra for null termination) */
    size_t          remaining_len;                  /*!< Amount of data remaining to be fetched */
    char           *status;                         /*!< HTTP response's status code */
    char           *content_type;                   /*!< HTTP response's content type */
    bool            first_chunk_sent;               /*!< Used to indicate if first chunk sent */
    unsigned        req_hdrs_count;                 /*!< Count of total headers in request packet */
    unsigned        resp_hdrs_count;                /*!< Count of additional headers in response packet */
    struct resp_hdr {
        const char *field;
        const char *value;
    } *resp_hdrs;                                   /*!< Additional headers in response packet */
    struct http_parser_url url_parse_res;           /*!< URL parsing result, used for retrieving URL elements */
};

struct httpd_data {
    httpd_config_t config;                  /*!< HTTPD server configuration */
    int listen_fd;                          /*!< Server listener FD */
    int ctrl_fd;                            /*!< Ctrl message receiver FD */
    int msg_fd;                             /*!< Ctrl message sender FD */
    struct thread_data hd_td;               /*!< Information for the HTTPD thread */
    struct sock_db *hd_sd;                  /*!< The socket database */
    int hd_sd_active_count;                 /*!< The number of the active sockets */
    httpd_uri_t **hd_calls;                 /*!< Registered URI handlers */
    struct httpd_req hd_req;                /*!< The current HTTPD request */
    struct httpd_req_aux hd_req_aux;        /*!< Additional data about the HTTPD request kept unexposed */
    uint64_t lru_counter;                   /*!< LRU counter */
    bool shutdown_complete;                 //will be true after server shutdown is complete
};

/*session functions*/

struct sock_db *http_sess_get_free(struct httpd_data *hd);

void httpd_sess_init(struct httpd_data *hd);

esp_err_t http_sess_new(struct httpd_data *hd, int newfd);

void http_sess_delete(struct httpd_data *hd, struct sock_db *session);

void http_sess_free_ctx(void **ctx, httpd_free_ctx_fn_t free_fn);

bool http_is_sess_available(struct httpd_data *hd);

void http_sess_close_all(struct httpd_data *hd);

/*uri functions*/

esp_err_t httpd_uri(struct httpd_data *hd);

void httpd_unregister_all_uri_handlers(struct httpd_data *hd);

/*req functions*/

esp_err_t httpd_req_new(struct httpd_data *hd, struct sock_db *sd);

esp_err_t httpd_req_delete(struct httpd_data *hd);

esp_err_t http_req_handle_err(httpd_req_t *req, httpd_err_code_t error);

/** End of Group : Parsing
 * @}
 */

/****************** Group : Send/Receive ********************/
/** @name Send and Receive
 * Methods for transmitting and receiving HTTP requests and responses
 * @{
 */

/**
 * @brief   For sending out data in response to an HTTP request.
 *
 * @param[in] req     Pointer to the HTTP request for which the response needs to be sent
 * @param[in] buf     Pointer to the buffer from where the body of the response is taken
 * @param[in] buf_len Length of the buffer
 *
 * @return
 *  - Length of data : if successful
 *  - ESP_FAIL       : if failed
 */
int httpd_send(httpd_req_t *req, const char *buf, size_t buf_len);

/**
 * @brief   For receiving HTTP request data
 *
 * @note    The exposed API httpd_recv() is simply this function with last parameter
 *          set as false. This function is used internally during reception and
 *          processing of a new request. The option to halt after receiving pending
 *          data prevents the server from requesting more data than is needed for
 *          completing a packet in case when all the remaining part of the packet is
 *          in the pending buffer.
 *
 * @param[in]  req    Pointer to new HTTP request which only has the socket descriptor
 * @param[out] buf    Pointer to the buffer which will be filled with the received data
 * @param[in] buf_len Length of the buffer
 * @param[in] halt_after_pending When set true, halts immediately after receiving from
 *                               pending buffer
 *
 * @return
 *  - Length of data : if successful
 *  - ESP_FAIL       : if failed
 */
int http_recv_with_opt(httpd_req_t *r, char *buf, size_t buf_len, bool halt_after_pending);

/**
 * @brief   For un-receiving HTTP request data
 *
 * This function copies data into internal buffer pending_data so that
 * when httpd_recv is called, it first fetches this pending data and
 * then only starts receiving from the socket
 *
 * @note    If data is too large for the internal buffer then only
 *          part of the data is unreceived, reflected in the returned
 *          length. Make sure that such truncation is checked for and
 *          handled properly.
 *
 * @param[in] req     Pointer to new HTTP request which only has the socket descriptor
 * @param[in] buf     Pointer to the buffer from where data needs to be un-received
 * @param[in] buf_len Length of the buffer
 *
 * @return  Length of data copied into pending buffer
 */
size_t httpd_unrecv(struct httpd_req *r, const char *buf, size_t buf_len);

/**
 * @brief   This is the low level default send function of the HTTPD. This should
 *          NEVER be called directly. The semantics of this is exactly similar to
 *          send() of the BSD socket API.
 *
 * @param[in] hd      Server instance data
 * @param[in] sockfd  Socket descriptor for sending data
 * @param[in] buf     Pointer to the buffer from where the body of the response is taken
 * @param[in] buf_len Length of the buffer
 * @param[in] flags   Flags for mode selection
 *
 * @return
 *  - Length of data : if successful
 *  - -1             : if failed (appropriate errno is set)
 */
int httpd_default_send(httpd_handle_t hd, int sockfd, const char *buf, size_t buf_len, int flags);

/**
 * @brief   This is the low level default recv function of the HTTPD. This should
 *          NEVER be called directly. The semantics of this is exactly similar to
 *          recv() of the BSD socket API.
 *
 * @param[in] hd      Server instance data
 * @param[in] sockfd  Socket descriptor for sending data
 * @param[out] buf    Pointer to the buffer which will be filled with the received data
 * @param[in] buf_len Length of the buffer
 * @param[in] flags   Flags for mode selection
 *
 * @return
 *  - Length of data : if successful
 *  - -1             : if failed (appropriate errno is set)
 */
int httpd_default_recv(httpd_handle_t hd, int sockfd, char *buf, size_t buf_len, int flags);

/** End of Group : Send and Receive
 * @}
 */

/* ************** Group: WebSocket ************** */
/** @name WebSocket
 * Functions for WebSocket header parsing
 * @{
 */


/**
 * @brief   This function is for responding a WebSocket handshake
 *
 * @param[in] req                       Pointer to handshake request that will be handled
 * @param[in] supported_subprotocol     Pointer to the subprotocol supported by this URI
 * @return
 *  - ESP_OK                        : When handshake is sucessful
 *  - ESP_ERR_NOT_FOUND             : When some headers (Sec-WebSocket-*) are not found
 *  - ESP_ERR_INVALID_VERSION       : The WebSocket version is not "13"
 *  - ESP_ERR_INVALID_STATE         : Handshake was done beforehand
 *  - ESP_ERR_INVALID_ARG           : Argument is invalid (null or non-WebSocket)
 *  - ESP_FAIL                      : Socket failures
 */
esp_err_t httpd_ws_respond_server_handshake(httpd_req_t *req, const char *supported_subprotocol);

/**
 * @brief   This function is for getting a frame type
 *          and responding a WebSocket control frame automatically
 *
 * @param[in] req    Pointer to handshake request that will be handled
 * @return
 *  - ESP_OK                        : When handshake is sucessful
 *  - ESP_ERR_INVALID_ARG           : Argument is invalid (null or non-WebSocket)
 *  - ESP_ERR_INVALID_STATE         : Received only some parts of a control frame
 *  - ESP_FAIL                      : Socket failures
 */
esp_err_t httpd_ws_get_frame_type(httpd_req_t *req);

/**
 * @brief   Trigger an httpd session close externally
 *
 * @note    Calling this API is only required in special circumstances wherein
 *          some application requires to close an httpd client session asynchronously.
 *
 * @param[in] handle    Handle to server returned by httpd_start
 * @param[in] session   Session to be closed
 *
 * @return
 *  - ESP_OK    : On successfully initiating closure
 *  - ESP_FAIL  : Failure to queue work
 *  - ESP_ERR_NOT_FOUND   : Socket fd not found
 *  - ESP_ERR_INVALID_ARG : Null arguments
 */
esp_err_t httpd_sess_trigger_close_(httpd_handle_t handle, struct sock_db *session);

/** End of WebSocket related functions
 * @}
 */

void httpd_sess_close(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* ! _HTTPD_PRIV_H_ */
