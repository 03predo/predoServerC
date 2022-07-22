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

/*parsing functions*/

//int httpd_send(httpd_req_t *req, const char *buf, size_t buf_len);

int http_recv_with_opt(httpd_req_t *r, char *buf, size_t buf_len, bool halt_after_pending);

size_t http_unrecv(struct httpd_req *r, const char *buf, size_t buf_len);

//int httpd_default_send(httpd_handle_t hd, int sockfd, const char *buf, size_t buf_len, int flags);

//int httpd_default_recv(httpd_handle_t hd, int sockfd, char *buf, size_t buf_len, int flags);

//esp_err_t httpd_ws_respond_server_handshake(httpd_req_t *req, const char *supported_subprotocol);

//esp_err_t httpd_ws_get_frame_type(httpd_req_t *req);

//esp_err_t httpd_sess_trigger_close_(httpd_handle_t handle, struct sock_db *session);

void httpd_sess_close(void *arg);

#endif /* ! _HTTPD_PRIV_H_ */
