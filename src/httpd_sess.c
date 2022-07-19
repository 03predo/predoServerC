/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <esp_log.h>
#include <esp_err.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "SevSeg.h"
#include <PredoHttpServer.h>
#include "esp_http_priv.h"
#include "ctrl_sock.h"

static const char *TAG = "httpd_sess";

typedef enum {
    HTTPD_TASK_NONE = 0,
    HTTPD_TASK_INIT,            // Init session
    HTTPD_TASK_GET_ACTIVE,      // Get active session (fd!=-1)
    HTTPD_TASK_GET_FREE,        // Get free session slot (fd<0)
    HTTPD_TASK_FIND_FD,         // Find session with specific fd
    HTTPD_TASK_SET_DESCRIPTOR,  // Set descriptor
    HTTPD_TASK_DELETE_INVALID,  // Delete invalid session
    HTTPD_TASK_FIND_LOWEST_LRU, // Find session with lowest lru
    HTTPD_TASK_CLOSE            // Close session
} task_t;

typedef struct {
    task_t task;
    int fd;
    fd_set *fdset;
    int max_fd;
    struct httpd_data *hd;
    uint64_t lru_counter;
    struct sock_db    *session;
} enum_context_t;

void httpd_sess_close(void *arg)
{
    struct sock_db *sock_db = (struct sock_db *) arg;
    if (!sock_db) {
        return;
    }

    if (!sock_db->lru_counter && !sock_db->lru_socket) {
        ESP_LOGD(TAG, "Skipping session close for %d as it seems to be a race condition", sock_db->fd);
        return;
    }
    sock_db->lru_socket = false;
    struct httpd_data *hd = (struct httpd_data *) sock_db->handle;
    http_sess_delete(hd, sock_db);
}

struct sock_db *http_sess_get_free(struct httpd_data *hd)
{
    if ((!hd) || (hd->hd_sd_active_count == hd->config.max_open_sockets)) {
        return NULL;
    }

    struct sock_db *current = hd->hd_sd;
    struct sock_db *end = hd->hd_sd + hd->config.max_open_sockets - 1;
    while(current <= end){
        if(current->fd < 0){
            return current;
        }
        current++;
    }
    return NULL;
}

bool http_is_sess_available(struct httpd_data *hd)
{
    return http_sess_get_free(hd) ? true : false;
}

esp_err_t http_sess_new(struct httpd_data *hd, int newfd)
{
    //sess_get loops though all sockets in socket database
    //if the socket is in the database a session is already open for it
    ESP_LOGD(TAG, LOG_FMT("checking if fd is already in session"));
    struct sock_db *current = hd->hd_sd;
    struct sock_db *end = hd->hd_sd + hd->config.max_open_sockets - 1;

    while (current <= end) {
        if(current->fd == newfd){
            ESP_LOGE(TAG, LOG_FMT("session already exists with fd = %d"), newfd);
            return ESP_FAIL;
        }
        current++;
    }
    ESP_LOGD(TAG, LOG_FMT("fd not in session"));
    //sess_get_free loops through all sockets in database
    //if the socket is negative it is unused and can be used for new connection
    ESP_LOGD(TAG, LOG_FMT("checking for free session"));
    struct sock_db *session = NULL;
    current = hd->hd_sd;
    end = hd->hd_sd + hd->config.max_open_sockets - 1;
    while (current <= end) {
        if(current->fd < 0){
            session = current;
            ESP_LOGD(TAG, LOG_FMT("free session found"));
        }
        current++;
    }
    if (!session) {
        ESP_LOGD(TAG, LOG_FMT("unable to launch session for fd = %d"), newfd);
        return ESP_FAIL;
    }
    
    // Clear session data
    memset(session, 0, sizeof (struct sock_db));
    session->fd = newfd;
    session->handle = (httpd_handle_t) hd;
    session->send_fn = httpd_default_send;
    session->recv_fn = httpd_default_recv;


    // increment number of sessions
    hd->hd_sd_active_count++;
    ESP_LOGI(TAG, LOG_FMT("active sockets: %d"), hd->hd_sd_active_count);
    SevSegInt(hd->hd_sd_active_count);

    return ESP_OK;
}

// void http_sess_free_ctx(void **ctx, httpd_free_ctx_fn_t free_fn)
// {
//     if ((!ctx) || (!*ctx)) {
//         return;
//     }
//     if (free_fn) {
//         free_fn(*ctx);
//     } else {
//         free(*ctx);
//     }
//     *ctx = NULL;
// }

// void http_sess_clear_ctx(struct sock_db *session)
// {
//     if ((!session) || ((!session->ctx))){
//         return;
//     }

//     // free user ctx
//     if (session->ctx) {
//         http_sess_free_ctx(&session->ctx, session->free_ctx);
//         session->free_ctx = NULL;
//     }

// }

void http_sess_delete(struct httpd_data *hd, struct sock_db *session)
{
    if ((!hd) || (!session) || (session->fd < 0)) {
        return;
    }

    ESP_LOGI(TAG, LOG_FMT("deleting session on fd %d"), session->fd);

    // Call close function if defined
    if (hd->config.close_fn) {
        hd->config.close_fn(hd, session->fd);
    } else {
        close(session->fd);
    }

    // clear all contexts
    //http_sess_clear_ctx(session);

    // mark session slot as available
    session->fd = -1;

    // decrement number of sessions
    hd->hd_sd_active_count--;
    ESP_LOGI(TAG, LOG_FMT("active sockets: %d"), hd->hd_sd_active_count);
    SevSegInt(hd->hd_sd_active_count);
    if (!hd->hd_sd_active_count) {
        hd->lru_counter = 0;
    }
}

void http_sess_close_all(struct httpd_data *hd)
{
    if ((!hd) || (!hd->hd_sd) || (!hd->config.max_open_sockets)) {
        return;
    }

    struct sock_db *current = hd->hd_sd;
    struct sock_db *end = hd->hd_sd + hd->config.max_open_sockets - 1;

    while (current <= end) {
        if (current->fd != -1) {
            ESP_LOGD(TAG, LOG_FMT("cleaning up socket %d"), current->fd);
            http_sess_delete(hd, current);
        }
        current++;
    }
}
