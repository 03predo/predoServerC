/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#include <esp_log.h>
#include <esp_err.h>
#include <assert.h>


#include "PredoHttpServer.h"
#include "esp_httpd_priv.h"
#include "ctrl_sock.h"
#include "SevSeg.h"



typedef struct {
    fd_set *fdset;
    struct httpd_data *hd;
} process_session_context_t;

struct httpd_ctrl_data {
    enum httpd_ctrl_msg {
        HTTPD_CTRL_SHUTDOWN,
        HTTPD_CTRL_WORK,
    } hc_msg;
    httpd_work_fn_t hc_work;
    void *hc_work_arg;
};

static const char *TAG = "httpd";

// static void httpd_sess_close(void *arg)
// {
//     struct sock_db *sock_db = (struct sock_db *) arg;
//     if (!sock_db) {
//         return;
//     }

//     if (!sock_db->lru_counter && !sock_db->lru_socket) {
//         ESP_LOGD(TAG, "Skipping session close for %d as it seems to be a race condition", sock_db->fd);
//         return;
//     }
//     sock_db->lru_socket = false;
//     struct httpd_data *hd = (struct httpd_data *) sock_db->handle;
//     httpd_sess_delete(hd, sock_db);
// }

static esp_err_t httpd_accept_conn(struct httpd_data *hd, int listen_fd)
{
    // If no space is available for new session, close the least recently used one 
    struct sock_db *current = hd->hd_sd;
    struct sock_db *end = hd->hd_sd + hd->config.max_open_sockets - 1;
    if (hd->config.lru_purge_enable == true) {
        ESP_LOGD(TAG, LOG_FMT("checking for free sessions"));
        bool free_sess = false;
        while(current <= end){
            if(current->fd < 0){
                free_sess = true;
            }
            current++;
        }
        if (!free_sess) {
            ESP_LOGD(TAG, LOG_FMT("no free sessions, closing least recently used"));
            current = hd->hd_sd;
            end = hd->hd_sd + hd->config.max_open_sockets - 1;
            long long unsigned int lru_counter = UINT64_MAX;
            struct sock_db * lru_session = NULL;
            while(current <= end){
                if (current->fd == -1) {
                    return 0;
                }
                // Check/update lowest lru
                if (current->lru_counter < lru_counter) {
                    lru_counter = current->lru_counter;
                    lru_session = current;
                }
                current++;
            }
            if (!lru_session) {
                return ESP_OK;
            }
            ESP_LOGD(TAG, LOG_FMT("closing session with fd %d"), lru_session->fd);
            lru_session->lru_socket = true;
            if (!lru_session) {
                return ESP_ERR_NOT_FOUND;
            }
            struct httpd_ctrl_data msg = {
                .hc_msg = HTTPD_CTRL_WORK,
                .hc_work = httpd_sess_close,
                .hc_work_arg = lru_session,
            };
            ESP_LOGD(TAG, LOG_FMT("sending work ctrl msg"));
            struct sockaddr_in to_addr;
            to_addr.sin_family = AF_INET;
            to_addr.sin_port = htons(hd->config.ctrl_port);
            inet_aton("127.0.0.1", &to_addr.sin_addr);
            int ret = sendto(hd->msg_fd, &msg, sizeof(msg), 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
            
            if (ret < 0) {
                ESP_LOGW(TAG, LOG_FMT("failed to queue work"));
                return ESP_FAIL;
            }
            return ESP_OK;
        }
        ESP_LOGD(TAG, LOG_FMT("session available, starting to accept"));
    }

    struct sockaddr_in addr_from;
    socklen_t addr_from_len = sizeof(addr_from);
    //accept will create a new socket for the new connection
    //the address of the connecting socket will be stored in addr_from
    int new_fd = accept(listen_fd, (struct sockaddr *)&addr_from, &addr_from_len);
    if (new_fd < 0) {
        ESP_LOGW(TAG, LOG_FMT("error in accept (%d)"), errno);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, LOG_FMT("accepted new fd = %d"), new_fd);

    struct timeval tv;
    //set recv timeout of this fd as per config, how much time 
    //to wait for socket when recving data
    tv.tv_sec = hd->config.recv_wait_timeout;
    tv.tv_usec = 0;
    setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    ESP_LOGD(TAG, LOG_FMT("setting recv timeout to %d"), hd->config.recv_wait_timeout);

    //Set send timeout of this fd as per config, how much time
    //to wait for socket when sending it data
    tv.tv_sec = hd->config.send_wait_timeout;
    tv.tv_usec = 0;
    setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    ESP_LOGD(TAG, LOG_FMT("setting send timeout to %d"), hd->config.recv_wait_timeout);

    //sess_new either confirms a session is already open for the
    //fd or assigns it to an empty session

    //sess_get loops though all sockets in socket database
    //if the socket is in the database a session is already open for it
    ESP_LOGD(TAG, LOG_FMT("checking if fd %d is already in session"), new_fd);
    current = hd->hd_sd;
    while (current <= end) {
        if(current->fd == new_fd){
            ESP_LOGE(TAG, LOG_FMT("session already exists with fd %d"), new_fd);
            close(new_fd);
            return ESP_FAIL;
        }
        current++;
    }
    ESP_LOGD(TAG, LOG_FMT("fd %d not in session"), new_fd);
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
        ESP_LOGD(TAG, LOG_FMT("unable to launch session for fd = %d"), new_fd);
        close(new_fd);
        return ESP_FAIL;
    }
    
    // Clear session data
    ESP_LOGD(TAG, LOG_FMT("clearing old session data"));
    memset(session, 0, sizeof (struct sock_db));
    ESP_LOGD(TAG, LOG_FMT("adding new session data"));
    session->fd = new_fd;
    session->handle = (httpd_handle_t) hd;
    session->send_fn = httpd_default_send;
    session->recv_fn = httpd_default_recv;


    ESP_LOGD(TAG, LOG_FMT("fd %d connection complete"), session->fd);
    // increment number of sessions
    hd->hd_sd_active_count++;
    ESP_LOGD(TAG, LOG_FMT("active sockets: %d"), hd->hd_sd_active_count);
    SevSegInt(hd->hd_sd_active_count);

    
    return ESP_OK;
}

static int fd_is_valid(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

esp_err_t httpd_queue_work(httpd_handle_t handle, httpd_work_fn_t work, void *arg)
{
    if (handle == NULL || work == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    struct httpd_data *hd = (struct httpd_data *) handle;
    struct httpd_ctrl_data msg = {
        .hc_msg = HTTPD_CTRL_WORK,
        .hc_work = work,
        .hc_work_arg = arg,
    };

    int ret = cs_send_to_ctrl_sock(hd->msg_fd, hd->config.ctrl_port, &msg, sizeof(msg));
    if (ret < 0) {
        ESP_LOGW(TAG, LOG_FMT("failed to queue work"));
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t httpd_get_client_list(httpd_handle_t handle, size_t *fds, int *client_fds)
{
    struct httpd_data *hd = (struct httpd_data *) handle;
    if (hd == NULL || fds == NULL || *fds == 0 || client_fds == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t max_fds = *fds;
    *fds = 0;
    for (int i = 0; i < hd->config.max_open_sockets; ++i) {
        if (hd->hd_sd[i].fd != -1) {
            if (*fds < max_fds) {
                client_fds[(*fds)++] = hd->hd_sd[i].fd;
            } else {
                return ESP_ERR_INVALID_ARG;
            }
        }
    }
    return ESP_OK;
}

void *httpd_get_global_user_ctx(httpd_handle_t handle)
{
    return ((struct httpd_data *)handle)->config.global_user_ctx;
}

void *httpd_get_global_transport_ctx(httpd_handle_t handle)
{
    return ((struct httpd_data *)handle)->config.global_transport_ctx;
}

// Called for each session from httpd_server
static int httpd_process_session(struct sock_db *session, void *context)
{
    if ((!session) || (!context)) {
        return 0;
    }

    if (session->fd < 0) {
        return 1;
    }

    process_session_context_t *ctx = (process_session_context_t *)context;
    int fd = session->fd;

    if (FD_ISSET(fd, ctx->fdset) || httpd_sess_pending(ctx->hd, session)) {
        ESP_LOGD(TAG, LOG_FMT("processing socket %d"), fd);
        if (httpd_sess_process(ctx->hd, session) != ESP_OK) {
            httpd_sess_delete(ctx->hd, session); // Delete session
        }
    }
    return 1;
}

/* Manage in-coming connection or data requests */
static esp_err_t httpd_server(struct httpd_data *hd)
{
    ESP_LOGI(TAG, "HTTP SERVER");
    //start by initializing the file descriptor(fd) set, 
    fd_set read_set;
    //FD_ZERO initialized the fd set (read_set) to be empty
    FD_ZERO(&read_set);

    if (hd->config.lru_purge_enable || httpd_sess_get_free(hd)) {
        /* Only listen for new connections if server has capacity to
         * handle more (or when LRU purge is enabled, in which case
         * older connections will be closed) */
        //FD_SET adds the fd (listen_fd) to the fd set (reads_set)
        //listen_fd will be used to listen for new connections to the server
        FD_SET(hd->listen_fd, &read_set);
    }
    //ctrl_fd will be used to send ctrl msgs to server
    //only known ctrl msgs are shutdown and work
    FD_SET(hd->ctrl_fd, &read_set);

    //we now add all fds in database to read_set
    struct sock_db *current = hd->hd_sd;
    struct sock_db *end = hd->hd_sd + hd->config.max_open_sockets - 1;
    int max_fd = -1;
    while(current <= end){
        if(current->fd != -1){
            FD_SET(current->fd, &read_set);
            if(current->fd > max_fd){
                max_fd = current->fd;
            }
        }
        current++;
    }

    //when fds are active they are given an integer identifier
    //when a fd becomes active it will always take the lowest available positive int
    //so if we take the highest fd value that will give us the max number of sockets
    //open at a given time
    int maxfd = MAX(hd->listen_fd, max_fd);
    max_fd = maxfd;
    maxfd = MAX(hd->ctrl_fd, max_fd);

    ESP_LOGD(TAG, LOG_FMT("doing select maxfd+1 = %d"), maxfd + 1);
    //select goes through the first (maxfd + 1) fds in read_set to see
    //if they are ready to be read from, and returns the amount of ready sockets
    //it also modifies read_set to only contain the fds that are ready to read from
    int active_cnt = select(maxfd + 1, &read_set, NULL, NULL, NULL);
    if (active_cnt < 0) {
        ESP_LOGE(TAG, LOG_FMT("error in select (%d)"), errno);
        //delete invalid sess
        current = hd->hd_sd;
        end = hd->hd_sd + hd->config.max_open_sockets - 1;

        while (current <= end) {
            if (!fd_is_valid(current->fd)) {
                ESP_LOGW(TAG, LOG_FMT("Closing invalid socket %d"), current->fd);
                httpd_sess_delete(hd, current);
            }
            current++;
        }
    }

    /* Case0: Do we have a control message? */
    //if ctrl_fd has a message, it will have stayed in read_set after select()
    //FD_ISSET returns true if the fd is in the set and false otherwise
    if (FD_ISSET(hd->ctrl_fd, &read_set)) {
        ESP_LOGD(TAG, LOG_FMT("processing ctrl message"));
        struct httpd_ctrl_data msg;
        //recv will take in the data on ctrl_fd into the buffer msg
        //it returns the length of the message
        int ret = recv(hd->ctrl_fd, &msg, sizeof(msg), 0);
        if (ret <= 0) {
            ESP_LOGW(TAG, LOG_FMT("error in recv (%d)"), errno);
            return ESP_FAIL;
        }
        if (ret != sizeof(msg)) {
            ESP_LOGW(TAG, LOG_FMT("incomplete msg"));
            return ESP_FAIL;
        }

        switch (msg.hc_msg) {
        case HTTPD_CTRL_WORK:
            if (msg.hc_work) {
                ESP_LOGD(TAG, LOG_FMT("work"));
                //the work ctrl message is used for deleting sockets
                //msg.hc_work is a pointer to a function and msg.hc_work_arg
                //is the paramter of the function, see httpd_sess_trigger_close_
                (*msg.hc_work)(msg.hc_work_arg);
            }
            break;
        case HTTPD_CTRL_SHUTDOWN:
            ESP_LOGD(TAG, LOG_FMT("shutdown"));
            hd->hd_td.status = THREAD_STOPPING;
            break;
        default:
            break;
        }
        
        if (hd->hd_td.status == THREAD_STOPPING) {
            ESP_LOGD(TAG, LOG_FMT("stopping thread"));
            return ESP_FAIL;
        }
    }

    /* Case1: Do we have any activity on the current data
     * sessions? */
    process_session_context_t context = {
        .fdset = &read_set,
        .hd = hd
    };
    httpd_sess_enum(hd, httpd_process_session, &context);

    /* Case2: Do we have any incoming connection requests to
     * process? */
    //same as with ctrl msg, if listen_fd has a request
    //it will have stayed in read_set after select, so we
    //check if it is in read_set with FD_ISSET
    if (FD_ISSET(hd->listen_fd, &read_set)) {
        ESP_LOGD(TAG, LOG_FMT("processing listen socket %d"), hd->listen_fd);
        if (httpd_accept_conn(hd, hd->listen_fd) != ESP_OK) {
            ESP_LOGW(TAG, LOG_FMT("error accepting new connection"));
        }
    }
    return ESP_OK;
}

/* The main HTTPD thread */
static void httpd_thread(void *arg)
{
    int ret;
    struct httpd_data *hd = (struct httpd_data *) arg;
    hd->hd_td.status = THREAD_RUNNING;

    ESP_LOGD(TAG, LOG_FMT("web server started"));
    while (1) {
        ret = httpd_server(hd);
        if (ret != ESP_OK) {
            break;
        }
    }

    ESP_LOGD(TAG, LOG_FMT("web server exiting"));
    close(hd->msg_fd);
    cs_free_ctrl_sock(hd->ctrl_fd);
    httpd_sess_close_all(hd);
    close(hd->listen_fd);
    hd->hd_td.status = THREAD_STOPPED;
    httpd_os_thread_delete();
}

static void HttpDelete(struct httpd_data *hd)
{
    struct httpd_req_aux *ra = &hd->hd_req_aux;
    /* Free memory of httpd instance data */
    free(hd->err_handler_fns);
    free(ra->resp_hdrs);
    free(hd->hd_sd);

    /* Free registered URI handlers */
    for (unsigned i = 0; i < hd->config.max_uri_handlers; i++) {
        if (!hd->hd_calls[i]) {
            break;
        }
        ESP_LOGD(TAG, LOG_FMT("[%d] removing %s"), i, hd->hd_calls[i]->uri);

        free((char*)hd->hd_calls[i]->uri);
        free(hd->hd_calls[i]);
        hd->hd_calls[i] = NULL;
    }

    free(hd->hd_calls);
    free(hd);
}

esp_err_t HttpStart(httpd_handle_t *handle, const httpd_config_t *config)
{
    if (handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Sanity check about whether LWIP is configured for providing the
     * maximum number of open sockets sufficient for the server. Though,
     * this check doesn't guarantee that many sockets will actually be
     * available at runtime as other processes may use up some sockets.
     * Note that server also uses 3 sockets for its internal use :
     *     1) listening for new TCP connections
     *     2) for sending control messages over UDP
     *     3) for receiving control messages over UDP
     * So the total number of required sockets is max_open_sockets + 3
     */
    if (CONFIG_LWIP_MAX_SOCKETS < config->max_open_sockets + 3) {
        ESP_LOGE(TAG, "Configuration option max_open_sockets is too large (max allowed %d)\n\t"
                 "Either decrease this or configure LWIP_MAX_SOCKETS to a larger value",
                 CONFIG_LWIP_MAX_SOCKETS - 3);
        return ESP_ERR_INVALID_ARG;
    }

    /* Allocate memory for httpd instance data */
    struct httpd_data *hd = calloc(1, sizeof(struct httpd_data));
    if (!hd) {
        ESP_LOGE(TAG, LOG_FMT("Failed to allocate memory for HTTP server instance"));
        return ESP_ERR_HTTPD_ALLOC_MEM;
    }


    hd->hd_calls = calloc(config->max_uri_handlers, sizeof(httpd_uri_t *));
    //hd_sd is the pointer to the first socket in the socker database
    hd->hd_sd = calloc(config->max_open_sockets, sizeof(struct sock_db));
    struct httpd_req_aux *ra = &hd->hd_req_aux;
    ra->resp_hdrs = calloc(config->max_resp_headers, sizeof(struct resp_hdr));
    hd->err_handler_fns = calloc(HTTPD_ERR_CODE_MAX, sizeof(httpd_err_handler_func_t));

    if((!hd->hd_calls) || (!hd->hd_sd) || (!ra->resp_hdrs) || (!hd->err_handler_fns)){
        if (!hd->hd_calls) {ESP_LOGE(TAG, LOG_FMT("Failed to allocate memory for HTTP URI handlers"));}
        if (!hd->hd_sd) {ESP_LOGE(TAG, LOG_FMT("Failed to allocate memory for HTTP session data"));}
        if (!ra->resp_hdrs) {ESP_LOGE(TAG, LOG_FMT("Failed to allocate memory for HTTP response headers"));}
        if (!hd->err_handler_fns) {ESP_LOGE(TAG, LOG_FMT("Failed to allocate memory for HTTP error handlers"));}

        free(ra->resp_hdrs);
        free(hd->hd_sd);
        free(hd->hd_calls);
        free(hd);
        return ESP_ERR_HTTPD_ALLOC_MEM;
    }
    hd->config = *config;

    //fd will be the socket we listen on for new connections
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ESP_LOGE(TAG, LOG_FMT("error in socket (%d)"), errno);
        return ESP_FAIL;
    }
    struct sockaddr_in serv_addr = {
        .sin_family   = PF_INET,
        .sin_addr     = {
            .s_addr = htonl(INADDR_ANY)
        },
        .sin_port     = htons(hd->config.server_port)
    };
    /* Enable SO_REUSEADDR to allow binding to the same
     * address and port when restarting the server */
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        /* This will fail if CONFIG_LWIP_SO_REUSE is not enabled. But
         * it does not affect the normal working of the HTTP Server */
        ESP_LOGW(TAG, LOG_FMT("error enabling SO_REUSEADDR (%d)"), errno);
    }

    bool sock_err = false;
    //bind the socket to the address
    int ret = bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
        ESP_LOGE(TAG, LOG_FMT("error in bind (%d)"), errno);
        close(fd);
        sock_err = true;
    }

    //listen if any backlog connections
    ret = listen(fd, hd->config.backlog_conn);
    if (ret < 0) {
        ESP_LOGE(TAG, LOG_FMT("error in listen (%d)"), errno);
        close(fd);
        sock_err = true;
    }

    //ctrl socket will listen for ctrl msgs
    int ctrl_fd = cs_create_ctrl_sock(hd->config.ctrl_port);
    if (ctrl_fd < 0) {
        ESP_LOGE(TAG, LOG_FMT("error in creating ctrl socket (%d)"), errno);
        close(fd);
        sock_err = true;
    }

    //msg socket will 
    int msg_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (msg_fd < 0) {
        ESP_LOGE(TAG, LOG_FMT("error in creating msg socket (%d)"), errno);
        close(fd);
        close(ctrl_fd);
        sock_err = true;
    }
    
    if(sock_err){
        HttpDelete(hd);
        return ESP_FAIL;
    }

    hd->listen_fd = fd;
    hd->ctrl_fd = ctrl_fd;
    hd->msg_fd  = msg_fd;

    if((!hd) || (!hd->hd_sd) || (!hd->config.max_open_sockets)) {
        return ESP_FAIL;
    }

    //set all sockets to -1 in socket database
    struct sock_db *current = hd->hd_sd;
    struct sock_db *end = hd->hd_sd + hd->config.max_open_sockets - 1;
    while(current <= end){
        current->fd = -1;
        current->ctx = NULL;
        current++;
    }
    
    if (xTaskCreatePinnedToCore(httpd_thread, "httpd", hd->config.stack_size, hd, hd->config.task_priority, &hd->hd_td.handle, hd->config.core_id) != pdPASS) {
        /* Failed to launch task */
        HttpDelete(hd);
        return ESP_ERR_HTTPD_TASK;
    }

    *handle = (httpd_handle_t *)hd;
    return ESP_OK;
}

esp_err_t httpd_stop(httpd_handle_t handle)
{
    struct httpd_data *hd = (struct httpd_data *) handle;
    if (hd == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    struct httpd_ctrl_data msg;
    memset(&msg, 0, sizeof(msg));
    msg.hc_msg = HTTPD_CTRL_SHUTDOWN;
    int ret = 0;
    if ((ret = cs_send_to_ctrl_sock(hd->msg_fd, hd->config.ctrl_port, &msg, sizeof(msg))) < 0) {
        ESP_LOGE(TAG, "Failed to send shutdown signal err=%d", ret);
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, LOG_FMT("sent control msg to stop server"));
    while (hd->hd_td.status != THREAD_STOPPED) {
        httpd_os_thread_sleep(100);
    }

    /* Release global user context, if not NULL */
    if (hd->config.global_user_ctx) {
        if (hd->config.global_user_ctx_free_fn) {
            hd->config.global_user_ctx_free_fn(hd->config.global_user_ctx);
        } else {
            free(hd->config.global_user_ctx);
        }
        hd->config.global_user_ctx = NULL;
    }

    /* Release global transport context, if not NULL */
    if (hd->config.global_transport_ctx) {
        if (hd->config.global_transport_ctx_free_fn) {
            hd->config.global_transport_ctx_free_fn(hd->config.global_transport_ctx);
        } else {
            free(hd->config.global_transport_ctx);
        }
        hd->config.global_transport_ctx = NULL;
    }

    HttpDelete(hd);
    ESP_LOGI(TAG, LOG_FMT("Server Stopped"));
    return ESP_OK;
}
