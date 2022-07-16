/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <errno.h>
#include <esp_log.h>
#include <esp_err.h>
#include <http_parser.h>

#include <PredoHttpServer.h>
#include "esp_http_priv.h"

static const char *TAG = "httpd_uri";

static bool httpd_uri_match_simple(const char *uri1, const char *uri2, size_t len2)
{
    return strlen(uri1) == len2 &&          // First match lengths
        (strncmp(uri1, uri2, len2) == 0);   // Then match actual URIs
}

static httpd_uri_t* httpd_find_uri_handler(struct httpd_data *hd, const char *uri, size_t uri_len, httpd_method_t method, httpd_err_code_t *err)
{
    if (err) {
        *err = HTTPD_404_NOT_FOUND;
    }

    for (int i = 0; i < hd->config.max_uri_handlers; i++) {
        if (!hd->hd_calls[i]) {
            break;
        }
        ESP_LOGD(TAG, LOG_FMT("[%d] = %s"), i, hd->hd_calls[i]->uri);

        /* Check if custom URI matching function is set,
         * else use simple string compare */
        if (hd->config.uri_match_fn ?
            hd->config.uri_match_fn(hd->hd_calls[i]->uri, uri, uri_len) :
            httpd_uri_match_simple(hd->hd_calls[i]->uri, uri, uri_len)) {
            /* URIs match. Now check if method is supported */
            if (hd->hd_calls[i]->method == method) {
                /* Match found! */
                if (err) {
                    /* Unset any error that may
                     * have been set earlier */
                    *err = 0;
                }
                return hd->hd_calls[i];
            }
            /* URI found but method not allowed.
             * If URI is found later then this
             * error must be set to 0 */
            if (err) {
                *err = HTTPD_405_METHOD_NOT_ALLOWED;
            }
        }
    }
    return NULL;
}

esp_err_t httpd_register_uri_handler(httpd_handle_t handle, const httpd_uri_t *uri_handler)
{
    if (handle == NULL || uri_handler == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    struct httpd_data *hd = (struct httpd_data *) handle;

    /* Make sure another handler with matching URI and method
     * is not already registered. This will also catch cases
     * when a registered URI wildcard pattern already accounts
     * for the new URI being registered */
    if (httpd_find_uri_handler(handle, uri_handler->uri,
                               strlen(uri_handler->uri),
                               uri_handler->method, NULL) != NULL) {
        ESP_LOGW(TAG, LOG_FMT("handler %s with method %d already registered"),
                 uri_handler->uri, uri_handler->method);
        return ESP_ERR_HTTPD_HANDLER_EXISTS;
    }

    for (int i = 0; i < hd->config.max_uri_handlers; i++) {
        if (hd->hd_calls[i] == NULL) {
            hd->hd_calls[i] = malloc(sizeof(httpd_uri_t));
            if (hd->hd_calls[i] == NULL) {
                /* Failed to allocate memory */
                return ESP_ERR_HTTPD_ALLOC_MEM;
            }

            /* Copy URI string */
            hd->hd_calls[i]->uri = strdup(uri_handler->uri);
            if (hd->hd_calls[i]->uri == NULL) {
                /* Failed to allocate memory */
                free(hd->hd_calls[i]);
                return ESP_ERR_HTTPD_ALLOC_MEM;
            }

            /* Copy remaining members */
            hd->hd_calls[i]->method   = uri_handler->method;
            hd->hd_calls[i]->handler  = uri_handler->handler;
            hd->hd_calls[i]->user_ctx = uri_handler->user_ctx;
            ESP_LOGD(TAG, LOG_FMT("[%d] installed %s"), i, uri_handler->uri);
            return ESP_OK;
        }
        ESP_LOGD(TAG, LOG_FMT("[%d] exists %s"), i, hd->hd_calls[i]->uri);
    }
    ESP_LOGW(TAG, LOG_FMT("no slots left for registering handler"));
    return ESP_ERR_HTTPD_HANDLERS_FULL;
}

void httpd_unregister_all_uri_handlers(struct httpd_data *hd)
{
    for (unsigned i = 0; i < hd->config.max_uri_handlers; i++) {
        if (!hd->hd_calls[i]) {
            break;
        }
        ESP_LOGD(TAG, LOG_FMT("[%d] removing %s"), i, hd->hd_calls[i]->uri);

        free((char*)hd->hd_calls[i]->uri);
        free(hd->hd_calls[i]);
        hd->hd_calls[i] = NULL;
    }
}

esp_err_t httpd_uri(struct httpd_data *hd)
{
    httpd_uri_t            *uri = NULL;
    httpd_req_t            *req = &hd->hd_req;
    struct http_parser_url *res = &hd->hd_req_aux.url_parse_res;

    /* For conveying URI not found/method not allowed */
    httpd_err_code_t err = 0;

    ESP_LOGD(TAG, LOG_FMT("request for %s with type %d"), req->uri, req->method);

    /* URL parser result contains offset and length of path string */
    if (res->field_set & (1 << UF_PATH)) {
        uri = httpd_find_uri_handler(hd, req->uri + res->field_data[UF_PATH].off,
                                     res->field_data[UF_PATH].len, req->method, &err);
    }

    /* If URI with method not found, respond with error code */
    if (uri == NULL) {
        switch (err) {
            case HTTPD_404_NOT_FOUND:
                ESP_LOGW(TAG, LOG_FMT("URI '%s' not found"), req->uri);
                return http_req_handle_err(req, HTTPD_404_NOT_FOUND);
            case HTTPD_405_METHOD_NOT_ALLOWED:
                ESP_LOGW(TAG, LOG_FMT("Method '%d' not allowed for URI '%s'"),
                         req->method, req->uri);
                return http_req_handle_err(req, HTTPD_405_METHOD_NOT_ALLOWED);
            default:
                return ESP_FAIL;
        }
    }

    /* Attach user context data (passed during URI registration) into request */
    req->user_ctx = uri->user_ctx;

    /* Invoke handler */
    if (uri->handler(req) != ESP_OK) {
        /* Handler returns error, this socket should be closed */
        ESP_LOGW(TAG, LOG_FMT("uri handler execution failed"));
        return ESP_FAIL;
    }
    return ESP_OK;
}
