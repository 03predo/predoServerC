/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdlib.h>
#include <sys/param.h>
#include <esp_log.h>
#include <esp_err.h>
#include "http_parser.h"

#include <PredoHttpServer.h>
#include "esp_http_priv.h"
#include "osal.h"

static const char *TAG = "httpd_parse";

typedef struct {
    /* Parser settings for http_parser_execute() */
    http_parser_settings settings;

    /* Request being parsed */
    struct httpd_req *req;

    /* Status of the parser describes the part of the
     * HTTP request packet being processed at any moment.
     */
    enum {
        PARSING_IDLE = 0,
        PARSING_URL,
        PARSING_HDR_FIELD,
        PARSING_HDR_VALUE,
        PARSING_BODY,
        PARSING_COMPLETE,
        PARSING_FAILED
    } status;

    /* Response error code in case of PARSING_FAILED */
    httpd_err_code_t error;

    /* For storing last callback parameters */
    struct {
        const char *at;
        size_t      length;
    } last;

    /* State variables */
    bool   paused;          /*!< Parser is paused */
    size_t pre_parsed;      /*!< Length of data to be skipped while parsing */
    size_t raw_datalen;     /*!< Full length of the raw data in scratch buffer */
} parser_data_t;

static esp_err_t verify_url (http_parser *parser)
{
    parser_data_t *parser_data  = (parser_data_t *) parser->data;
    struct httpd_req *r         = parser_data->req;
    struct httpd_req_aux *ra    = r->aux;
    struct http_parser_url *res = &ra->url_parse_res;

    const char *at = parser_data->last.at;
    size_t  length = parser_data->last.length;

    if ((r->method = parser->method) < 0) {
        ESP_LOGW(TAG, LOG_FMT("HTTP Operation not supported"));
        parser_data->error = HTTPD_501_METHOD_NOT_IMPLEMENTED;
        return ESP_FAIL;
    }

    if (sizeof(r->uri) < (length + 1)) {
        ESP_LOGW(TAG, LOG_FMT("URI length (%d) greater than supported (%d)"),
                 length, sizeof(r->uri));
        parser_data->error = HTTPD_414_URI_TOO_LONG;
        return ESP_FAIL;
    }

    strlcpy((char *)r->uri, at, (length + 1));
    ESP_LOGI(TAG, LOG_FMT("received URI = %s"), r->uri);

    if ((parser->http_major != 1) && (parser->http_minor != 1)) {
        ESP_LOGW(TAG, LOG_FMT("unsupported HTTP version = %d.%d"),
                 parser->http_major, parser->http_minor);
        parser_data->error = HTTPD_505_VERSION_NOT_SUPPORTED;
        return ESP_FAIL;
    }

    http_parser_url_init(res);

    if (http_parser_parse_url(r->uri, strlen(r->uri),
                              r->method == HTTP_CONNECT, res)) {
        ESP_LOGW(TAG, LOG_FMT("http_parser_parse_url failed with errno = %d"),
                              parser->http_errno);
        parser_data->error = HTTPD_400_BAD_REQUEST;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t cb_url(http_parser *parser, const char *at, size_t length)
{
    parser_data_t *parser_data = (parser_data_t *) parser->data;
    if (parser_data->status == PARSING_IDLE) {
        ESP_LOGD(TAG, LOG_FMT("message begin, storing values: at=%p, length=0, status=PARSING_URL"), at);
        parser_data->last.at     = at;
        parser_data->last.length = 0;
        parser_data->status      = PARSING_URL;
    } else if (parser_data->status != PARSING_URL) {
        ESP_LOGE(TAG, LOG_FMT("unexpected state transition"));
        parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, LOG_FMT("processing url = %.*s"), length, at);
    if ((parser_data->last.length += length) > HTTPD_MAX_URI_LEN) {
        ESP_LOGW(TAG, LOG_FMT("URI length (%d) greater than supported (%d)"),
                 parser_data->last.length, HTTPD_MAX_URI_LEN);
        parser_data->error = HTTPD_414_URI_TOO_LONG;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t pause_parsing(http_parser *parser, const char* at)
{
    parser_data_t *parser_data = (parser_data_t *) parser->data;
    struct httpd_req *r        = parser_data->req;
    struct httpd_req_aux *ra   = r->aux;

    /* The length of data that was not parsed due to interruption
     * and hence needs to be read again later for parsing */
    ssize_t unparsed = parser_data->raw_datalen - (at - ra->scratch);
    if (unparsed < 0) {
        ESP_LOGE(TAG, LOG_FMT("parsing beyond valid data = %d"), -unparsed);
        return ESP_ERR_INVALID_STATE;
    }

    /* Push back the un-parsed data into pending buffer for
     * receiving again with http_recv_with_opt() later when
     * read_block() executes */
    if (unparsed && (unparsed != httpd_unrecv(r, at, unparsed))) {
        ESP_LOGE(TAG, LOG_FMT("data too large for un-recv = %d"), unparsed);
        return ESP_FAIL;
    }

    /* Signal http_parser to pause execution and save the maximum
     * possible length, of the yet un-parsed data, that may get
     * parsed before http_parser_execute() returns. This pre_parsed
     * length will be updated then to reflect the actual length
     * that got parsed, and must be skipped when parsing resumes */
    parser_data->pre_parsed = unparsed;
    http_parser_pause(parser, 1);
    parser_data->paused = true;
    ESP_LOGD(TAG, LOG_FMT("paused"));
    return ESP_OK;
}

static size_t continue_parsing(http_parser *parser, size_t length)
{
    parser_data_t *data = (parser_data_t *) parser->data;

    /* Part of the received data may have been parsed earlier
     * so we must skip that before parsing resumes */
    length = MIN(length, data->pre_parsed);
    data->pre_parsed -= length;
    ESP_LOGD(TAG, LOG_FMT("skip pre-parsed data of size = %d"), length);

    http_parser_pause(parser, 0);
    data->paused = false;
    ESP_LOGD(TAG, LOG_FMT("un-paused"));
    return length;
}

static esp_err_t cb_header_field(http_parser *parser, const char *at, size_t length)
{
    //parser holds data about request and parsing
    //at is the address of the start of the header field in data
    //len is the length header field, ie) Host, len is 4
    parser_data_t *parser_data = (parser_data_t *) parser->data;
    struct httpd_req *r        = parser_data->req;
    struct httpd_req_aux *ra   = r->aux;

    if (parser_data->status == PARSING_URL) {
        ESP_LOGD(TAG, LOG_FMT("previous parser status: PARSING URL"));
        if (verify_url(parser) != ESP_OK) {
            parser_data->status = PARSING_FAILED;
            return ESP_FAIL;
        }

        ESP_LOGD(TAG, LOG_FMT("headers begin"));
        parser_data->last.at     = ra->scratch;
        parser_data->last.length = 0;
        parser_data->status      = PARSING_HDR_FIELD;

        if (pause_parsing(parser, at) != ESP_OK) {
            parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
            parser_data->status = PARSING_FAILED;
            return ESP_FAIL;
        }
    } else if (parser_data->status == PARSING_HDR_VALUE) {
        //Overwrite terminator (carriage returns(CR) or line finishes(LF))following last header
        //(key: value) pair with null characters
        char *term_start = (char *)parser_data->last.at + parser_data->last.length;
        memset(term_start, '\0', at - term_start);
        parser_data->last.at     = at;
        parser_data->last.length = 0;
        parser_data->status      = PARSING_HDR_FIELD;
        ra->req_hdrs_count++;
    } else if (parser_data->status != PARSING_HDR_FIELD) {
        ESP_LOGD(TAG, LOG_FMT("NOT PARSING HDR FIELD"));
        ESP_LOGE(TAG, LOG_FMT("unexpected state transition"));
        parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, LOG_FMT("processing field = %.*s"), length, at);
    parser_data->last.length += length;
    return ESP_OK;
}

static esp_err_t cb_header_value(http_parser *parser, const char *at, size_t length)
{
    //http_parser callback on header value in HTTP request.
    //May be invoked ATLEAST once every header value
    parser_data_t *parser_data = (parser_data_t *) parser->data;

    if (parser_data->status == PARSING_HDR_FIELD) {
        ESP_LOGD(TAG, LOG_FMT("HDR_FIELD"));
        parser_data->last.at     = at;
        parser_data->last.length = 0;
        parser_data->status      = PARSING_HDR_VALUE;

        if (length == 0) {
            char *at_adj = (char *)parser_data->last.at;
            //if length is 0, the at is pointing after CRLF and it should be before
            while (*(--at_adj) != ':');
            while (*(++at_adj) == ' ');
            parser_data->last.at = at_adj;
        }
    } else if (parser_data->status != PARSING_HDR_VALUE) {
        ESP_LOGE(TAG, LOG_FMT("unexpected state transition"));
        parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, LOG_FMT("processing value = %.*s"), length, at);
    parser_data->last.length += length;
    return ESP_OK;
}

static esp_err_t cb_headers_complete(http_parser *parser)
{
    parser_data_t *parser_data = (parser_data_t *) parser->data;
    struct httpd_req *r        = parser_data->req;
    struct httpd_req_aux *ra   = r->aux;

    if (parser_data->status == PARSING_URL) {
        ESP_LOGD(TAG, LOG_FMT("no headers"));
        if (verify_url(parser) != ESP_OK) {
            parser_data->status = PARSING_FAILED;
            return ESP_FAIL;
        }
    } else if (parser_data->status == PARSING_HDR_VALUE) {
        char *at = (char *)parser_data->last.at + parser_data->last.length;

        ssize_t remaining_length = parser_data->raw_datalen - (at - ra->scratch);
        if (remaining_length < 2) {
            ESP_LOGE(TAG, LOG_FMT("invalid length of data remaining to be parsed"));
            parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
            parser_data->status = PARSING_FAILED;
            return ESP_FAIL;
        }

        unsigned short remaining_terminators = 2;
        while (remaining_length-- && remaining_terminators) {
            if (*at == '\n') {
                remaining_terminators--;
            }
            /* Overwrite termination characters with null */
            *(at++) = '\0';
        }
        if (remaining_terminators) {
            ESP_LOGE(TAG, LOG_FMT("incomplete termination of headers"));
            parser_data->error = HTTPD_400_BAD_REQUEST;
            parser_data->status = PARSING_FAILED;
            return ESP_FAIL;
        }

        parser_data->last.at = at;
        ra->req_hdrs_count++;
    } else {
        ESP_LOGE(TAG, LOG_FMT("unexpected state transition"));
        parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }

    /* In absence of body/chunked encoding, http_parser sets content_len to -1 */
    r->content_len = ((int)parser->content_length != -1 ?
                      parser->content_length : 0);

    ESP_LOGD(TAG, LOG_FMT("bytes read     = %d"),  parser->nread);
    ESP_LOGD(TAG, LOG_FMT("content length = %zu"), r->content_len);

    parser_data->status = PARSING_BODY;
    ra->remaining_len = r->content_len;
    return ESP_OK;
}

static esp_err_t cb_no_body(http_parser *parser)
{
    parser_data_t *parser_data = (parser_data_t *) parser->data;

    /* Check previous status */
    if (parser_data->status == PARSING_URL) {
        ESP_LOGD(TAG, LOG_FMT("no headers"));
        if (verify_url(parser) != ESP_OK) {
            /* verify_url would already have set the
             * error field of parser data, so only setting
             * status to failed */
            parser_data->status = PARSING_FAILED;
            return ESP_FAIL;
        }
    } else if (parser_data->status != PARSING_BODY) {
        ESP_LOGE(TAG, LOG_FMT("unexpected state transition"));
        parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }

    /* Pause parsing so that if part of another packet
     * is in queue then it doesn't get parsed, which
     * may reset the parser state and cause current
     * request packet to be lost */
    if (pause_parsing(parser, parser_data->last.at) != ESP_OK) {
        parser_data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
        parser_data->status = PARSING_FAILED;
        return ESP_FAIL;
    }

    parser_data->last.at     = 0;
    parser_data->last.length = 0;
    parser_data->status      = PARSING_COMPLETE;
    ESP_LOGD(TAG, LOG_FMT("message complete"));
    return ESP_OK;
}

static int read_block(httpd_req_t *req, size_t offset, size_t length)
{
    struct httpd_req_aux *raux  = req->aux;

    /* Limits the read to scratch buffer size */
    ssize_t buf_len = MIN(length, (sizeof(raux->scratch) - offset));
    if (buf_len <= 0) {
        return 0;
    }

    /* Receive data into buffer. If data is pending (from unrecv) then return
     * immediately after receiving pending data, as pending data may just complete
     * this request packet. */
    int nbytes = http_recv_with_opt(req, raux->scratch + offset, buf_len, true);
    if (nbytes < 0) {
        ESP_LOGD(TAG, LOG_FMT("error in httpd_recv"));
        /* If timeout occurred allow the
         * situation to be handled */
        if (nbytes == HTTPD_SOCK_ERR_TIMEOUT) {
            /* Invoke error handler which may return ESP_OK
             * to signal for retrying call to recv(), else it may
             * return ESP_FAIL to signal for closure of socket */
            return (httpd_req_handle_err(req, HTTPD_408_REQ_TIMEOUT) == ESP_OK) ?
                    HTTPD_SOCK_ERR_TIMEOUT : HTTPD_SOCK_ERR_FAIL;
        }
        /* Some socket error occurred. Return failure
         * to force closure of underlying socket.
         * Error message is not sent as socket may not
         * be valid anymore */
        return HTTPD_SOCK_ERR_FAIL;
    } else if (nbytes == 0) {
        ESP_LOGD(TAG, LOG_FMT("connection closed"));
        /* Connection closed by client so no
         * need to send error response */
        return HTTPD_SOCK_ERR_FAIL;
    }

    ESP_LOGD(TAG, LOG_FMT("received HTTP request block size = %d"), nbytes);
    return nbytes;
}

static int parse_block(http_parser *parser, size_t offset, size_t length, char * full_req)
{
    parser_data_t        *data  = (parser_data_t *)(parser->data);
    httpd_req_t          *req   = data->req;
    struct httpd_req_aux *raux  = req->aux;
    size_t nparsed = 0;

    if (!length) {
        /* Parsing is still happening but nothing to
         * parse means no more space left on buffer,
         * therefore it can be inferred that the
         * request URI/header must be too long */
        ESP_LOGW(TAG, LOG_FMT("request URI/header too long"));
        switch (data->status) {
            case PARSING_URL:
                data->error = HTTPD_414_URI_TOO_LONG;
                break;
            case PARSING_HDR_FIELD:
            case PARSING_HDR_VALUE:
                data->error = HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE;
                break;
            default:
                ESP_LOGE(TAG, LOG_FMT("unexpected state"));
                data->error = HTTPD_500_INTERNAL_SERVER_ERROR;
                break;
        }
        data->status = PARSING_FAILED;
        return -1;
    }

    /* Un-pause the parsing if paused */
    if (data->paused) {
        nparsed = continue_parsing(parser, length);
        length -= nparsed;
        offset += nparsed;
        if (!length) {
            return nparsed;
        }
    }

    /* Execute http_parser */
    nparsed = http_parser_execute(parser, &data->settings,
                                  raux->scratch + offset, length, full_req);

    /* Check state */
    if (data->status == PARSING_FAILED) {
        /* It is expected that the error field of
         * parser data should have been set by now */
        ESP_LOGW(TAG, LOG_FMT("parsing failed"));
        return -1;
    } else if (data->paused) {
        /* Update the value of pre_parsed which was set when
         * pause_parsing() was called. (length - nparsed) is
         * the length of the data that will need to be parsed
         * again later and hence must be deducted from the
         * pre_parsed length */
        data->pre_parsed -= (length - nparsed);
        return 0;
    } else if (nparsed != length) {
        /* http_parser error */
        data->error  = HTTPD_400_BAD_REQUEST;
        data->status = PARSING_FAILED;
        ESP_LOGW(TAG, LOG_FMT("incomplete (%d/%d) with parser error = %d"),
                 nparsed, length, parser->http_errno);
        return -1;
    }

    /* Return with the total length of the request packet
     * that has been parsed till now */
    ESP_LOGD(TAG, LOG_FMT("parsed block size = %d"), offset + nparsed);
    return offset + nparsed;
}

static void parse_init(httpd_req_t *r, http_parser *parser, parser_data_t *data)
{
    /* Initialize parser data */
    memset(data, 0, sizeof(parser_data_t));
    data->req = r;

    /* Initialize parser */
    http_parser_init(parser, HTTP_REQUEST);
    parser->data = (void *)data;

    /* Initialize parser settings */
    http_parser_settings_init(&data->settings);

    /* Set parser callbacks */
    data->settings.on_url              = cb_url;
    data->settings.on_header_field     = cb_header_field;
    data->settings.on_header_value     = cb_header_value;
    data->settings.on_headers_complete = cb_headers_complete;
    data->settings.on_message_complete = cb_no_body;
}

static esp_err_t httpd_parse_req(struct httpd_data *hd)
{
    httpd_req_t *r = &hd->hd_req;
    int blk_len,  offset;
    http_parser   parser;
    parser_data_t parser_data;
    char * full_req = calloc(2048, sizeof(char));
    parse_init(r, &parser, &parser_data);

    /* Set offset to start of scratch buffer */
    offset = 0;
    do {
        // Read block into scratch buffer
        if ((blk_len = read_block(r, offset, PARSER_BLOCK_SIZE)) < 0) {
            if (blk_len == HTTPD_SOCK_ERR_TIMEOUT) {
                continue;
            }
            return ESP_FAIL;
        }
        parser_data.raw_datalen = blk_len + offset;

        if ((offset = parse_block(&parser, offset, blk_len, full_req)) < 0) {
            return httpd_req_handle_err(r, parser_data.error);
        }
    } while (parser_data.status != PARSING_COMPLETE);

    ESP_LOGD(TAG, LOG_FMT("parsing complete"));
    return httpd_uri(hd);
}

static void init_req(httpd_req_t *r, httpd_config_t *config)
{
    r->handle = 0;
    r->method = 0;
    memset((char*)r->uri, 0, sizeof(r->uri));
    r->content_len = 0;
    r->aux = 0;
    r->user_ctx = 0;
    r->sess_ctx = 0;
    r->free_ctx = 0;
    r->ignore_sess_ctx_changes = 0;
}

static void init_req_aux(struct httpd_req_aux *ra, httpd_config_t *config)
{
    ra->sd = 0;
    memset(ra->scratch, 0, sizeof(ra->scratch));
    ra->remaining_len = 0;
    ra->status = 0;
    ra->content_type = 0;
    ra->first_chunk_sent = 0;
    ra->req_hdrs_count = 0;
    ra->resp_hdrs_count = 0;
    memset(ra->resp_hdrs, 0, config->max_resp_headers * sizeof(struct resp_hdr));
}

static void httpd_req_cleanup(httpd_req_t *r)
{
    struct httpd_req_aux *ra = r->aux;

    /* Check if the context has changed and needs to be cleared */
    if ((r->ignore_sess_ctx_changes == false) && (ra->sd->ctx != r->sess_ctx)) {
        http_sess_free_ctx(ra->sd->ctx, ra->sd->free_ctx);
    }

    /* Retrieve session info from the request into the socket database. */
    ra->sd->ctx = r->sess_ctx;
    ra->sd->free_ctx = r->free_ctx;
    ra->sd->ignore_sess_ctx_changes = r->ignore_sess_ctx_changes;

    /* Clear out the request and request_aux structures */
    ra->sd = NULL;
    r->handle = NULL;
    r->aux = NULL;
    r->user_ctx = NULL;
}

esp_err_t httpd_req_new(struct httpd_data *hd, struct sock_db *sd)
{
    //Function that processes incoming TCP data and
    //updates the http request data httpd_req_t
    httpd_req_t *r = &hd->hd_req;
    init_req(r, &hd->config);
    init_req_aux(&hd->hd_req_aux, &hd->config);
    r->handle = hd;
    r->aux = &hd->hd_req_aux;

    /* Associate the request to the socket */
    struct httpd_req_aux *ra = r->aux;
    ra->sd = sd;

    /* Set defaults */
    ra->status = (char *)HTTPD_200;
    ra->content_type = (char *)HTTPD_TYPE_TEXT;
    ra->first_chunk_sent = false;

    /* Copy session info to the request */
    r->sess_ctx = sd->ctx;
    r->free_ctx = sd->free_ctx;
    r->ignore_sess_ctx_changes = sd->ignore_sess_ctx_changes;

    esp_err_t ret;

    /* Parse request */
    ret = httpd_parse_req(hd);
    if (ret != ESP_OK) {
        httpd_req_cleanup(r);
    }
    return ret;
}

esp_err_t httpd_req_delete(struct httpd_data *hd)
{
    //Function that resets the http request data
    httpd_req_t *r = &hd->hd_req;
    struct httpd_req_aux *ra = r->aux;

    /* Finish off reading any pending/leftover data */
    while (ra->remaining_len) {
        /* Any length small enough not to overload the stack, but large
         * enough to finish off the buffers fast */
        char dummy[CONFIG_HTTPD_PURGE_BUF_LEN];
        int recv_len = MIN(sizeof(dummy), ra->remaining_len);
        recv_len = httpd_req_recv(r, dummy, recv_len);
        if (recv_len <= 0) {
            httpd_req_cleanup(r);
            return ESP_FAIL;
        }

        ESP_LOGD(TAG, LOG_FMT("purging data size : %d bytes"), recv_len);
    }

    httpd_req_cleanup(r);
    return ESP_OK;
}