/* Based on src/http/ngx_http_parse.c from NGINX copyright Igor Sysoev
 *
 * Additional changes are licensed under the same terms as NGINX and
 * copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "http_parser.h"
#include "esp_http_priv.h"
#include <esp_log.h>
#include <assert.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static const char *TAG = "httpd_parser";

#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif

#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef BIT_AT
# define BIT_AT(a, i)                                                \
  (!!((unsigned int) (a)[(unsigned int) (i) >> 3] &                  \
   (1 << ((unsigned int) (i) & 7))))
#endif

#ifndef ELEM_AT
# define ELEM_AT(a, i, v) ((unsigned int) (i) < ARRAY_SIZE(a) ? (a)[(i)] : (v))
#endif

#define SET_ERRNO(e)                                                 \
do {                                                                 \
  parser->http_errno = (e);                                          \
} while(0)

#define CURRENT_STATE() p_state
#define UPDATE_STATE(V) p_state = (enum state) (V);
#define RETURN(V)                                                    \
do {                                                                 \
  parser->state = CURRENT_STATE();                                   \
  return (V);                                                        \
} while (0);
#define REEXECUTE()                                                  \
  goto reexecute;                                                    \


#ifdef __GNUC__
# define LIKELY(X) __builtin_expect(!!(X), 1)
# define UNLIKELY(X) __builtin_expect(!!(X), 0)
#else
# define LIKELY(X) (X)
# define UNLIKELY(X) (X)
#endif


/* Run the notify callback FOR, returning ER if it fails */
#define CALLBACK_NOTIFY_(FOR, ER)                                    \
do {                                                                 \
  ESP_LOGD(TAG, LOG_FMT("CALLBACK NOTIFY"));                         \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (LIKELY(settings->on_##FOR)) {                                  \
    parser->state = CURRENT_STATE();                                 \
    if (UNLIKELY(0 != settings->on_##FOR(parser))) {                 \
      SET_ERRNO(HPE_CB_##FOR);                                       \
    }                                                                \
    UPDATE_STATE(parser->state);                                     \
                                                                     \
    /* We either errored above or got paused; get out */             \
    if (UNLIKELY(HTTP_PARSER_ERRNO(parser) != HPE_OK)) {             \
      return (ER);                                                   \
    }                                                                \
  }                                                                  \
} while (0)

/* Run the notify callback FOR and consume the current byte */
#define CALLBACK_NOTIFY(FOR)            CALLBACK_NOTIFY_(FOR, p - data + 1)

/* Run the notify callback FOR and don't consume the current byte */
#define CALLBACK_NOTIFY_NOADVANCE(FOR)  CALLBACK_NOTIFY_(FOR, p - data)

/* Set the mark FOR; non-destructive if mark is already set */
#define MARK(FOR)                                                    \
do {                                                                 \
  if (!FOR##_mark) {                                                 \
    FOR##_mark = p;                                                  \
  }                                                                  \
} while (0)

/* Don't allow the total size of the HTTP headers (including the status
 * line) to exceed HTTP_MAX_HEADER_SIZE.  This check is here to protect
 * embedders against denial-of-service attacks where the attacker feeds
 * us a never-ending header that the embedder keeps buffering.
 *
 * This check is arguably the responsibility of embedders but we're doing
 * it on the embedder's behalf because most won't bother and this way we
 * make the web a little safer.  HTTP_MAX_HEADER_SIZE is still far bigger
 * than any reasonable request or response so this should never affect
 * day-to-day operation.
 */
#define COUNT_HEADER_SIZE(V)                                         \
do {                                                                 \
  parser->nread += (V);                                              \
  if (UNLIKELY(parser->nread > (HTTP_MAX_HEADER_SIZE))) {            \
    SET_ERRNO(HPE_HEADER_OVERFLOW);                                  \
    goto error;                                                      \
  }                                                                  \
} while (0)


#define PROXY_CONNECTION "proxy-connection"
#define CONNECTION "connection"
#define CONTENT_LENGTH "content-length"
#define TRANSFER_ENCODING "transfer-encoding"
#define UPGRADE "upgrade"
#define CHUNKED "chunked"
#define KEEP_ALIVE "keep-alive"
#define CLOSE "close"


static char * valid = "!#$%%&\'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz";


static char * valid_url = "!\"$%%&\'()*+,-./0123456789:;<=>1@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

enum state
  { s_dead = 1
  , s_start_req
  , s_req_method
  , s_req_spaces_before_url
  , s_req_schema
  , s_req_schema_slash
  , s_req_schema_slash_slash
  , s_req_server_start
  , s_req_server
  , s_req_server_with_at
  , s_req_path
  , s_req_query_string_start
  , s_req_query_string
  , s_req_fragment_start
  , s_req_fragment 
  , s_req_http_start
  , s_req_http_H
  , s_req_http_HT
  , s_req_http_HTT
  , s_req_http_HTTP
  , s_req_first_http_major
  , s_req_http_major
  , s_req_first_http_minor
  , s_req_http_minor
  , s_req_line_almost_done
  , s_header_field_start
  , s_header_field
  , s_header_value_discard_ws
  , s_header_value_discard_ws_almost_done
  , s_header_value_discard_lws
  , s_header_value_start
  , s_header_value
  , s_header_value_lws
  , s_header_almost_done
  , s_headers_almost_done
  , s_headers_done
  , s_message_done
  };


#define PARSING_HEADER(state) (state <= s_headers_done)

#define CR                  '\r'
#define LF                  '\n'

static void parser_state(char * state, char ch){
  if (ch == ' '){
    ESP_LOGD(TAG, LOG_FMT("state = %s, ch = \' \'"), state);
  }else if(ch == '\r'){
    ESP_LOGD(TAG, LOG_FMT("state = %s, ch = \\r"), state);
  }else if(ch == '\n'){
    ESP_LOGD(TAG, LOG_FMT("state = %s, ch = \\n"), state);
  }else{
    ESP_LOGD(TAG, LOG_FMT("state = %s, ch = %c"), state, ch);
  }
}

static enum state parse_url_char(enum state s, const char ch)
{
  if (ch == ' ' || ch == '\r' || ch == '\n') {
    return s_dead;
  }
  switch (s) {
    case s_req_spaces_before_url:
      if (ch == '/' || ch == '*') {
        return s_req_path;
      }
      break;
    case s_req_path:
      if (memchr(valid_url, ch, 95) != NULL) {
        return s;
      }
      break;
    default:
      break;
  }
  return s_dead;
}

size_t http_parser_execute (http_parser *parser, const http_parser_settings *settings, const char *data, size_t len, char * full_req)
{
  char ch;
  static int overall_len;
  overall_len += len;
  const char *p = data;
  const char *header_field_mark = 0;
  const char *header_value_mark = 0;
  const char *url_mark = 0;
  enum state p_state = (enum state) parser->state;
  /* We're in an error state. Don't bother doing anything. */
  if (parser->http_errno != HPE_OK) return 0;

  if (len == 0) {
    if (p_state == s_start_req){
      return 0;
    }else{
      SET_ERRNO(HPE_INVALID_EOF_STATE);
      return 1;
    }
  }

  //these marks are for callback functions
  if (CURRENT_STATE() == s_header_field) header_field_mark = data;
  if (CURRENT_STATE() == s_header_value) header_value_mark = data;
  if (CURRENT_STATE() == s_req_path) url_mark = data;

  ESP_LOGD(TAG, LOG_FMT("data:\n%s"), data);
  
  for (p=data; p != data + len; p++) {
    ch = *p;
    if (PARSING_HEADER(CURRENT_STATE())) COUNT_HEADER_SIZE(1);

reexecute:
    switch (p_state) {
      case s_start_req:
      {
        parser_state("s_start_req", ch);
        if (ch == CR || ch == LF) break;
        parser->flags = 0;
        parser->content_length = ULLONG_MAX;
        parser->method = (enum http_method) 0;
        parser->index = 1;
        if(ch == 'G'){
          parser->method = HTTP_GET; 
        }else{
          parser->http_errno = HPE_INVALID_METHOD;
          goto error;
        }
        p_state = (enum state)s_req_method;
        break;
      }
      case s_req_method:
      {
        parser_state("s_req_method", ch);
        if (ch == '\0') {
          parser->http_errno = HPE_INVALID_METHOD;
          goto error;
        }

        if (ch == ' ') {
          p_state = (enum state)s_req_spaces_before_url;
        } else if ((parser->index == 1 && ch == 'E') || (parser->index == 2 && ch == 'T')) {
          ++parser->index;
        } else {
          parser->http_errno = HPE_INVALID_METHOD;
          goto error;
        }
        break;
      }
      case s_req_spaces_before_url:
      {
        parser_state("s_req_spaces_before_url", ch);
        if (ch == ' ') break;
        if(!url_mark) url_mark = p;
        if(ch == '/' ){
          p_state = (enum state) s_req_path;
        }else{
          parser->http_errno = HPE_INVALID_URL;
          goto error;
        }
        break;
      }
      case s_req_path:
      {
        parser_state("s_req_path", ch);
        switch (ch) {
          case ' ':
            p_state = (enum state) s_req_http_start;
            parser->state = p_state;
            
            if (0 != settings->on_url(parser, url_mark, p - url_mark)) parser->http_errno = HPE_CB_url;
            if (parser->http_errno != HPE_OK) return (p - data + 1);
            url_mark = NULL;
            p_state = (enum state) parser->state;
            break;
          case CR:
          case LF:
            parser->http_major = 0;
            parser->http_minor = 9;
            p_state = (enum state) (ch == CR) ?  s_req_line_almost_done : s_header_field_start;
            parser->state = p_state;
            if (0 != settings->on_url(parser, url_mark, p - url_mark)) parser->http_errno = HPE_CB_url;
            if (parser->http_errno != HPE_OK) return (p - data + 1);
            url_mark = NULL;
            p_state = (enum state) parser->state;
            break;
          default:
            if (p_state == s_dead) {
              parser->http_errno = HPE_INVALID_URL;
              goto error;
            }
        }
        break;
      }
      case s_req_http_start:
      {
        parser_state("s_req_http_start", ch);
        switch (ch) {
          case 'H':
            p_state = (enum state) s_req_http_H;
            break;
          case ' ':
            break;
          default:
            parser->http_errno = HPE_INVALID_CONSTANT;
            goto error;
        }
        break;
      }
      case s_req_http_H:
      {
        parser_state("s_req_http_H", ch);
        if(ch != 'T'){
          parser->http_errno = HPE_INVALID_CONSTANT;
          goto error;
        }else{
          p_state = (enum state) s_req_http_HT;
        }
        break;
      }
      case s_req_http_HT:
      {
        parser_state("s_req_http_HT", ch);
        if(ch != 'T'){
          parser->http_errno = HPE_INVALID_CONSTANT;
          goto error;
        }else{
          p_state = (enum state) s_req_http_HTT;
        }
        break;
      }
      case s_req_http_HTT:
      {
        parser_state("s_req_http_HTT", ch);
        if(ch != 'P'){
          parser->http_errno = HPE_INVALID_CONSTANT;
          goto error;
        }else{
          p_state = (enum state) s_req_http_HTTP;
        }
        break;
      }
      case s_req_http_HTTP:
      {
        parser_state("s_req_http_HTTP", ch);
        if(ch != '/'){
          parser->http_errno = HPE_INVALID_CONSTANT;
          goto error;
        }else{
          p_state = (enum state) s_req_first_http_major;
        }
        break;
      }
      case s_req_first_http_major:
      {
        parser_state("s_req_first_http_major", ch);
        if (ch < '1' || ch > '9') {
          parser->http_errno = HPE_INVALID_VERSION;
          goto error;
        }
        parser->http_major = ch - '0';
        p_state = (enum state) s_req_http_major;
        break;
      }
      case s_req_http_major:
      {
        parser_state("s_req_http_major", ch);
        if (ch == '.') {
          p_state = (enum state) s_req_first_http_minor;
          break;
        }
        if (ch >= '0' && ch <= '9') {
          parser->http_errno = HPE_INVALID_VERSION;
          goto error;
        }
        parser->http_major *= 10;
        parser->http_major += ch - '0';
        if (parser->http_major > 999) {
          parser->http_errno = HPE_INVALID_VERSION;
          goto error;
        }
        break;
      }
      case s_req_first_http_minor:
      {
        parser_state("s_req_first_http_minor", ch);
        if (!(ch >= '0' && ch <= '9')) {
          parser->http_errno = HPE_INVALID_VERSION;
          goto error;
        }
        parser->http_minor = ch - '0';
        p_state = (enum state) s_req_http_minor;
        break;
      }
      case s_req_http_minor:
      {
        parser_state("s_req_http_minor", ch);
        strncat(full_req, data, p-data+1);
        char nl = '\n';
        strncat(full_req, &nl, 1);
        if (ch == CR) {
          p_state = (enum state) s_req_line_almost_done;
          break;
        }else if (ch == LF) {
          p_state = (enum state) s_header_field_start;
          break;
        }
        if (!(ch >= '0' && ch <= '9')) {
          parser->http_errno = HPE_INVALID_VERSION;
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if (parser->http_minor > 999) {
          parser->http_errno = HPE_INVALID_VERSION;
          goto error;
        }
        break;
      }
      case s_req_line_almost_done:
      {
        parser_state("s_req_line_almost_done", ch);
        if (ch != LF) {
          parser->http_errno = HPE_LF_EXPECTED;
          goto error;
        }
        p_state = (enum state) s_header_field_start;
        break;
      }
      case s_header_field_start:
      {
        parser_state("s_header_field_start", ch);
        if (ch == CR) {
          p_state = (enum state) s_headers_almost_done;
          break;
        }

        if (ch == LF) {
          p_state = (enum state) s_headers_almost_done;
          goto reexecute;;
        }
        
        if (memchr(valid, ch, 77) == NULL) {
          parser->http_errno = HPE_INVALID_HEADER_TOKEN;
          goto error;
        }

        if (!header_field_mark) { header_field_mark = p; }
        parser->index = 0;
        p_state = (enum state) s_header_field;
        break;
      }
      case s_header_field:
      {
        const char* start = p;
        for (; p != data + len; p++) {
          ch = *p;
          parser_state("s_header_field", ch);
          if (memchr(valid, ch, 77) == NULL) {
            strncat(full_req, header_field_mark, p-header_field_mark+1);
            break;
          }

        }

        COUNT_HEADER_SIZE(p - start);

        if (p == data + len) {
          --p;
          break;
        }

        if (ch == ':') {
          p_state = (enum state) s_header_value_start;

          parser->state = p_state;
          if (0 != settings->on_header_field(parser, header_field_mark, p - header_field_mark)){
            parser->http_errno = HPE_CB_header_field;
          }
          //We either errored above or got paused; get out
          if (parser->http_errno != HPE_OK) {
            return (p - data + 1);
          }
          header_field_mark = NULL;
          p_state = (enum state) parser->state;

          break;
        }

        parser->http_errno = HPE_INVALID_HEADER_TOKEN;
        goto error;
      }
      case s_header_value_start:
      {
        parser_state("s_header_value_discard_ws", ch);
        if (ch == ' ' || ch == '\t') break;

        if (ch == CR) {
          p_state = (enum state) s_header_value_discard_ws_almost_done;
          break;
        }

        if (ch == LF) {
          p_state = (enum state) s_header_value_discard_lws;
          break;
        }
        parser_state("s_header_value_start", ch);
        if (!header_value_mark) header_value_mark = p;
        p_state = (enum state) s_header_value;
        parser->index = 0;

        if (memchr(valid, ch, 77) == NULL) {
          parser->http_errno = HPE_INVALID_HEADER_TOKEN;
          goto error;
        }
        break;
      }
      case s_header_value:
      {
        //parser_state("s_header_value", ch);
        const char* start = p;
        for (; p != data + len; p++) {
          parser_state("s_header_value", ch);
          ch = *p;
          if (ch == CR) {
            strncat(full_req, header_value_mark, p-header_value_mark+1);
            char nl = '\n';
            strncat(full_req, &nl, 1);
            p_state = (enum state) s_header_almost_done;
            parser->state = p_state;
            if (0 != settings->on_header_value(parser, header_value_mark, p - header_value_mark)) parser->http_errno = HPE_CB_header_value;
            if (parser->http_errno != HPE_OK) return (p - data + 1);
            p_state = (enum state) parser->state;
            header_value_mark = NULL;
            break;
          }

          if (ch == LF) {
            strncat(full_req, header_value_mark, p-header_value_mark+1);
            char nl = '\n';
            strncat(full_req, &nl, 1);
            p_state = (enum state) s_header_almost_done;
            COUNT_HEADER_SIZE(p - start);
            if (0 != settings->on_header_value(parser, header_value_mark, p - header_value_mark)) parser->http_errno = HPE_CB_header_value;
            if (parser->http_errno != HPE_OK) return (p - data);
            p_state = (enum state) parser->state;
            header_value_mark = NULL;
            goto reexecute;
          }

          const char* p_cr;
          const char* p_lf;
          size_t limit = data + len - p;

          limit = MIN(limit, HTTP_MAX_HEADER_SIZE);

          p_cr = (const char*) memchr(p, CR, limit);
          p_lf = (const char*) memchr(p, LF, limit);
          if (p_cr != NULL) {
            if (p_lf != NULL && p_cr >= p_lf)
              p = p_lf;
            else
              p = p_cr;
          } else if (p_lf != NULL) {
            p = p_lf;
          } else {
            p = data + len;
            strncat(full_req, header_value_mark, p-header_value_mark+1);
          }
          --p;
        }

        COUNT_HEADER_SIZE(p - start);

        if (p == data + len)
          --p;
        break;
      }
      case s_header_almost_done:
      {
        parser_state("s_header_almost_done", ch);
        if (ch != LF) {
          parser->http_errno = HPE_LF_EXPECTED;
          goto error;
        }

        p_state = (enum state) s_header_value_lws;
        break;
      }
      case s_header_value_lws:
      {
        parser_state("s_header_value_lws", ch);
        if (ch == ' ' || ch == '\t') {
          p_state = (enum state) s_header_value_start;
          goto reexecute;
        }

        p_state = (enum state) s_header_field_start;
        goto reexecute;
      }
      case s_header_value_discard_ws_almost_done:
      {
        if(ch != LF){
          parser->http_errno = HPE_LF_EXPECTED;
        }
        p_state = (enum state) s_header_value_discard_lws;
        break;
      }
      case s_header_value_discard_lws:
      {
        if (ch == ' ' || ch == '\t') {
          p_state = (enum state) s_header_value_start;
          break;
        } else {
          if (!header_value_mark) { header_value_mark = p; }
          p_state = (enum state) s_header_field_start;
          if (0 != settings->on_header_value(parser, header_value_mark, p - header_value_mark)) parser->http_errno = HPE_CB_header_value;
          if (parser->http_errno != HPE_OK) return (p - data);
          p_state = (enum state) parser->state;
          header_value_mark = NULL;
          goto reexecute;
        }
      }
      case s_headers_almost_done:
      {
        parser_state("s_headers_almost_done", ch);
        if(ch != LF){
          parser->http_errno = HPE_LF_EXPECTED;
        }

        p_state = (enum state) s_headers_done;
        if (settings->on_headers_complete) {
          switch (settings->on_headers_complete(parser)) {
            case 0:
              break;
            default:
              SET_ERRNO(HPE_CB_headers_complete);
              RETURN(p - data); /* Error */
          }
        }

        if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
          RETURN(p - data);
        }

        goto reexecute;
      }
      case s_headers_done:
      {
        parser_state("s_headers_done", ch);
        ESP_LOGI(TAG, LOG_FMT("parsed request of length %d\n\n%s"), overall_len, full_req);
        overall_len = 0;
        if (ch != '\n'){ SET_ERRNO(HPE_STRICT); goto error;}
        parser->state = CURRENT_STATE();
        if (0 != settings->on_message_complete(parser)) SET_ERRNO(HPE_CB_message_complete);
        p_state = (enum state) (parser->state);
        if (HTTP_PARSER_ERRNO(parser) != HPE_OK) return (p - data + 1);
        parser->state = p_state;
        return ((p - data) + 1);
        break;
      }
      default:
      {
        assert(0 && "unhandled state");
        SET_ERRNO(HPE_INVALID_INTERNAL_STATE);
        goto error;
      }
    }
  }
  parser->state = p_state;
  return (len);

error:
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK) {
    SET_ERRNO(HPE_UNKNOWN);
  }
  parser->state = p_state;
  return (p - data);
}

void http_parser_init (http_parser *parser, enum http_parser_type t)
{
  ESP_LOGD(TAG, LOG_FMT("PARSER INIT"));
  void *data = parser->data; /* preserve application data */
  memset(parser, 0, sizeof(*parser));
  parser->data = data;
  parser->type = t;
  parser->state = s_start_req;
  parser->http_errno = HPE_OK;
}

void http_parser_settings_init(http_parser_settings *settings)
{
  memset(settings, 0, sizeof(*settings));
}

void http_parser_url_init(struct http_parser_url *u) {
  memset(u, 0, sizeof(*u));
}

int http_parser_parse_url(const char *buf, size_t buflen, int is_connect, struct http_parser_url *u)
{
  enum state s;
  const char *p;
  enum http_parser_url_fields uf, old_uf;

  u->port = u->field_set = 0;
  s = is_connect ? s_req_server_start : s_req_spaces_before_url;
  old_uf = UF_MAX;

  for (p = buf; p < buf + buflen; p++) {
    s = parse_url_char(s, *p);

    /* Figure out the next field that we're operating on */
    switch (s) {
      case s_dead:
        return 1;
      case s_req_path:
        uf = UF_PATH;
        break;
      default:
        assert(!"Unexpected state");
        return 1;
    }

    /* Nothing's changed; soldier on */
    if (uf == old_uf) {
      u->field_data[uf].len++;
      continue;
    }
    u->field_data[uf].off = p - buf;
    u->field_data[uf].len = 1;
    u->field_set |= (1 << uf);
    old_uf = uf;
  }

  return 0;
}

void http_parser_pause(http_parser *parser, int paused) {
  /* Users should only be pausing/unpausing a parser that is not in an error
   * state. In non-debug builds, there's not much that we can do about this
   * other than ignore it.
   */
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK ||
      HTTP_PARSER_ERRNO(parser) == HPE_PAUSED) {
    SET_ERRNO((paused) ? HPE_PAUSED : HPE_OK);
  } else {
    assert(0 && "Attempting to pause parser in error state");
  }
}

