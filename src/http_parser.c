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
#include "esp_httpd_priv.h"
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

/* Run data callback FOR with LEN bytes, returning ER if it fails */
#define CALLBACK_DATA_(FOR, LEN, ER)                                 \
do {                                                                 \
  ESP_LOGD(TAG, LOG_FMT("CALLBACK DATA"));                           \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (FOR##_mark) {                                                  \
    if (LIKELY(settings->on_##FOR)) {                                \
      parser->state = CURRENT_STATE();                               \
      if (UNLIKELY(0 !=                                              \
                   settings->on_##FOR(parser, FOR##_mark, (LEN)))) { \
        SET_ERRNO(HPE_CB_##FOR);                                     \
      }                                                              \
      UPDATE_STATE(parser->state);                                   \
                                                                     \
      /* We either errored above or got paused; get out */           \
      if (UNLIKELY(HTTP_PARSER_ERRNO(parser) != HPE_OK)) {           \
        return (ER);                                                 \
      }                                                              \
    }                                                                \
    FOR##_mark = NULL;                                               \
  }                                                                  \
} while (0)

/* Run the data callback FOR and consume the current byte */
//FOR will be the last part of the function var in settings 
// ie) CALLBACK_DATA(header_field) corresponds to settings->on_header_field
// p - FOR##_mark will become p - header_field_mark which is the length of the header field
// p - data + 1 is for error checking  
#define CALLBACK_DATA(FOR)                                           \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data + 1)

/* Run the data callback FOR and don't consume the current byte */
#define CALLBACK_DATA_NOADVANCE(FOR)                                 \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data)

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


static const char *method_strings[] = 
  {
#define XX(num, name, string) #string, //returns the method strings is a list
  HTTP_METHOD_MAP(XX)                  //of http methods as strings, through some macro wizardry
#undef XX
  };


static char * valid = "!#$%%&\'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz";

/* Tokens as defined by rfc 2616. Also lowercases them.
 *        token       = 1*<any CHAR except CTLs or separators>
 *     separators     = "(" | ")" | "<" | ">" | "@"
 *                    | "," | ";" | ":" | "\" | <">
 *                    | "/" | "[" | "]" | "?" | "="
 *                    | "{" | "}" | SP | HT
 */
// static const char tokens[256] = { 
// /*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
//         0,       0,       0,       0,       0,       0,       0,       0,
// /*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
//         0,       0,       0,       0,       0,       0,       0,       0,
// /*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
//         0,       0,       0,       0,       0,       0,       0,       0,
// /*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
//         0,       0,       0,       0,       0,       0,       0,       0,
// /*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
//         0,      '!',      0,      '#',     '$',     '%',     '&',    '\'',
// /*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
//         0,       0,      '*',     '+',      0,      '-',     '.',      0,
// /*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
//        '0',     '1',     '2',     '3',     '4',     '5',     '6',     '7',
// /*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
//        '8',     '9',      0,       0,       0,       0,       0,       0,
// /*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
//         0,      'a',     'b',     'c',     'd',     'e',     'f',     'g',
// /*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
//        'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
// /*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
//        'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
// /*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
//        'x',     'y',     'z',      0,       0,       0,      '^',     '_',
// /*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
//        '`',     'a',     'b',     'c',     'd',     'e',     'f',     'g',
// /* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
//        'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
// /* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
//        'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
// /* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
//        'x',     'y',     'z',      0,      '|',      0,      '~',       0 };


// static const int8_t unhex[256] =
//   {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   , 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
//   ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
//   };


#if HTTP_PARSER_STRICT
# define T(v) 0
#else
# define T(v) v
#endif

static char * valid_url = "!\"$%%&\'()*+,-./0123456789:;<=>1@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
// static const uint8_t normal_url_char[32] = {
// /*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
//         0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
// /*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
//         0    | T(2)   |   0    |   0    | T(16)  |   0    |   0    |   0,
// /*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
//         0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
// /*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
//         0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
// /*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
//         0    |   2    |   4    |   0    |   16   |   32   |   64   |  128,
// /*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |   0,
// /*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
// /* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
//         1    |   2    |   4    |   8    |   16   |   32   |   64   |   0, };

#undef T

enum state
  { s_dead = 1 /* important that this is > 0 */

  , s_start_req_or_res
  , s_res_or_resp_I /* for ICY URIs */
  , s_res_or_resp_H
  , s_start_res
  , s_res_I         /* for ICY URIs */
  , s_res_IC        /* for ICY URIs */
  , s_res_H
  , s_res_HT
  , s_res_HTT
  , s_res_HTTP
  , s_res_first_http_major
  , s_res_http_major
  , s_res_first_http_minor
  , s_res_http_minor
  , s_res_first_status_code
  , s_res_status_code
  , s_res_status_start
  , s_res_status
  , s_res_line_almost_done

  , s_start_req //21

  , s_req_method //22
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
  , s_req_http_start //35
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
  , s_header_value_discard_ws //47
  , s_header_value_discard_ws_almost_done
  , s_header_value_discard_lws
  , s_header_value_start
  , s_header_value //51
  , s_header_value_lws

  , s_header_almost_done //53

  , s_chunk_size_start
  , s_chunk_size
  , s_chunk_parameters
  , s_chunk_size_almost_done

  , s_headers_almost_done
  , s_headers_done

  /* Important: 's_headers_done' must be the last 'header' state. All
   * states beyond this must be 'body' states. It is used for overflow
   * checking. See the PARSING_HEADER() macro.
   */

  , s_chunk_data
  , s_chunk_data_almost_done
  , s_chunk_data_done

  , s_body_identity
  , s_body_identity_eof

  , s_message_done
  };


#define PARSING_HEADER(state) (state <= s_headers_done)


enum header_states
  { h_general = 0
  , h_C
  , h_CO
  , h_CON

  , h_matching_connection
  , h_matching_proxy_connection
  , h_matching_content_length
  , h_matching_transfer_encoding
  , h_matching_upgrade

  , h_connection
  , h_content_length
  , h_transfer_encoding
  , h_upgrade

  , h_matching_transfer_encoding_chunked
  , h_matching_connection_token_start
  , h_matching_connection_keep_alive
  , h_matching_connection_close
  , h_matching_connection_upgrade
  , h_matching_connection_token

  , h_transfer_encoding_chunked
  , h_connection_keep_alive
  , h_connection_close
  , h_connection_upgrade
  };

enum http_host_state
  {
    s_http_host_dead = 1
  , s_http_userinfo_start
  , s_http_userinfo
  , s_http_host_start
  , s_http_host_v6_start
  , s_http_host
  , s_http_host_v6
  , s_http_host_v6_end
  , s_http_host_v6_zone_start
  , s_http_host_v6_zone
  , s_http_host_port_start
  , s_http_host_port
};

/* Macros for character classes; depends on strict-mode  */
#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))
#define IS_HEX(c)           (IS_NUM(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
  (c) == ';' || (c) == ':' || (c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',')

#define STRICT_TOKEN(c)     (tokens[(unsigned char)c])

#if HTTP_PARSER_STRICT
#define TOKEN(c)            (tokens[(unsigned char)c])
#define IS_URL_CHAR(c)      (BIT_AT(normal_url_char, (unsigned char)c))
#define IS_HOST_CHAR(c)     (IS_ALPHANUM(c) || (c) == '.' || (c) == '-')
#else
#define TOKEN(c)            ((c == ' ') ? ' ' : tokens[(unsigned char)c])
#define IS_URL_CHAR(c)                                                         \
  (BIT_AT(normal_url_char, (unsigned char)c) || ((c) & 0x80))
#define IS_HOST_CHAR(c)                                                        \
  (IS_ALPHANUM(c) || (c) == '.' || (c) == '-' || (c) == '_')
#endif

/**
 * Verify that a char is a valid visible (printable) US-ASCII
 * character or %x80-FF
 **/
#define IS_HEADER_CHAR(ch)                                                     \
  (ch == CR || ch == LF || ch == 9 || ((unsigned char)ch > 31 && ch != 127))

#define start_state (parser->type == HTTP_REQUEST ? s_start_req : s_start_res)


#if HTTP_PARSER_STRICT
# define STRICT_CHECK(cond)                                          \
do {                                                                 \
  if (cond) {                                                        \
    SET_ERRNO(HPE_STRICT);                                           \
    goto error;                                                      \
  }                                                                  \
} while (0)
# define NEW_MESSAGE() (http_should_keep_alive(parser) ? start_state : s_dead)
#else
# define STRICT_CHECK(cond)
# define NEW_MESSAGE() start_state
#endif

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

/* Map errno values to strings for human-readable output */
#define HTTP_STRERROR_GEN(n, s) { "HPE_" #n, s },
static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  HTTP_ERRNO_MAP(HTTP_STRERROR_GEN)
};
#undef HTTP_STRERROR_GEN

int http_message_needs_eof(const http_parser *parser);

/* Our URL parser.
 *
 * This is designed to be shared by http_parser_execute() for URL validation,
 * hence it has a state transition + byte-for-byte interface. In addition, it
 * is meant to be embedded in http_parser_parse_url(), which does the dirty
 * work of turning state transitions URL components for its API.
 *
 * This function should only be invoked with non-space characters. It is
 * assumed that the caller cares about (and can detect) the transition between
 * URL and non-URL states by looking for these.
 */
static enum state
parse_url_char(enum state s, const char ch)
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

size_t http_parser_execute (http_parser *parser,
                            const http_parser_settings *settings,
                            const char *data,
                            size_t len, char * full_req)
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
        parser->header_state = h_general;

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
        parser->header_state = h_general;
        break;
      }
      case s_header_value:
      {
        //parser_state("s_header_value", ch);
        const char* start = p;
        enum header_states h_state = (enum header_states) parser->header_state;
        for (; p != data + len; p++) {
          parser_state("s_header_value", ch);
          ch = *p;
          if (ch == CR) {
            strncat(full_req, header_value_mark, p-header_value_mark+1);
            char nl = '\n';
            strncat(full_req, &nl, 1);
            p_state = (enum state) s_header_almost_done;
            parser->header_state = h_state;
            CALLBACK_DATA(header_value);
            break;
          }

          if (ch == LF) {
            strncat(full_req, header_value_mark, p-header_value_mark+1);
            char nl = '\n';
            strncat(full_req, &nl, 1);
            p_state = (enum state) s_header_almost_done;
            COUNT_HEADER_SIZE(p - start);
            parser->header_state = h_state;
            ESP_LOGI(TAG, "header_field_mark LF: %c", *header_value_mark);
            CALLBACK_DATA_NOADVANCE(header_value);
            REEXECUTE();
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
        parser->header_state = h_state;

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
          CALLBACK_DATA_NOADVANCE(header_value);
          goto reexecute;
        }
      }
      case s_headers_almost_done:
      {
        parser_state("s_headers_almost_done", ch);
        if(ch != LF){
          parser->http_errno = HPE_LF_EXPECTED;
        }

        if (parser->flags & F_TRAILING) {
          /* End of a chunked request */
          p_state = (enum state) s_message_done;
          CALLBACK_NOTIFY_NOADVANCE(chunk_complete);
          goto reexecute;
        }

        /* Cannot use chunked encoding and a content-length header together
           per the HTTP specification. */
        if ((parser->flags & F_CHUNKED) &&
            (parser->flags & F_CONTENTLENGTH)) {
          parser->http_errno = HPE_UNEXPECTED_CONTENT_LENGTH;
          goto error;
        }

        p_state = (enum state) s_headers_done;

        /* Set this here so that on_headers_complete() callbacks can see it */
        parser->upgrade =
          ((parser->flags & (F_UPGRADE | F_CONNECTION_UPGRADE)) ==
           (F_UPGRADE | F_CONNECTION_UPGRADE) ||
           parser->method == HTTP_CONNECT);

        /* Here we call the headers_complete callback. This is somewhat
         * different than other callbacks because if the user returns 1, we
         * will interpret that as saying that this message has no body. This
         * is needed for the annoying case of recieving a response to a HEAD
         * request.
         *
         * We'd like to use CALLBACK_NOTIFY_NOADVANCE() here but we cannot, so
         * we have to simulate it by handling a change in errno below.
         */
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

        REEXECUTE();
      }
      case s_headers_done:
      {
        parser_state("s_headers_done", ch);
        ESP_LOGI(TAG, LOG_FMT("parsed request of length %d\n\n%s"), overall_len, full_req);
        overall_len = 0;
        STRICT_CHECK(ch != LF);
        //UPDATE_STATE(NEW_MESSAGE());
        CALLBACK_NOTIFY(message_complete);
        RETURN((p - data) + 1);
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


/* Does the parser need to see an EOF to find the end of the message? */
int
http_message_needs_eof (const http_parser *parser)
{
  if (parser->type == HTTP_REQUEST) {
    return 0;
  }

  /* See RFC 2616 section 4.4 */
  if (parser->status_code / 100 == 1 || /* 1xx e.g. Continue */
      parser->status_code == 204 ||     /* No Content */
      parser->status_code == 304 ||     /* Not Modified */
      parser->flags & F_SKIPBODY) {     /* response to a HEAD request */
    return 0;
  }

  if ((parser->flags & F_CHUNKED) || parser->content_length != ULLONG_MAX) {
    return 0;
  }

  return 1;
}


int
http_should_keep_alive (const http_parser *parser)
{
  if (parser->http_major > 0 && parser->http_minor > 0) {
    /* HTTP/1.1 */
    if (parser->flags & F_CONNECTION_CLOSE) {
      return 0;
    }
  } else {
    /* HTTP/1.0 or earlier */
    if (!(parser->flags & F_CONNECTION_KEEP_ALIVE)) {
      return 0;
    }
  }

  return !http_message_needs_eof(parser);
}


const char *
http_method_str (enum http_method m)
{
  return ELEM_AT(method_strings, m, "<unknown>");
}


void
http_parser_init (http_parser *parser, enum http_parser_type t)
{
  ESP_LOGD(TAG, LOG_FMT("PARSER INIT"));
  void *data = parser->data; /* preserve application data */
  memset(parser, 0, sizeof(*parser));
  parser->data = data;
  parser->type = t;
  parser->state = (t == HTTP_REQUEST ? s_start_req : (t == HTTP_RESPONSE ? s_start_res : s_start_req_or_res));
  parser->http_errno = HPE_OK;
}

void
http_parser_settings_init(http_parser_settings *settings)
{
  memset(settings, 0, sizeof(*settings));
}

const char *
http_errno_name(enum http_errno err) {
  assert(((size_t) err) < ARRAY_SIZE(http_strerror_tab));
  return http_strerror_tab[err].name;
}

const char *
http_errno_description(enum http_errno err) {
  assert(((size_t) err) < ARRAY_SIZE(http_strerror_tab));
  return http_strerror_tab[err].description;
}

static enum http_host_state
http_parse_host_char(enum http_host_state s, const char ch) {
  switch(s) {
    case s_http_userinfo:
    case s_http_userinfo_start:
      if (ch == '@') {
        return s_http_host_start;
      }

      if (IS_USERINFO_CHAR(ch)) {
        return s_http_userinfo;
      }
      break;

    case s_http_host_start:
      if (ch == '[') {
        return s_http_host_v6_start;
      }

      if (IS_HOST_CHAR(ch)) {
        return s_http_host;
      }

      break;

    case s_http_host:
      if (IS_HOST_CHAR(ch)) {
        return s_http_host;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_end:
      if (ch == ':') {
        return s_http_host_port_start;
      }

      break;

    case s_http_host_v6:
      if (ch == ']') {
        return s_http_host_v6_end;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_start:
      if (IS_HEX(ch) || ch == ':' || ch == '.') {
        return s_http_host_v6;
      }

      if (s == s_http_host_v6 && ch == '%') {
        return s_http_host_v6_zone_start;
      }
      break;

    case s_http_host_v6_zone:
      if (ch == ']') {
        return s_http_host_v6_end;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_zone_start:
      /* RFC 6874 Zone ID consists of 1*( unreserved / pct-encoded) */
      if (IS_ALPHANUM(ch) || ch == '%' || ch == '.' || ch == '-' || ch == '_' ||
          ch == '~') {
        return s_http_host_v6_zone;
      }
      break;

    case s_http_host_port:
    case s_http_host_port_start:
      if (IS_NUM(ch)) {
        return s_http_host_port;
      }

      break;

    default:
      break;
  }
  return s_http_host_dead;
}

static int
http_parse_host(const char * buf, struct http_parser_url *u, int found_at) {
  enum http_host_state s;

  const char *p;
  size_t buflen = u->field_data[UF_HOST].off + u->field_data[UF_HOST].len;

  assert(u->field_set & (1 << UF_HOST));

  u->field_data[UF_HOST].len = 0;

  s = found_at ? s_http_userinfo_start : s_http_host_start;

  for (p = buf + u->field_data[UF_HOST].off; p < buf + buflen; p++) {
    enum http_host_state new_s = http_parse_host_char(s, *p);

    if (new_s == s_http_host_dead) {
      return 1;
    }

    switch(new_s) {
      case s_http_host:
        if (s != s_http_host) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_v6:
        if (s != s_http_host_v6) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_v6_zone_start:
      case s_http_host_v6_zone:
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_port:
        if (s != s_http_host_port) {
          u->field_data[UF_PORT].off = p - buf;
          u->field_data[UF_PORT].len = 0;
          u->field_set |= (1 << UF_PORT);
        }
        u->field_data[UF_PORT].len++;
        break;

      case s_http_userinfo:
        if (s != s_http_userinfo) {
          u->field_data[UF_USERINFO].off = p - buf ;
          u->field_data[UF_USERINFO].len = 0;
          u->field_set |= (1 << UF_USERINFO);
        }
        u->field_data[UF_USERINFO].len++;
        break;

      default:
        break;
    }
    s = new_s;
  }

  /* Make sure we don't end somewhere unexpected */
  switch (s) {
    case s_http_host_start:
    case s_http_host_v6_start:
    case s_http_host_v6:
    case s_http_host_v6_zone_start:
    case s_http_host_v6_zone:
    case s_http_host_port_start:
    case s_http_userinfo:
    case s_http_userinfo_start:
      return 1;
    default:
      break;
  }

  return 0;
}

void
http_parser_url_init(struct http_parser_url *u) {
  memset(u, 0, sizeof(*u));
}

int
http_parser_parse_url(const char *buf, size_t buflen, int is_connect,
                      struct http_parser_url *u)
{
  enum state s;
  const char *p;
  enum http_parser_url_fields uf, old_uf;
  int found_at = 0;

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

void
http_parser_pause(http_parser *parser, int paused) {
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

int
http_body_is_final(const struct http_parser *parser) {
    return parser->state == s_message_done;
}

unsigned long
http_parser_version(void) {
  return HTTP_PARSER_VERSION_MAJOR * 0x10000 |
         HTTP_PARSER_VERSION_MINOR * 0x00100 |
         HTTP_PARSER_VERSION_PATCH * 0x00001;
}
