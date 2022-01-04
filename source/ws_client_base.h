/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2019 Jan Jongboom
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _MBED_WS_WS_REQUEST_BASE_H_
#define _MBED_WS_WS_REQUEST_BASE_H_

#include "mbed.h"
#include "Socket.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "randLIB.h"

#ifdef MBED_WS_HAS_MBED_HTTP
#include "http_request.h"
#include "http_parsed_url.h"
#endif

#ifndef MBED_WS_RX_PAYLOAD_BUFFER_SIZE
#define MBED_WS_RX_PAYLOAD_BUFFER_SIZE 256
#endif

#ifndef MBED_WS_RX_BUFFER_SIZE
#define MBED_WS_RX_BUFFER_SIZE 256
#endif

#ifndef MBED_WS_TX_BUFFER_SIZE
#define MBED_WS_TX_BUFFER_SIZE 256
#endif

#ifndef MBED_WS_PING_INTERVAL_MS
#define MBED_WS_PING_INTERVAL_MS 10000
#endif

#ifndef MBED_WS_USER_AGENT
#define MBED_WS_USER_AGENT "Mbed-WS-Client"
#endif

// #define MBED_WS_DEBUG 1

// this library returns nsapi_error_t codes, plus these
typedef enum {
    MBED_WS_ERROR_OK                =  0,        /*!< no error */
    MBED_WS_INVALID_STATUS_CODE     = -3101,     /*!< response code from server was not 101 */
    MBED_WS_INVALID_UPGRADE_HEADER  = -3102,     /*!< upgrade HTTP header was not 'websocket' */
    MBED_WS_INVALID_ACCEPT_HEADER   = -3103,     /*!< Sec-WebSocket-Accept has invalid value (or missing) */
} mbed_ws_error_t;

typedef enum {
    WS_CONTINUATION_FRAME = 0,
    WS_TEXT_FRAME = 1,
    WS_BINARY_FRAME = 2,
    WS_CONNECTION_CLOSE_FRAME = 8,
    WS_PING_FRAME = 9,
    WS_PONG_FRAME = 10
} WS_OPCODE;

typedef enum {
    WS_PARSING_NONE = 0,
    WS_PARSING_OPCODE = 1,
    WS_PARSING_LEN = 2,
    WS_PARSING_LEN126_1 = 3,
    WS_PARSING_LEN126_2 = 4,
    WS_PARSING_LEN127_1 = 5,
    WS_PARSING_LEN127_2 = 6,
    WS_PARSING_LEN127_3 = 7,
    WS_PARSING_LEN127_4 = 8,
    WS_PARSING_LEN127_5 = 9,
    WS_PARSING_LEN127_6 = 10,
    WS_PARSING_LEN127_7 = 11,
    WS_PARSING_LEN127_8 = 12,
    WB_PARSING_MASK_CHECK = 13,
    WB_PARSING_MASK_1 = 14,
    WB_PARSING_MASK_2 = 15,
    WB_PARSING_MASK_3 = 16,
    WB_PARSING_MASK_4 = 17,
    WS_PARSING_PAYLOAD_INIT = 18,
    WS_PARSING_PAYLOAD = 19,
    WS_PARSING_DONE = 20
} WS_PARSING_STATE;

typedef struct {
    WS_PARSING_STATE state;
    bool fin;
    WS_OPCODE opcode;
    bool is_masked;
    char mask[4];
    uint32_t payload_len;
    uint32_t payload_cur_pos;
    uint8_t *payload;
} rx_ws_message_t;

typedef struct {
    Callback<void(WS_OPCODE, uint8_t*, size_t)> rx_callback;
    Callback<void()> disconnect_callback;
} ws_callbacks_t;

class WsClient;
class WssClient;

class WebsocketClientBase {
    friend class WsClient;
    friend class WssClient;

public:
    WebsocketClientBase(EventQueue *queue, NetworkInterface *network, const char *url)
        : _queue(queue)
          , _network(network)
#ifdef MBED_WS_HAS_MBED_HTTP
          , _url(url)
          , _parsed_url(new ParsedUrl(url))
#endif
          , _socket(NULL)
    {
        _callbacks = nullptr;
        _ping_counter = 0;
        _pong_counter = 0;
        _ping_ev = 0;
    }

    /**
     * HttpRequest Constructor
     */
    virtual ~WebsocketClientBase() {
        if (_socket && _we_created_socket) {
            _socket->set_blocking(true);
            _socket->sigio(NULL);
            _socket->close();
            delete _socket;
        }

        if (_parsed_url) {
            delete _parsed_url;
        }

        if (_ping_ev != 0) {
            _queue->cancel(_ping_ev);
        }
    }

    int connect(ws_callbacks_t *callbacks) {
        _callbacks = callbacks;

        if (_socket) {
            _socket->set_blocking(true);
            _socket->sigio(NULL);
        }

        _ping_counter = 0;
        _pong_counter = 0;

#ifdef MBED_WS_HAS_MBED_HTTP
        if (!_network) {
            return NSAPI_ERROR_NO_CONNECTION;
        }

        nsapi_error_t r;

#ifdef MBED_WS_DEBUG
        printf("Connecting to %s:%u\n", _parsed_url->host(), _parsed_url->port());
#endif

        r = connect_socket(_parsed_url->host(), _parsed_url->port());
        if (r != NSAPI_ERROR_OK) {
#ifdef MBED_WS_DEBUG
            printf("Failed to connect socket (%d)\n", r);
#endif
            return r;
        }

        size_t key_len;
        char random_bytes[16], ws_sec_key[25];
        for (size_t i = 0; i < 16; i++) {
            random_bytes[i] = randLIB_get_8bit();
        }
        mbedtls_base64_encode((unsigned char *)&ws_sec_key[0], sizeof(ws_sec_key), &key_len, (const unsigned char *)&random_bytes[0], sizeof(random_bytes));
        #ifdef MBED_WS_DEBUG
        printf("Sec-WebSocket-Key: %s\n", ws_sec_key);
        #endif

        // This might seem weird... because we support both ws:// and wss://
        // but we already have a good working socket with TLS connection, and so the only thing
        // we do is act on that socket. So it's fine to reference HttpRequest
        // the TCPSocket casting is also weird, but it's just setting pointers, so it's fine for now
        // This might break if Mbed HTTP changes inner workings though!!
        HttpRequest* req = new HttpRequest((TCPSocket*)_socket, HTTP_GET, _url);
        req->set_header("Upgrade", "Websocket");
        req->set_header("Connection", "Upgrade");
        req->set_header("Sec-WebSocket-Key", string(ws_sec_key));
        req->set_header("Sec-WebSocket-Version", "13");
        req->set_header("User-Agent", MBED_WS_USER_AGENT);

        HttpResponse* res = req->send();
        if (!res) {
            r = req->get_error();
            delete req;
            return r;
        }

        r = NSAPI_ERROR_OK;

#ifdef MBED_WS_DEBUG
        printf("Response: %d - %s\n", res->get_status_code(), res->get_status_message().c_str());
#endif

        bool has_valid_upgrade = false;
        bool has_valid_websocket_accept = false;

        unsigned char ws_sec_accept_hash[20] = {0};
        unsigned char ws_sec_accept_buffer[61] = {0};
        const char guid_str[] = {"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"};
        char ws_sec_accept[29];
        sprintf((char*)ws_sec_accept_buffer,"%s%s", ws_sec_key, guid_str);
        mbedtls_sha1(ws_sec_accept_buffer, 60, ws_sec_accept_hash);
        mbedtls_base64_encode( (unsigned char *)&ws_sec_accept, sizeof(ws_sec_accept), &key_len, ws_sec_accept_hash, 20);

#ifdef MBED_WS_DEBUG
        printf("Calculated Sec-Websocket-Accpet: %s\n", ws_sec_accept);
        printf("Headers:\n");
#endif
        for (size_t ix = 0; ix < res->get_headers_length(); ix++) {
            const char *header_key = res->get_headers_fields()[ix]->c_str();
            const char *header_value = res->get_headers_values()[ix]->c_str();

            if (strcmp_insensitive(header_key, "Upgrade") == 0 &&
                strcmp_insensitive(header_value, "websocket") == 0)
            {
                has_valid_upgrade = true;
            }
            if (strcmp_insensitive(header_key, "Sec-WebSocket-Accept") == 0 &&
                strcmp_insensitive(header_value, ws_sec_accept) == 0)
            {
                has_valid_websocket_accept = true;
            }

#ifdef MBED_WS_DEBUG
            printf("\t%s: %s\n", header_key, header_value);
#endif
        }
#ifdef MBED_WS_DEBUG
        printf("\nBody (%lu bytes):\n\n%s\n", res->get_body_length(), res->get_body_as_string().c_str());
#endif

        if (res->get_status_code() != 101) {
            r = MBED_WS_INVALID_STATUS_CODE;
        }

        if (!has_valid_upgrade) {
            r = MBED_WS_INVALID_UPGRADE_HEADER;
        }
        if (!has_valid_websocket_accept) {
            r = MBED_WS_INVALID_ACCEPT_HEADER;
        }

        delete req;

        if (r != NSAPI_ERROR_OK) {
            return r;
        }

        // ok... now connected
#endif

        // switch socket to non-blocking mode
        _socket->set_blocking(false);
        _socket->sigio(_queue->event(this, &WebsocketClientBase::handle_socket_sigio));

        // set ping interval
        _ping_ev = _queue->call_every(MBED_WS_PING_INTERVAL_MS, callback(this, &WebsocketClientBase::ping));

        return NSAPI_ERROR_OK;
    }

    nsapi_error_t send(WS_OPCODE opcode, const uint8_t *data, size_t data_size) {
        bool use_tx_buffer = true;
        // if there's space in the ws_buffer, we'll put the payload there too
        // otherwise we'll need two TCP frames
        if (data_size + 15 > MBED_WS_TX_BUFFER_SIZE) {
            use_tx_buffer = false;
        }

        memset(_tx_buffer, 0, MBED_WS_TX_BUFFER_SIZE);
        int idx = 0;
        idx = set_opcode(opcode, _tx_buffer);
        idx += set_length(data_size, _tx_buffer + idx);
        idx += set_mask(_tx_buffer + idx);

        nsapi_size_or_error_t r;

        if (use_tx_buffer) {
            memcpy(_tx_buffer + idx, data, data_size);
            idx += data_size;
        }

        r = _socket->send((const uint8_t*)_tx_buffer, idx);
#ifdef MBED_WS_DEBUG
        printf("send1 returned %d\n", r);
#endif

        if (r < 0) {
            return r;
        }

        if (!use_tx_buffer) {
            r = _socket->send(data, data_size);
#ifdef MBED_WS_DEBUG
            printf("send2 returned %d\n", r);
#endif
        }

        return r < 0 ? r : NSAPI_ERROR_OK;

        return 0;
    }

#ifdef MBED_WS_HAS_MBED_HTTP
    void set_url(const char *url) {
        delete _parsed_url;

        _parsed_url = new ParsedUrl(url);
    }
#endif

    /**
     * Disconnect manually
     */
    void disconnect() {
        // stop handling ping/pong
        if (_ping_ev != 0) {
            _queue->cancel(_ping_ev);
            _ping_ev = 0;
        }

        _socket->close(); // ignore return value here...
    }

    /**
     * Pause the ping/pong disconnect mechanism.
     * This is useful if you have a long running process (e.g. sampling data)
     * that runs at a higher priority than the thread that handles the websocket messages.
     * Otherwise it'll trigger an instant disconnect when that thread gets priority back.
     * Note that this will still detect socket close events on the web socket.
     */
    void pause_disconnect_checker() {
#ifdef MBED_WS_DEBUG
        printf("ws pause_disconnect_checker\n");
#endif
        if (_ping_ev != 0) {
            _queue->cancel(_ping_ev);
            _ping_ev = 0;
        }
    }

    /**
     * Resume the ping/pong disconnect mechanism.
     * This is useful if you have a long running process (e.g. sampling data)
     * that runs at a higher priority than the thread that handles the websocket messages.
     * See also `pause_disconnect_checker`.
     */
    void resume_disconnect_checker() {
#ifdef MBED_WS_DEBUG
        printf("ws resume_disconnect_checker\n");
#endif

        _ping_counter = _pong_counter = 0;

        _ping_ev = _queue->call_every(MBED_WS_PING_INTERVAL_MS, callback(this, &WebsocketClientBase::ping));
    }

protected:
    virtual nsapi_error_t connect_socket(char *host, uint16_t port) = 0;

private:
    int set_length(uint32_t len, uint8_t *buffer) {
        if (len < 126) {
            buffer[0] = len | (1 << 7);
            return 1;
        }
        else if (len < 65535) {
            buffer[0] = 126 | (1 << 7);
            buffer[1] = (len >> 8) & 0xff;
            buffer[2] = len & 0xff;
            return 3;
        }
        else {
            buffer[0] = 127 | (1 << 7);
            for (int i = 0; i < 8; i++) {
                buffer[i+1] = (len >> i*8) & 0xff;
            }
            return 9;
        }
    }

    int set_opcode(WS_OPCODE opcode, uint8_t *buffer) {
        buffer[0] = 0x80 | (opcode & 0x0f);
        return 1;
    }

    int set_mask(uint8_t *buffer) {
        for (int i = 0; i < 4; i++) {
            buffer[i] = 0;
        }
        return 4;
    }

    void handle_disconnect() {
#ifdef MBED_WS_DEBUG
        printf("handle_disconnect\n");
#endif

        disconnect();

        if (_callbacks && _callbacks->disconnect_callback) {
            _callbacks->disconnect_callback();
        }
    }

    void ping() {
        if (_ping_counter != _pong_counter) {
#ifdef MBED_WS_DEBUG
            printf("Ping and pong out of sync: ping=%u pong=%u\n", _ping_counter, _pong_counter);
#endif
            handle_disconnect();
            return;
        }

        _ping_counter++;
#ifdef MBED_WS_DEBUG
        printf("Ping (%u)!\n", _ping_counter);
#endif

        // I don't want to do this globally in the send() handler, because incorrect user
        // behavior could also trigger an error from the network...
        if (send(WS_PING_FRAME, nullptr, 0) < 0) {
            handle_disconnect();
        }
    }

    WS_PARSING_STATE handle_rx_msg(rx_ws_message_t *msg, const uint8_t c) {
#ifdef MBED_WS_DEBUG
        printf("handle_rx_msg state=%d\n", msg->state);
#endif

        int i;

        switch (msg->state) {
            case WS_PARSING_NONE:
            case WS_PARSING_OPCODE:
                memset(msg->mask, 0, 4);    // empty mask
                msg->fin = c >> 7 & 0x1;    // first bit indicates the fin flag
                msg->opcode = (WS_OPCODE)(c & 0b1111);   // last four bits indicate the opcode
                msg->state = WS_PARSING_LEN;
                break;

            case WS_PARSING_LEN:
                msg->payload_len = c & 0x7f;
                msg->is_masked = c & 0x80;
                msg->payload_cur_pos = 0;
#ifdef MBED_WS_DEBUG
                printf("WS_PARSING_LEN len=%lu\n", msg->payload_len);
#endif
                if (msg->payload_len == 0) {
                    msg->state = WS_PARSING_DONE;
                }
                else if (msg->payload_len == 126) {
                    msg->state = WS_PARSING_LEN126_1;
                }
                else if (msg->payload_len == 127) {
                    msg->payload_len = 0;
                    msg->state = WS_PARSING_LEN127_1;
                }
                else {
                    msg->state = WB_PARSING_MASK_CHECK;
                }
                break;

            case WS_PARSING_LEN126_1:
                msg->payload_len = c << 8;
                msg->state = WS_PARSING_LEN126_2;
                break;

            case WS_PARSING_LEN126_2:
                msg->payload_len += c;
                msg->state = WB_PARSING_MASK_CHECK;
                break;

            case WS_PARSING_LEN127_1:
            case WS_PARSING_LEN127_2:
            case WS_PARSING_LEN127_3:
            case WS_PARSING_LEN127_4:
            case WS_PARSING_LEN127_5:
            case WS_PARSING_LEN127_6:
            case WS_PARSING_LEN127_7:
            case WS_PARSING_LEN127_8:
                i = msg->state - WS_PARSING_LEN127_1;
                msg->payload_len += (c << (7 - i) * 8);
                msg->state = (WS_PARSING_STATE)((int)msg->state + 1);
                break;

            case WB_PARSING_MASK_CHECK:
                if (!msg->is_masked) {
                    msg->state = WS_PARSING_PAYLOAD_INIT;
                }
                else {
                    msg->state = WB_PARSING_MASK_1;
                }
                return handle_rx_msg(msg, c);

            case WB_PARSING_MASK_1:
                msg->mask[0] = c;
                msg->state = WB_PARSING_MASK_2;
                break;

            case WB_PARSING_MASK_2:
                msg->mask[1] = c;
                msg->state = WB_PARSING_MASK_3;
                break;

            case WB_PARSING_MASK_3:
                msg->mask[2] = c;
                msg->state = WB_PARSING_MASK_4;
                break;

            case WB_PARSING_MASK_4:
                msg->mask[3] = c;
                msg->state = WS_PARSING_PAYLOAD_INIT;
                break;

            case WS_PARSING_PAYLOAD_INIT:
                msg->payload_cur_pos = 0;
                if (msg->payload_len <= MBED_WS_RX_PAYLOAD_BUFFER_SIZE) {
                    msg->payload = _rx_buffer;
                }
                else {
                    msg->payload = nullptr;
                }
                msg->state = WS_PARSING_PAYLOAD;
                return handle_rx_msg(msg, c);

            case WS_PARSING_PAYLOAD:
                if (msg->payload_len == 0) {
                    msg->state = WS_PARSING_DONE;
                    return handle_rx_msg(msg, c);
                }
                if (msg->payload != nullptr) {
                    msg->payload[msg->payload_cur_pos] = c ^ msg->mask[msg->payload_cur_pos % 4];
                }
                if (msg->payload_cur_pos + 1 == msg->payload_len) {
                    msg->state = WS_PARSING_DONE;
                }
                msg->payload_cur_pos++;
                break;

            case WS_PARSING_DONE:
                break;
        }

#ifdef MBED_WS_DEBUG
        printf("handle_rx_msg now state=%d\n", msg->state);
#endif
        return msg->state;
    }

    void handle_socket_sigio() {
        if (!_socket) return;

        uint8_t rx_buffer[MBED_WS_RX_BUFFER_SIZE];

        nsapi_size_or_error_t r = _socket->recv(rx_buffer, sizeof(rx_buffer));
#ifdef MBED_WS_DEBUG
        printf("socket.recv returned %d\n", r); // 0 would be fine, would block would be fine too
#endif
        if (r > 0) {
            _curr_msg.state = WS_PARSING_NONE;

            for (int ix = 0; ix < r; ix++) {
                WS_PARSING_STATE s = handle_rx_msg(&_curr_msg, rx_buffer[ix]);
                if (s == WS_PARSING_DONE) {
#ifdef MBED_WS_DEBUG
                    printf("Websocket msg, opcode=%u, len=%lu: ", _curr_msg.opcode, _curr_msg.payload_len);
                    for (size_t jx = 0; jx < _curr_msg.payload_len; jx++) {
                        printf("%c", _curr_msg.payload[jx]);
                    }
                    printf("\n");
#endif
                    _curr_msg.state = WS_PARSING_NONE;

                    // send pong back if server asks for it
                    if (_curr_msg.opcode == WS_PING_FRAME) {
                        _queue->call(callback(this, &WebsocketClientBase::send), WS_PONG_FRAME, nullptr, 0);
                    }
                    else if (_curr_msg.opcode == WS_PONG_FRAME) {
                        _pong_counter++;
#ifdef MBED_WS_DEBUG
                        printf("Pong (%u)!\n", _pong_counter);
#endif
                    }
                    else if (_callbacks && _callbacks->rx_callback) {
                        _callbacks->rx_callback(_curr_msg.opcode, _curr_msg.payload, _curr_msg.payload_len);
                    }
                }
            }

        }
    }

    /**
     * Case insensitive strcmp (ASCII only!!)
     */
    int strcmp_insensitive(const char a[], const char b[]) {
        int c = 0;

        while (1) {
            char ac = a[c];
            char bc = b[c];

            if (ac >= 'A' && ac <= 'Z') {
                ac += 32;
            }
            if (bc >= 'A' && bc <= 'Z') {
                bc += 32;
            }

            if (ac != bc) {
                break;
            }
            if (ac == '\0' || bc == '\0') {
                break;
            }
            c++;
        }

        if (a[c] == '\0' && b[c] == '\0') {
            return 0;
        }
        else {
            return -1;
        }
    }

    EventQueue *_queue;
    NetworkInterface *_network;
#ifdef MBED_WS_HAS_MBED_HTTP
    const char *_url;
    ParsedUrl *_parsed_url;
#endif
    Socket *_socket;

    uint8_t _rx_buffer[MBED_WS_RX_PAYLOAD_BUFFER_SIZE];
    uint8_t _tx_buffer[MBED_WS_TX_BUFFER_SIZE];

    bool _we_created_socket;

    ws_callbacks_t *_callbacks;

    size_t _ping_counter;
    size_t _pong_counter;
    int _ping_ev;

    rx_ws_message_t _curr_msg;
};

#endif // _MBED_WS_WS_REQUEST_BASE_H_
