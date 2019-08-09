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

#ifndef _MBED_WS_WSS_REQUEST_H_
#define _MBED_WS_WSS_REQUEST_H_

#include "TLSSocket.h"
#include "ws_client_base.h"
#include "mbed_trace.h"

class WssClient : public WebsocketClientBase {
public:
#ifdef MBED_WS_HAS_MBED_HTTP
    /**
     * Start a new secure Websocket Client (wss://)
     * @param queue Event queue
     * @param network Initialized and connected network interface
     * @param url URL to the websocket server
     */
    WssClient(EventQueue *queue, NetworkInterface *network, const char* ssl_ca_pem, const char *url)
        : WebsocketClientBase(queue, network, url), _ssl_ca_pem(ssl_ca_pem)
    {
        _socket = new TLSSocket();
        _we_created_socket = true;
    }
#endif

    /**
     * Start a new secure Websocket Client (wss://)
     * @param queue Event queue
     * @param socket An initialized and connected TLSSocket
     */
    WssClient(EventQueue *queue, TLSSocket *socket)
        : WebsocketClientBase(queue, nullptr, "")
    {
        _socket = socket;
        _we_created_socket = false;
    }


protected:
    virtual nsapi_error_t connect_socket(char *host, uint16_t port) {
        nsapi_error_t r;
        TLSSocket *socket = (TLSSocket*)_socket;
        r = socket->open(_network);
        if (r != NSAPI_ERROR_OK) {
            return r;
        }
        r = socket->set_root_ca_cert(_ssl_ca_pem);
        if (r != NSAPI_ERROR_OK) {
            return r;
        }
        return socket->connect(host, port);
    }

private:
    const char *_ssl_ca_pem;
};

#endif // _MBED_WS_WSS_REQUEST_H_
