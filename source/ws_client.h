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

#ifndef _MBED_WS_WS_REQUEST_H_
#define _MBED_WS_WS_REQUEST_H_

#include "TCPSocket.h"
#include "ws_client_base.h"

class WsClient : public WebsocketClientBase {
public:
#ifdef MBED_WS_HAS_MBED_HTTP
    /**
     * Start a new non-secure Websocket Client (ws://)
     * @param queue Event queue
     * @param network Initialized and connected network interface
     * @param url URL to the websocket server
     */
    WsClient(EventQueue *queue, NetworkInterface *network, const char *url)
        : WebsocketClientBase(queue, network, url)
    {
        _we_created_socket = true;
        _socket = NULL;
    }
#endif

    /**
     * Start a new non-secure Websocket Client (ws://)
     * @param queue Event queue
     * @param socket An initialized and connected TCPSocket
     */
    WsClient(EventQueue *queue, TCPSocket *socket)
        : WebsocketClientBase(queue, nullptr, "")
    {
        _socket = socket;
        _we_created_socket = false;
    }


protected:
    virtual nsapi_error_t connect_socket(char *host, uint16_t port) {
        if (_socket != NULL) {
            TCPSocket *old_socket = (TCPSocket*)_socket;
            old_socket->set_blocking(true);
            old_socket->sigio(NULL);
            old_socket->close();
            delete old_socket;
        }

        _socket = new TCPSocket();

        nsapi_error_t r;
        TCPSocket *socket = (TCPSocket*)_socket;
        r = socket->open(_network);
        if (r != NSAPI_ERROR_OK) {
            return r;
        }
        return socket->connect(host, port);
    }
};

#endif // _MBED_WS_WS_REQUEST_H_
