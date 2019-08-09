# Websocket library for Mbed OS 5

An experimental small websocket client for embedded systems, supporting both `ws` and `wss` protocols. Note that this is not well tested, does not have a test suite, and should thus not be used in any real systems. Use [libwebsockets](https://libwebsockets.org) instead.

Goals for this library:

* Support secure and non-secure endpoints.
* Detect disconnects.
* Event based.

https://os.mbed.com/blog/entry/Adding-TLS-Sockets-to-Mbed-OS/

## Usage (ws)

```cpp
#include "mbed.h"
#include "ws_request.h"

EventQueue queue;
NetworkInterface *network = NetworkInterface::get_default_instance();
WebsocketClient *client;

void send_msg() {
    const char *msg = "Hello world";
    client->send(WS_TEXT_FRAME, (const uint8_t*)msg, strlen(msg));
}

void rx_callback(WS_OPCODE opcode, uint8_t *buffer, size_t buffer_size) {
    printf("ws received message: opcode=%u, buffer_size=%lu, content=", opcode, buffer_size);
    for (size_t ix = 0; ix < buffer_size; ix++) {
        printf("%c", buffer[ix]);
    }
    printf("\n");
}

void disconnect_callback() {
    printf("ws disconnected\n);
    // add some reconnect logic
}

int main() {
    // ... connect to the network

    client = new WebsocketClient(&queue, network, "ws://echo.websocket.org");

    // receive and disconnect callbacks
    ws_callbacks_t ws_callbacks = {
        rx_callback,
        disconnect_callback
    };
    int r = client->connect(ws_callbacks);
    if (r != 0) {
        printf("Failed to connect to websocket server (%d)\n", r);
        return 1;
    }

    // schedule a message every 5 seconds
    queue.call_every(5000, &send_msg);

    queue.dispatch_forever();
}
```

### WSS

To use secure websockets you

## Configuration options

These are all macros:

* `MBED_WS_HAS_MBED_HTTP` - Whether Mbed HTTP is present. If this is disabled you can only use the library by providing an initialized and upgraded socket. Otherwise Mbed HTTP can set this up for you (default `TRUE`).
* `MBED_WS_RX_PAYLOAD_BUFFER_SIZE` - As the library does not support streaming received data, you need to set a payload buffer (default `256`).
* `MBED_WS_RX_BUFFER_SIZE` - Network receive buffer (default `256`).
* `MBED_WS_TX_BUFFER_SIZE` - Network transmit buffer, minimum 15 bytes. If a message is sent that's larger than this buffer, then this buffer will only be used for the websocket header (and the message will thus be split up in multiple TCP packets) (default `256`).
* `MBED_WS_PING_INTERVAL_MS` - When ping messages are sent to the server. Ping/pong is used to detect disconnects, so that's crucial to know set this to a low value (default `1000`).
* `MBED_WS_DEBUG` - Define this macro to print detailed debug logs (default `undefined`).

## Todo

* Allow streaming of message content without using the RX buffer.
