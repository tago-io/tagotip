<!--
  Copyright 2026 TagoIO Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# TagoTiP Transport Bindings

**Version:** 1.0 (Draft)
**Date:** February 2026
**Status:** Draft Specification

> This document defines how TagoTiP messages are carried over specific transports. For the core protocol (frame format, variable syntax, parsing rules), see [TagoTiP.md](TagoTiP.md). For the encrypted envelope, see [TagoTiPs.md](TagoTiPs.md).

---

## 1. Introduction

TagoTiP is transport-agnostic: [TagoTiP.md](TagoTiP.md) defines only the message format and parsing rules. However, common transports (HTTP, MQTT) already provide native mechanisms for method signaling, authentication, and device routing. Duplicating these fields inside the TagoTiP body is wasteful.

This document defines **transport bindings** -- mappings that use each transport's native features for method, authentication, and device identification, carrying only the TagoTiP body on the wire.

| Binding | Method Signal | Authentication | Device ID | Body |
|---|---|---|---|---|
| **Raw** (UDP/TCP) | In frame (`METHOD\|...`) | In frame (`AUTH_HASH`) | In frame (`SERIAL`) | In frame |
| **HTTP** | HTTP method (POST/GET/HEAD) | `Authorization` header | URL path | HTTP body |
| **MQTT** | Topic suffix (`/push`, `/pull`) | CONNECT credentials | `$tip/{serial}/...` topic | Body only |

The **Raw** binding is the default: a complete TagoTiP frame as defined in [TagoTiP.md](TagoTiP.md). The HTTP and MQTT bindings described below extract method, auth, and device identity into transport-native fields, leaving only the TagoTiP body in the payload.

### 1.1 Conventions

- Keywords `MUST`, `SHOULD`, `MAY`, `MUST NOT` follow RFC 2119 definitions
- The **Authorization Hash** is derived as described in [TagoTiP.md §2](TagoTiP.md#2-credentials) -- 16 hex characters (8 bytes of SHA-256)
- All body content follows the syntax defined in [TagoTiP.md](TagoTiP.md) (structured variables, passthrough, etc.)

---

## 2. HTTP Binding

The HTTP binding maps TagoTiP methods to HTTP methods, carries the Authorization Hash in a header, and identifies the device via the URL path.

### 2.1 Method Mapping

| HTTP Method | TagoTiP Method | Purpose |
|---|---|---|
| `POST` | PUSH | Send data to a device |
| `GET` | PULL | Retrieve last values |
| `HEAD` | PING | Keepalive / connectivity test |

### 2.2 Authentication

The Authorization Hash is sent in the `Authorization` header:

```
Authorization: TagoTiP <auth-hash-hex>
```

Example:

```
Authorization: TagoTiP 4deedd7bab8817ec
```

The server resolves the Account/Profile by the Authorization Hash. If the hash does not match any profile, the server MUST respond with HTTP 401.

### 2.3 Device Identification

The device serial number is carried in the URL path:

```
/v1/tip/{serial}
```

Examples:

```
POST /v1/tip/sensor-01
GET  /v1/tip/weather-denver
HEAD /v1/tip/sensor-01
```

### 2.4 Request Body

The HTTP body carries only the TagoTiP body content -- no method, auth, or serial fields.

**POST (PUSH):** The body is a TagoTiP PUSH body -- structured variables or passthrough:

```
[temp:=32#C;humidity:=65#%]
^batch_42@1694567890000{firmware=2.1}[temp:=32#C]
>xDEADBEEF01020304
>b3q2+7wECAwQ=
```

**GET (PULL):** Variable names are specified as a query parameter:

```
GET /v1/tip/weather-denver?variables=temperature,humidity
```

The `variables` parameter is a comma-separated list of variable names.

**HEAD (PING):** No body.

### 2.5 Response Mapping

| HTTP Status | TagoTiP Status | Condition |
|---|---|---|
| `200 OK` | `OK` | PUSH: body contains data point count. PULL: body contains variable list in TagoTiP syntax. |
| `204 No Content` | `PONG` | HEAD response (keepalive acknowledged) |
| `400 Bad Request` | `ERR\|invalid_payload` | Malformed body or parse error |
| `401 Unauthorized` | `ERR\|invalid_token` | Missing or invalid Authorization Hash |
| `404 Not Found` | `ERR\|device_not_found` or `ERR\|variable_not_found` | Serial not found or no requested variables exist |
| `429 Too Many Requests` | `ERR\|rate_limited` | Rate limit exceeded |
| `500 Internal Server Error` | `ERR\|server_error` | Internal server error |

**Response body for 200 OK:**

- **POST (PUSH):** The count of accepted data points as a plain decimal string (e.g., `3`).
- **GET (PULL):** The bracket-wrapped variable list in TagoTiP syntax (e.g., `[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]`).

**Error response body:** The TagoTiP error code as a plain string (e.g., `invalid_payload`).

### 2.6 CMD Delivery ----- TBD

On HTTP, commands are delivered as part of the response to PUSH or PULL requests when a command is pending for the device. The server MAY include a `X-TagoTiP-CMD` response header containing the command string:

```
X-TagoTiP-CMD: reboot
X-TagoTiP-CMD: ota=https://example.com/v2.1.bin
```

Clients SHOULD use periodic HEAD requests to poll for pending commands. When a command is pending, the server responds with `200 OK` instead of `204 No Content`, with the command string in the `X-TagoTiP-CMD` header.

### 2.7 Sequence Counter

Not needed. HTTP is inherently request-response, providing built-in correlation between requests and responses.

### 2.8 Examples

**PUSH -- Send data:**

```http
POST /v1/tip/sensor-01 HTTP/1.1
Host: tip.tago.io
Authorization: TagoTiP 4deedd7bab8817ec
Content-Type: text/plain

[temperature:=32#C;humidity:=65#%]
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain

2
```

**PUSH -- Passthrough (hex):**

```http
POST /v1/tip/sensor-01 HTTP/1.1
Host: tip.tago.io
Authorization: TagoTiP 4deedd7bab8817ec
Content-Type: text/plain

>xDEADBEEF01020304
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain

1
```

**PULL -- Retrieve last values:**

```http
GET /v1/tip/weather-denver?variables=temperature,humidity HTTP/1.1
Host: tip.tago.io
Authorization: TagoTiP 4deedd7bab8817ec
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain

[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]
```

**PING -- Keepalive:**

```http
HEAD /v1/tip/sensor-01 HTTP/1.1
Host: tip.tago.io
Authorization: TagoTiP 4deedd7bab8817ec
```

```http
HTTP/1.1 204 No Content
```

**PING with pending command:**

```http
HEAD /v1/tip/sensor-01 HTTP/1.1
Host: tip.tago.io
Authorization: TagoTiP 4deedd7bab8817ec
```

```http
HTTP/1.1 200 OK
X-TagoTiP-CMD: reboot
```

---

## 3. MQTT Binding

The MQTT binding uses MQTT native features for authentication, topic-based routing, and pub/sub data flow.

### 3.1 Authentication (CONNECT)

The Authorization Hash (16 hex characters) is split across the MQTT CONNECT credentials:

| MQTT Field | Value | Example |
|---|---|---|
| **Username** | First 8 hex chars of auth hash | `4deedd7b` |
| **Password** | Last 8 hex chars of auth hash | `ab8817ec` |

The server reconstructs the full Authorization Hash by concatenating username + password, then resolves the Account/Profile.

All MQTT connections sharing the same credentials (i.e., derived from the same Authorization Token) belong to the same context. This means any device on that context can publish or subscribe to any `$tip/{serial}/...` topic within it, enabling inter-device communication. If devices require isolation, they SHOULD use separate Authorization Tokens so each device operates in its own context.

### 3.2 Topic Structure

TagoTiP uses the MQTT **reserved topic prefix** `$tip/` for all protocol traffic. The `$` prefix follows the MQTT convention for broker/protocol-level topics (similar to `$SYS/`).

| Topic | Direction | Purpose |
|---|---|---|
| `$tip/{serial}/push` | Uplink (device -> server) | Device publishes data |
| `$tip/{serial}/pull` | Uplink (device -> server) | Device requests last values of variables |
| `$tip/{serial}/ack` | Downlink (server -> device) | Server publishes responses and commands |

- The device MUST **publish** to `$tip/{serial}/push` to send data
- The device MUST **publish** to `$tip/{serial}/pull` to request last values of variables
- The device MUST **subscribe** to `$tip/{serial}/ack` at CONNECT time to receive responses and commands

Since the device serial is embedded in the topic path, it does not need to appear in the payload.

### 3.3 Payload Format

The MQTT PUBLISH payload carries only the TagoTiP body, with an optional sequence counter prefix. The serial is already identified by the topic.

**Uplink on `/push`** -- structured variables or passthrough:

```
BODY
!N|BODY
```

Examples:

```
[temp:=32#C;humidity:=65#%]
^batch_42@1694567890000[temp:=32#C]
>xDEADBEEF01020304
>b3q2+7wECAwQ=
!42|[temp:=32#C;humidity:=65#%]
!1|>xDEADBEEF01020304
```

**Uplink on `/pull`** -- comma-separated variable names:

```
var1,var2,...
!N|var1,var2,...
```

Examples:

```
temperature,humidity
!7|temperature,humidity
```

**Downlink on `/ack`** -- status with optional detail and counter:

```
STATUS|DETAIL
!N|STATUS|DETAIL
```

Examples:

```
OK|3
!42|OK|2
ERR|invalid_payload
!1|ERR|invalid_payload
OK|[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]
!7|OK|[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]
CMD|reboot
CMD|ota=https://example.com/v2.1.bin
```

### 3.4 Method Mapping

Each TagoTiP method maps to a specific topic:

| TagoTiP Method | MQTT Topic | Payload |
|---|---|---|
| PUSH | Client PUBLISH to `$tip/{serial}/push` | Structured variables or passthrough |
| PULL | Client PUBLISH to `$tip/{serial}/pull` | Comma-separated variable names |

Keepalive is handled natively by MQTT's PINGREQ/PINGRESP mechanism and does not require a TagoTiP-level PING.

### 3.5 Response / CMD Delivery

The server publishes all responses and commands to the device's `$tip/{serial}/ack` topic. The downlink payload format:

```
STATUS|DETAIL
!N|STATUS|DETAIL
```

When a sequence counter (`!N`) is present in the uplink, the server echoes it back in the corresponding downlink so the device can correlate which response matches which request.

- **PUSH response:** `OK|{count}` (e.g., `OK|3`) or `ERR|{reason}`
- **PULL response:** `OK|{variable-list}` (e.g., `OK|[temperature:=32#F@1694567890000]`) or `ERR|{reason}`
- **Commands:** `CMD|{command}` (e.g., `CMD|reboot`) -- delivered asynchronously at any time

### 3.6 Sequence Counter

Optional. MQTT QoS levels (0, 1, 2) provide delivery guarantees at the transport level. However, the `!N` prefix MAY be used for **application-level correlation** -- matching a specific ACK to its originating PUBLISH. This is useful when a device sends multiple messages in flight and needs to track individual responses.

### 3.7 Examples

**CONNECT:**

```
CONNECT
  Username: 4deedd7b
  Password: ab8817ec
```

**SUBSCRIBE (at CONNECT time):**

```
SUBSCRIBE $tip/sensor-01/ack
QoS: 1
```

**PUSH -- Send data:**

```
Topic:   $tip/sensor-01/push
Payload: [temperature:=32#C;humidity:=65#%]
QoS:     1
```

**PUSH -- Send data with sequence counter:**

```
Topic:   $tip/sensor-01/push
Payload: !42|[temperature:=32#C;humidity:=65#%]
QoS:     1
```

**PUSH -- Passthrough:**

```
Topic:   $tip/sensor-01/push
Payload: >xDEADBEEF01020304
QoS:     1
```

**PUSH response (on ack topic):**

```
Topic:   $tip/sensor-01/ack
Payload: OK|2
```

**PUSH response with echoed counter:**

```
Topic:   $tip/sensor-01/ack
Payload: !42|OK|2
```

**PULL -- Request last values:**

```
Topic:   $tip/sensor-01/pull
Payload: temperature,humidity
QoS:     1
```

**PULL -- Request with sequence counter:**

```
Topic:   $tip/sensor-01/pull
Payload: !7|temperature,humidity
QoS:     1
```

**PULL response (on ack topic):**

```
Topic:   $tip/sensor-01/ack
Payload: !7|OK|[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]
```

**Server command:**

```
Topic:   $tip/sensor-01/ack
Payload: CMD|reboot
```

---

## 4. Raw Binding (UDP/TCP)

The Raw binding uses the complete TagoTiP frame format as defined in [TagoTiP.md](TagoTiP.md). This is the default binding when no transport-specific adaptation is used.

### 4.1 Frame Delimiters

| Transport | Delimiter | Notes |
|---|---|---|
| TCP | `\n` (0x0A) | Server buffers bytes until `\n` is received |
| UDP | End of datagram | Each datagram contains exactly one frame |

### 4.2 TagoTiP/S Binary Framing

When using TagoTiP/S envelopes over TCP, frames MUST be length-prefixed (uint16 Big-Endian) as described in [TagoTiPs.md §5.4](TagoTiPs.md#54-framing-on-stream-transports-tcp).

### 4.3 Complete Frame Format

The full frame includes method, auth hash, serial, and body:

```
PUSH|4deedd7bab8817ec|sensor-01|[temperature:=32#C]
PULL|4deedd7bab8817ec|weather-denver|[temperature]
PING|4deedd7bab8817ec|sensor-01
```

See [TagoTiP.md §4](TagoTiP.md#4-frame-structure) for the complete frame specification.

---

## 5. Security Considerations

### 5.1 HTTP

- TLS (HTTPS) is RECOMMENDED for all production deployments
- The Authorization Hash is carried in the `Authorization` header, which is encrypted by TLS
- The auth hash never exposes the raw Authorization Token

### 5.2 MQTT

- TLS is RECOMMENDED for MQTT connections
- The Authorization Hash is split across MQTT username and password fields, which are encrypted by TLS
- The auth hash never exposes the raw Authorization Token

### 5.3 Raw (UDP/TCP)

- For encryption without TLS, use TagoTiP/S envelopes (see [TagoTiPs.md](TagoTiPs.md))
- TLS at the transport level is an alternative for TCP connections
- On unencrypted links, the Authorization Hash is visible but does not expose the raw Authorization Token

### 5.4 Authorization Hash

The Authorization Hash is a truncated SHA-256 of the Authorization Token (without the `at` prefix). Because SHA-256 is preimage-resistant, the hash does not leak any bits of the original token. The hash is safe to transmit over the wire and display in logs or UIs.

---

## 6. License

This specification is **open source**, published under the [Apache License 2.0](LICENSE).

Anyone is free to implement these transport bindings for any purpose, including commercial use, without requiring permission from TagoIO Inc. The Apache 2.0 license includes an express patent grant to all implementers.

The names "TagoTiP", "TagoTiP/S", and "TagoIO" are trademarks of TagoIO Inc. See [NOTICE](NOTICE) for trademark details.

Copyright 2026 TagoIO Inc.
