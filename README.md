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

<br/>
<p align="center">
  <img src="https://assets.tago.io/tagoio/tagoio.png" width="250px" alt="TagoIO"></img>
</p>

# TagoTiP — Transport IoT Protocol

A lightweight, human-readable protocol for sending and receiving IoT data to [TagoIO](https://tago.io). TagoTiP provides a compact alternative to HTTP/JSON for resource-constrained embedded devices.

## Quick Example

```
PUSH|ate2bd319014b24e0a8aca9f00aea4c0d0|sensor-01|[temperature:=32.5#C;humidity:=65#%]
```

## Key Features

- **Human-readable** — frames can be read and composed in a terminal
- **Type-safe** — explicit operators for numbers (`:=`), strings (`=`), booleans (`?=`), and locations (`@=`)
- **Compact** — ~3.7x smaller than equivalent HTTP/JSON
- **Transport-agnostic** — works over UDP, TCP, HTTP(S), MQTT, or any byte-capable channel
- **C-friendly** — linear parsing, predictable buffer sizes, minimal string handling

## Documentation

| Document | Description |
|---|---|
| [TagoTiP.md](TagoTiP.md) | Full protocol specification — frame format, methods, variable syntax, parsing rules |
| [TagoTiPs.md](TagoTiPs.md) | TagoTiP/S (Secure) — AES-128-CCM encrypted envelope for links without TLS |

## Protocol Overview

| Method | Direction | Purpose |
|---|---|---|
| `PUSH` | Client -> Server | Send data to a device |
| `PULL` | Client -> Server | Retrieve last value of a variable |
| `PING` | Client -> Server | Keepalive / connectivity test |
| `ACK`  | Server -> Client | Response to any uplink method |

## Size Comparison

| Format | Size | Ratio |
|---|---|---|
| HTTP/JSON | ~487 bytes | -- |
| TagoTiP | ~130 bytes | 3.7x smaller |
| TagoTiP/S | ~115 bytes | 4.2x smaller |

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
