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

# TagoTiP -- Transport IoT Protocol

A lightweight, human-readable protocol for sending and receiving IoT data to [TagoIO](https://tago.io). TagoTiP provides a compact alternative to HTTP/JSON for resource-constrained embedded devices.

## Quick Example

```
PUSH|ate2bd319014b24e0a8aca9f00aea4c0d0|sensor-01|[temperature:=32.5#C;humidity:=65#%]
```

## Key Features

- **Human-readable** -- frames can be read and composed in a terminal
- **Type-safe** -- explicit operators for numbers (`:=`), strings (`=`), booleans (`?=`), and locations (`@=`)
- **Compact** -- ~3.7x smaller than equivalent HTTP/JSON
- **Transport-agnostic** -- works over UDP, TCP, HTTP(S), MQTT, or any byte-capable channel
- **C-friendly** -- linear parsing, predictable buffer sizes, minimal string handling
- **Complete** -- supports all TagoIO data model fields: variable, value, unit, time, group, location, and metadata

## Documentation

| Document | Description |
|---|---|
| [TagoTiP.md](TagoTiP.md) | Full protocol specification (v1.0 Draft, Revision B) -- frame format, methods, variable syntax, parsing rules, ABNF grammar |
| [TagoTiPs.md](TagoTiPs.md) | TagoTiP/S (v1.0 Draft, Revision C) -- AEAD encrypted envelope for links without TLS |

## Protocol Overview

### Methods

| Method | Direction | Purpose |
|---|---|---|
| `PUSH` | Client -> Server | Send structured data or raw passthrough payloads to a device |
| `PULL` | Client -> Server | Retrieve last value of one or more variables |
| `PING` | Client -> Server | Keepalive / connectivity test |
| `ACK`  | Server -> Client | Response to any uplink method (`OK`, `PONG`, `CMD`, `ERR`) |

### Type Operators

| Operator | Type | Example |
|---|---|---|
| `:=` | Number | `temperature:=32.5` |
| `=` | String | `status=running` |
| `?=` | Boolean | `active?=true` |
| `@=` | Location | `position@=39.74,-104.99,305` |

### Variable Suffixes

Each variable supports optional suffixes for unit (`#`), timestamp (`@`), group (`^`), and metadata (`{}`):

```
temperature:=32.5#C@1694567890000^reading_001{source=dht22,quality=high}
```

### Body-Level Modifiers

Defaults that cascade to all variables in a frame, with variable-level overrides:

```
PUSH|AUTH|SERIAL|^batch_42@1694567890000{firmware=2.1}[temp:=32#C;humidity:=65#%]
```

### Passthrough Payloads

Raw hex or base64 data sent directly to the device's payload parser:

```
PUSH|AUTH|SERIAL|>xDEADBEEF01020304
PUSH|AUTH|SERIAL|>b3q2+7wECAwQ=
```

### Sequence Counter

Optional replay protection and request-response correlation:

```
PUSH|!42|AUTH|SERIAL|[temperature:=32]
ACK|!42|OK|1
```

## TagoTiP/S -- Secure Envelope

TagoTiP/S wraps TagoTiP data in a binary AEAD-encrypted envelope for links where TLS is unavailable (LoRa, Sigfox, NB-IoT, raw UDP). It uses a compact headless inner frame that omits redundant header fields, saving ~40 bytes per message.

### Supported Cipher Suites

| ID | Cipher | Key | Tag |
|----|--------|-----|-----|
| 0 | AES-128-CCM (mandatory) | 16 B | 8 B |
| 1 | AES-128-GCM | 16 B | 16 B |
| 2 | AES-256-CCM | 32 B | 8 B |
| 3 | AES-256-GCM | 32 B | 16 B |
| 4 | ChaCha20-Poly1305 | 32 B | 16 B |

### Envelope Structure

```
[Flags 1B] [Counter 4B] [Auth Hash 8B] [Device Hash 4B] [Ciphertext + Auth Tag]
```

Total overhead: 25 bytes (CCM) or 33 bytes (GCM / ChaCha20-Poly1305).

## Size Comparison

| Format | Size | Ratio |
|---|---|---|
| HTTP/JSON | ~487 bytes | -- |
| TagoTiP | ~130 bytes | 3.7x smaller |
| TagoTiP/S (AES-128-CCM) | ~115 bytes | 4.2x smaller |

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.

Anyone is free to implement TagoTiP for any purpose, including commercial use. The names "TagoTiP", "TagoTiP/S", and "TagoIO" are trademarks of TagoIO Inc. See [NOTICE](NOTICE) for trademark details.
