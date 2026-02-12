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

# TagoTiP — Transport IoT Protocol

**Version:** 1.0 (Draft)
**Date:** February 2026
**Status:** Draft Specification — Revision B

> For the encrypted envelope (TagoTiP/S), see [TagoTiPs.md](TagoTiPs.md).

---

## 1. Introduction

TagoTiP is a lightweight, human-readable protocol designed for sending and receiving IoT data to TagoIO. It provides a compact alternative to HTTP/JSON for resource-constrained embedded devices.

TagoTiP is **transport-agnostic**. It can be carried over UDP, TCP, HTTP(S), MQTT, or any other transport. This specification defines only the message format and parsing rules — not transport-specific behavior such as ports, connection management, or delivery guarantees.

> **Note:** For encryption without TLS, TagoTiP frames can be wrapped in a **TagoTiP/S** crypto envelope. See [TagoTiPs.md](TagoTiPs.md).

### 1.1 Protocol at a Glance

```mermaid
block-beta
  columns 5
  METHOD["METHOD\n4-6B"]:1
  N["!N\n(opt.)"]:1
  AUTH["AUTH\n16 hex"]:1
  SERIAL["SERIAL\ndevice serial"]:1
  BODY["BODY\ncontent"]:1
```

### 1.2 Design Goals

- **Human-readable** — frames can be read and composed manually in a terminal
- **Type-safe** — value types (number, string, boolean, location) are explicit in the syntax
- **C-friendly** — minimal string concatenation, predictable buffer sizes, linear parsing
- **Compact** — minimal overhead per frame compared to HTTP/JSON
- **Transport-agnostic** — works over UDP, TCP, HTTP(S), MQTT, or any byte-capable channel
- **Complete** — supports all TagoIO data model fields: variable, value, unit, time, group, location, and metadata

### 1.3 Conventions

- Keywords `MUST`, `SHOULD`, `MAY`, `MUST NOT` follow RFC 2119 definitions
- Method names (`PUSH`, `PULL`, `PING`), status codes (`OK`, `PONG`, `CMD`, `ERR`), and boolean values (`true`, `false`) are **case-sensitive** and MUST use the exact casing shown in this specification
- Timestamps are UNIX epoch in **milliseconds**
- Text frames are UTF-8 encoded. Implementations MAY restrict to printable ASCII; any non-ASCII bytes MUST be valid UTF-8.
- The NUL byte (`U+0000` / `0x00`) MUST NOT appear anywhere in a TagoTiP frame. This rule is maintained for protocol hygiene and C-string safety.
- All variable names, group names, and metadata keys are **lowercase** and MUST NOT contain `*`, `?`, `!`, `<`, `>`, `.`, `-`, `=`, `$`, or spaces (per TagoIO restrictions). Serial numbers MAY contain hyphens (`-`) in addition to alphanumeric characters and underscores.
- This specification defines version 1 of the protocol. Methods carry no version suffix. Future versions MAY use `METHOD/N` syntax (e.g., `PUSH/2`) to indicate a newer version while maintaining backward compatibility.

### 1.4 Terminology

| Term | Meaning |
|---|---|
| **Frame** | A TagoTiP text message (e.g., `PUSH\|AUTH\|SERIAL\|BODY`) |
| **Message** | The abstract unit of communication — either a frame or an envelope |
| **Uplink** | Client → Server direction |
| **Downlink** | Server → Client direction |

---

## 2. Credentials

Credentials are scoped to an **Account/Profile** (not to an individual device). A single profile may contain multiple devices, and the same credentials are used to authenticate traffic for any device that belongs to that profile.

| Credential | Format | Secrecy | Purpose |
|---|---|---|---|
| **Authorization Token** | `at` + 32 hex chars (34 chars total, e.g., `ate2bd319014b24e0a8aca9f00aea4c0d0`) | Secret | Identifies the Account/Profile. Used only to derive the Authorization Hash during device provisioning. Never transmitted on the wire. |
| **Authorization Hash** | 16 hex chars (8 bytes, e.g., `4deedd7bab8817ec`) | Public | Derived from the Authorization Token. Sent in TagoTiP frames to identify the Account/Profile. Safe to display in logs/UIs. |

**Authorization Hash derivation:**

```
Token:  ate2bd319014b24e0a8aca9f00aea4c0d0
Input:  e2bd319014b24e0a8aca9f00aea4c0d0     (strip "at" prefix)
Hash:   SHA-256 of input (UTF-8 bytes)
Result: first 8 bytes as 16 hex chars
```

The server uses the Authorization Hash to resolve the Account/Profile, then routes the message to the device identified by the SERIAL field in the frame header.

> **Note:** TagoTiP/S uses additional credentials (Device Hash, Encryption Key) for the crypto envelope. See [TagoTiPs.md](TagoTiPs.md).

---

## 3. Transport Notes (Non-Normative)

The following guidance is non-normative and intended to help implementers.

| Transport | Frame Delimiter | Notes |
|---|---|---|
| TCP | `\n` (0x0A) terminates each frame | Server buffers bytes until `\n` is received. Clients SHOULD reuse connections. |
| UDP | End of datagram | Each datagram contains exactly one frame. `\n` terminator is OPTIONAL. |
| HTTP(S) | HTTP body | One frame per request body. Method and headers are transport-level. |
| MQTT | MQTT payload | One frame per MQTT message. Topic structure is transport-level. |

The `\n` byte (0x0A) MUST NOT appear inside frame field values. On stream transports (TCP), it terminates the frame. On message transports (UDP, MQTT, HTTP), it is unnecessary but harmless if present.

> **Normative clarification:** The ABNF grammar defines frames with a trailing `LF` for the canonical wire format. On message-boundary transports (UDP, MQTT, HTTP body), the trailing `LF` is OPTIONAL — receivers on these transports MUST accept frames both with and without a trailing `LF`. On stream transports (TCP), the trailing `LF` is REQUIRED as the frame delimiter.

**CMD Delivery (Non-Normative):** On connection-oriented transports (TCP), the server MAY send CMD frames at any time. On pub/sub transports (MQTT), the server MAY publish to device-specific topics. On request-response transports (HTTP, UDP), CMD frames are delivered as responses to client requests — clients SHOULD use periodic PING to poll for pending commands.

---

## 4. Frame Structure

Each TagoTiP frame addresses exactly **one device**. To send data for multiple devices, the client sends multiple frames (one per device).

### 4.1 Uplink Frames (Client → Server)

> **Note:** The full frame structure described here applies to plaintext TagoTiP. When transmitted inside a TagoTiP/S envelope, a compact "headless" variant is used instead — see [TagoTiPs.md §4](TagoTiPs.md#4-headless-inner-frame).

Every uplink TagoTiP frame follows a pipe-delimited structure:

**Without sequence counter:**

```
METHOD|AUTH|SERIAL|BODY\n
METHOD|AUTH|SERIAL\n            ← PING (no body)
```

**With sequence counter:**

```
METHOD|!N|AUTH|SERIAL|BODY\n
METHOD|!N|AUTH|SERIAL\n         ← PING (no body)
```

| Field | Required | Description |
|---|---|---|
| `METHOD` | Yes | The action to perform (see §5) |
| `!N` | No | Sequence counter — `!` prefix + decimal integer (e.g., `!42`) |
| `AUTH` | Yes | Authorization Hash (16 hex chars, 8 bytes of SHA-256) |
| `SERIAL` | Yes | Device serial number (target device identifier) |
| `BODY` | Depends | Method-specific payload (see §6–§8). Omitted for PING. |

- Fields are separated by the pipe character `|` (byte `0x7C`)
- The `!` prefix distinguishes the optional counter field from the AUTH field (hex characters `0-9`, `a-f` never start with `!`)

**Examples:**

```
PUSH|4deedd7bab8817ec|sensor-01|[temperature:=32]
PUSH|!42|4deedd7bab8817ec|sensor-01|[temperature:=32]
PING|4deedd7bab8817ec|sensor-01
PING|!5|4deedd7bab8817ec|sensor-01
```

### 4.2 Downlink Frames (Server → Client)

All server-to-client communication uses the `ACK` frame format. This is a simplified frame — no AUTH field:

```
ACK|!N|STATUS|DETAIL\n     ← correlated response (echoes uplink counter)
ACK|!N|STATUS\n             ← correlated response (no detail)
ACK|STATUS|DETAIL\n         ← unsolicited or no-counter client
ACK|STATUS\n
```

| Field | Required | Description |
|---|---|---|
| `!N` | No | Optional — echoes the sequence counter from the uplink request. Present only when the uplink frame included `!N`. |
| `STATUS` | Yes | Result code |
| `DETAIL` | No | Additional information |

The server does not need to authenticate itself to the client. When the uplink frame includes a sequence counter (`!N`), the server echoes the same value in the ACK response (see §9.5). ACK frames without `!N` are either responses to requests that had no counter, or unsolicited server-initiated messages (e.g., CMD). This allows clients to correlate responses to requests on pipelined connections.

See §9 for the full ACK specification including status codes for responses and commands.

### 4.3 Authentication

The **Authorization Hash** identifies the **Account/Profile**. The **SERIAL** field identifies the target device.

The server MUST:
1. Resolve the Account/Profile by Authorization Hash.
2. Verify that the `SERIAL` belongs to that Account/Profile.
3. Reject the request if the `SERIAL` does not belong to the profile (`ACK|ERR|device_not_found`).

For passthrough payloads (`>x`, `>b`), the SERIAL field still identifies the target device. The payload parser receives the raw data associated with that device (see §6.5).

### 4.4 Escaping

Escaping is supported inside **string values** (`VALCHAR`) and **metadata values** (`METAVALCHAR`). Unit strings (`UNITCHAR`) do **not** support escape sequences — they are plain text terminated by structural characters.

**Rule:** A backslash (`\`) escapes the next byte, producing the literal character. This applies to any reserved/structural character, including:
`|`, `[`, `]`, `;`, `,`, `{`, `}`, `#`, `@`, `^`, `\`, and `n` (newline escape).

| Sequence | Meaning |
|---|---|
| `\n` | Literal newline character (U+000A) in the decoded value (note: the raw byte `0x0A` MUST NOT appear on stream transports) |
| `\\` | Literal `\` |
| `\|` | Literal `|` |
| `\[` | Literal `[` |
| `\]` | Literal `]` |
| `\;` | Literal `;` |
| `\,` | Literal `,` |
| `\{` | Literal `{` |
| `\}` | Literal `}` |
| `\#` | Literal `#` |
| `\@` | Literal `@` |
| `\^` | Literal `^` |

On the wire, `\n` is the two-byte sequence `0x5C 0x6E` (backslash + lowercase n), which parsers decode to U+000A in the application-layer value.

A real newline byte (`0x0A`) always terminates a frame on stream transports and MUST NOT appear in values.

**Note:** When splitting frame fields by `|`, parsers MUST respect `\|` (backslash followed by pipe) as an escape sequence, not a field delimiter. The same applies to all structural characters within their respective contexts (e.g., `\;` inside variable lists, `\,` inside metadata blocks, `\}` inside metadata blocks).

### 4.5 Size Limits

To ensure predictable memory usage on embedded clients and consistent server behavior:

- **Max plaintext frame size:** The server MUST reject any frame whose UTF-8 byte length exceeds **16,384 bytes** (excluding the optional `\n` terminator on stream transports) with `ACK|ERR|payload_too_large`.

Implementations MAY support larger limits, but clients SHOULD target this limit for maximum compatibility.

#### 4.5.1 Field-Level Limits

To enable safe fixed-buffer pre-allocation in C and other memory-constrained implementations, the following limits apply to **identifiers** (names and keys):

| Field | Max bytes | Reference |
|---|---|---|
| Variable name (`var-name`) | 100 | TagoIO platform: max 100 characters |
| Serial number (`serial`) | 100 | Aligned with variable name limit |
| Group name (`group`) | 100 | TagoIO platform: max 100 characters |
| Metadata key (`meta-key`) | 100 | Follows variable name rules |
| Unit string (`unit`) | 25 | TagoIO platform: max 25 characters |

The following limits apply to **element counts**:

| Field | Max count | Rationale |
|---|---|---|
| Variables per `[]` block (`var-list`, `pull-list`) | 100 | Generous for dataloggers; fits within frame budget |
| Metadata pairs per `{}` block (`meta-list`) | 32 | Sufficient for IoT; power-of-2 for C buffer sizing |

All limits above are normative: a frame that exceeds any of these limits MUST be rejected by the server with `ACK|ERR|invalid_payload`.

Number values, boolean values, location coordinates, and timestamp values are inherently bounded by their format definitions (§6.3.1) and do not require separate length limits.

String values and metadata values are bounded by the frame size limit (§4.5) and by application-level platform limits. The protocol does not define per-value byte limits.

All byte lengths are measured as UTF-8 encoded bytes. Since identifier fields (`VARNAMECHAR`, `SERIALCHAR`) are ASCII-only, the byte count equals the character count.

Implementations MAY enforce lower limits and SHOULD document their supported maximums.

---

## 5. Methods

### 5.1 Uplink Methods (Client → Server)

| Method | Purpose | Body Required |
|---|---|---|
| `PUSH` | Send data to a device | Yes |
| `PULL` | Retrieve last value of one or more variables | Yes |
| `PING` | Keepalive / connectivity test | No |

For real-time subscriptions to variable changes, use a transport that natively supports pub/sub (e.g., MQTT).

### 5.2 Downlink (Server → Client)

All downlink communication uses the `ACK` frame. The `STATUS` field determines the purpose:

| Status | Purpose | Example |
|---|---|---|
| `OK` | Successful response to PUSH, PULL | `ACK\|OK\|3`, `ACK\|!1\|OK\|3` |
| `PONG` | Response to PING | `ACK\|PONG`, `ACK\|!2\|PONG` |
| `CMD` | Server-initiated command | `ACK\|CMD\|reboot` (unsolicited, no counter) |
| `ERR` | Error response | `ACK\|ERR\|invalid_token`, `ACK\|!5\|ERR\|invalid_payload` |

See §9 for the full ACK specification.

---

## 6. PUSH — Sending Data

### 6.1 Basic Structure

```
PUSH|AUTH|SERIAL|BODY
PUSH|!N|AUTH|SERIAL|BODY
```

Where `BODY` is either a structured variable block or a passthrough payload:

```
PUSH|AUTH|SERIAL|^GROUP@TIMESTAMP{META}[variables]     ← structured
PUSH|AUTH|SERIAL|>xHEXDATA                             ← passthrough (hex)
PUSH|AUTH|SERIAL|>bBASE64DATA                          ← passthrough (base64)
```

### 6.2 Body-Level Modifiers

Optional body-level modifiers may appear before the variable block. They set defaults that cascade to all variables in the body:

```
PUSH|AUTH|SERIAL|^GROUP @TIMESTAMP {METADATA} [variables]
```

> *Spaces shown for readability only — not present in actual frames.*

| Component | Required | Prefix | Description |
|---|---|---|---|
| `^GROUP` | No | `^` | Group ID applied to all variables |
| `@TIMESTAMP` | No | `@` | Timestamp (ms) applied to all variables |
| `{METADATA}` | No | `{}` | Metadata applied to all variables |
| `[variables]` | Yes | `[]` | Variable block (always present for structured PUSH) |

Body-level modifiers MUST appear in the order shown (`^GROUP`, `@TIMESTAMP`, `{METADATA}`) when present. Each modifier MAY be omitted, but those present MUST follow this order. If the same modifier type appears more than once, the frame MUST be rejected with `invalid_payload`.

### 6.3 Variable Syntax

Variables are separated by semicolons (`;`) inside the brackets. Each variable follows this structure:

```
NAME OPERATOR VALUE #UNIT @TIMESTAMP ^GROUP {METADATA}
```

All suffixes are optional and MUST appear in the order shown when present.

The variable list inside `[]` MUST contain at least one variable. Empty blocks (`[]`) MUST be rejected with `invalid_payload`.

Metadata blocks MUST contain at least one key-value pair. Empty metadata blocks (`{}`) MUST be rejected with `invalid_payload`.

The same variable name MAY appear multiple times within a single variable block. Each occurrence is treated as a separate data point (useful for batch uploads — see §11.7).

PUSH frames are **atomic**: if any variable in the block fails validation (malformed operator, invalid value, illegal suffix combination), the server MUST reject the entire frame with `ACK|ERR|invalid_payload`. No partial acceptance.

#### 6.3.1 Operators (Type Hints)

| Operator | Type | Value Format | Example |
|---|---|---|---|
| `:=` | Number | Integer or decimal | `temperature:=32.5` |
| `=` | String | Text | `status=running` |
| `?=` | Boolean | `true` or `false` | `active?=true` |
| `@=` | Location | `lat,lng` or `lat,lng,alt` | `position@=39.74,-104.99` |

Number values MUST match the pattern `-?(0|[1-9][0-9]*)(\.[0-9]+)?` — an optional minus sign, one or more digits, and an optional decimal fraction. Scientific notation, leading zeros (except in `0` and `0.x` forms), and special values (`NaN`, `Infinity`) are not valid.

String values MUST contain at least one character. Empty values (e.g., `status=`) are not valid.

Boolean values MUST be the exact lowercase strings `true` or `false`.

Location coordinates follow the same numeric format as the number type. Validation of coordinate ranges (e.g., latitude −90 to 90, longitude −180 to 180) is application-level and not enforced by the protocol parser.

#### 6.3.2 Suffixes

| Suffix | Prefix | Description | Example |
|---|---|---|---|
| Unit | `#` | Unit of measurement | `temperature:=32#F` |
| Timestamp | `@` | UNIX timestamp in milliseconds | `temperature:=32@1694567890000` |
| Group | `^` | Group ID for linking data points | `temperature:=32^reading_001` |
| Metadata | `{}` | Key-value pairs separated by `,` | `temperature:=32{source=dht22,quality=high}` |

The `#unit` suffix MUST NOT be used with the location operator (`@=`). A `#` character after a location value is a **parse error** — the server MUST reject the frame with `invalid_payload`. Altitude in a location triple is always in meters.

Metadata keys follow the same character rules as variable names (lowercase alphanumeric and underscore). Metadata keys do not support escape sequences — they are restricted to the identifier charset (`[a-z0-9_]`), which contains no structural characters. Metadata values follow the same encoding rules as string values (printable UTF-8, with escaping for structural characters).

#### 6.3.3 Full Variable Form

With all optional suffixes:

```
temperature:=32.5#C@1694567890000^reading_001{source=dht22,quality=high}
```

### 6.4 Inheritance Rules

Body-level modifiers cascade to all variables in the body:

```
PUSH|4deedd7bab8817ec|sensor-01|^batch_42@1694567890000{firmware=2.1}[temp:=32#C;humidity:=65#%]
```

Both `temp` and `humidity` inherit:
- Group: `batch_42`
- Timestamp: `1694567890000`
- Metadata: `firmware=2.1`

Variable-level modifiers **override** body-level:

```
PUSH|4deedd7bab8817ec|sensor-01|@1694567890000[temp:=32@1694567891000;humidity:=65]
```

Here `temp` uses its own timestamp `1694567891000`, while `humidity` uses the body-level `1694567890000`.

For metadata, variable-level **merges** with body-level (variable wins on key conflicts):

```
PUSH|4deedd7bab8817ec|sensor-01|{firmware=2.1}[temp:=32{source=dht22};humidity:=65]
```

- `temp` has metadata: `{firmware: "2.1", source: "dht22"}`
- `humidity` has metadata: `{firmware: "2.1"}`

### 6.5 Passthrough

When a device needs to send raw data instead of structured variables, the BODY begins with `>` followed by an encoding flag:

| Prefix | Encoding | Delivered As | Example |
|---|---|---|---|
| `>x` | Hexadecimal | Raw buffer (bytes) — hex is decoded | `PUSH\|AUTH\|SERIAL\|>xDEADBEEF01020304` |
| `>b` | Base64 | Text string (base64) — delivered as-is, parser decodes if needed | `PUSH\|AUTH\|SERIAL\|>b3q2+7wECAwQ=` |

The `>` prefix signals **passthrough mode**: the server authenticates the frame (validates AUTH), identifies the target device (by SERIAL), but does NOT parse the BODY as variables. The data is delivered to the device's payload parser:

- `>x` → the hex string is decoded and delivered as a **raw byte buffer**. The hex string MUST have an even number of characters (each byte is two hex digits); odd-length hex MUST be rejected with `invalid_payload`.
- `>b` → the base64 string is delivered as a **text string** (the payload parser is responsible for decoding if needed)

Passthrough mode (`>x`, `>b`) is **uplink-only**.

The payload parser receives the raw data and can process it however needed. If the decoded data happens to be a TagoTiP frame (e.g., a device that encodes TagoTiP text as hex), a TagoTiP parser helper function is available in the payload parser environment to convert it to structured JSON objects.

```
PUSH|4deedd7bab8817ec|sensor-01|>xDEADBEEF01020304
PUSH|4deedd7bab8817ec|sensor-01|>b3q2+7wECAwQ=
```

The effective maximum passthrough data size depends on the frame budget remaining after method, auth, serial, and `>x`/`>b` prefix fields.

---

## 7. PULL — Retrieving Data

### 7.1 Request

```
PULL|AUTH|SERIAL|[VAR_NAME;VAR_NAME;...]
```

Retrieves the last stored value of one or more variables from the specified device. Variable names are enclosed in brackets (`[]`) and separated by semicolons (`;`), matching the PUSH body syntax. Even a single variable MUST be bracket-wrapped.

### 7.2 Response

The server MUST return the found variables in bracket-wrapped standard syntax:

```
ACK|OK|[VARIABLE OPERATOR VALUE #UNIT @TIMESTAMP ^GROUP {METADATA};...]
```

The response always uses bracket-wrapped variable syntax, matching the PUSH body format. Only found variables are included — variables that do not exist or have no stored values are silently omitted. If **none** of the requested variables are found, the server MUST respond with `ACK|ERR|variable_not_found`.

The server does not echo the serial in ACK responses (see §9).

Examples:

```
→ PULL|4deedd7bab8817ec|weather-denver|[temperature]
← ACK|OK|[temperature:=32#F@1694567890000]

→ PULL|4deedd7bab8817ec|weather-denver|[temperature;humidity;pressure]
← ACK|OK|[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]
```

In the second example, `pressure` was requested but not found — it is silently omitted from the response.

---

## 8. PING — Keepalive

### 8.1 Request

```
PING|AUTH|SERIAL
```

No body field. The SERIAL field identifies the device performing the keepalive.

### 8.2 Response

```
ACK|PONG
```

---

## 9. ACK — Server Response

All downlink communication uses the `ACK` frame:

```
ACK|!N|STATUS|DETAIL
ACK|!N|STATUS
ACK|STATUS|DETAIL
ACK|STATUS
```

| Field | Required | Description |
|---|---|---|
| `!N` | No | Echoed sequence counter from uplink request (`!` prefix + decimal integer) |
| `STATUS` | Yes | Result code |
| `DETAIL` | No | Additional information |

ACK frames never include a device serial number. A device may have multiple associated serials (e.g., after hardware replacement), so the server does not echo a serial in responses. The client already knows which device it addressed in the uplink request.

### 9.1 Status Codes

When `!N` is present, it appears between `ACK` and `STATUS` (e.g., `ACK|!1|OK|3`). The status codes themselves are unchanged:

| Status | Meaning | Detail |
|---|---|---|
| `OK` | Operation succeeded | For PUSH: decimal count of data points added to the device bucket. This applies to both structured payloads and passthrough payloads (`>x`, `>b`) — in the latter case, the count reflects data points produced by the payload parser. For PULL: bracket-wrapped variable list in standard syntax (see §7.2). `ACK|OK|0` is valid and means the frame was accepted but produced no data points (e.g., all variables were filtered by the payload parser). |
| `PONG` | Response to PING | — |
| `CMD` | Server-initiated command | Command string (application-defined) |
| `ERR` | Operation failed | Error code |

### 9.2 Error Codes

| Detail | Meaning |
|---|---|
| `invalid_token` | Authorization Hash is missing, expired, or invalid |
| `invalid_method` | Unknown method |
| `invalid_payload` | Malformed body / parse error |
| `invalid_seq` | Sequence counter is not greater than last accepted value |
| `device_not_found` | Device serial is not found under the authenticated Account/Profile |
| `variable_not_found` | No requested variables exist or have stored values (for PULL) |
| `rate_limited` | Rate limit exceeded |
| `auth_failed` | TagoTiP/S envelope authentication or decryption failed |
| `unsupported_version` | TagoTiP/S envelope version is not supported by the server |
| `payload_too_large` | Frame exceeds maximum size |
| `server_error` | Internal server error |

### 9.3 Examples

Without sequence counter (unsolicited or no-counter client):

```
ACK|OK|2
ACK|OK|[temperature:=32#F@1694567890000]
ACK|PONG
ACK|CMD|reboot
ACK|CMD|ota=https://example.com/v2.1.bin
ACK|ERR|invalid_token
ACK|ERR|invalid_payload
ACK|ERR|auth_failed
```

With sequence counter (correlated responses):

```
ACK|!1|OK|2
ACK|!2|OK|[temperature:=32#F@1694567890000]
ACK|!3|PONG
ACK|CMD|reboot                    ← unsolicited, no counter
ACK|!5|ERR|invalid_token
ACK|!6|ERR|invalid_seq
ACK|!7|ERR|invalid_payload
```

### 9.4 Client Guidance (Non-Normative)

- Clients receiving `rate_limited` SHOULD implement exponential backoff.
- `invalid_token` SHOULD NOT be retried without re-provisioning.
- `server_error` MAY be retried after a delay.

### 9.5 Response Correlation

When the uplink frame includes a sequence counter (`!N`), the server MUST echo the same `!N` value in the ACK response. This allows clients to correlate responses to their originating requests on pipelined connections.

**Rules:**

- The server MUST echo `!N` when the uplink included it
- The server MUST NOT include `!N` in unsolicited messages (CMD pushed without a request)
- The client uses presence/absence of `!N` to distinguish solicited responses from unsolicited CMDs
- The `!` prefix disambiguates the counter from STATUS — status codes are alphabetic (`OK`, `PONG`, `CMD`, `ERR`) and never start with `!`

---

## 10. Sequence Counter (Optional)

TagoTiP supports an optional, monotonically increasing sequence counter. When used, the counter provides:

- **Replay protection** — the server rejects messages with a counter value it has already seen
- **Message ordering** — the server can detect out-of-order delivery
- **Deduplication** — the server can discard duplicate messages

> The counter also serves as a nonce component in TagoTiP/S. See [TagoTiPs.md](TagoTiPs.md).

### 10.1 Counter Rules

| Rule | Description |
|---|---|
| Size | 32-bit unsigned integer (0 to 4,294,967,295) |
| Initial value | Device chooses; `1` is RECOMMENDED |
| Increment | MUST be strictly increasing for each client→server message when enabled. Increment by exactly 1 is RECOMMENDED |
| Persistence | Device SHOULD persist the counter across reboots (e.g., in flash/EEPROM) |
| Wraparound | When the counter reaches `0xFFFFFFFF`, device MUST re-provision or reset with the server |

### 10.2 Server-Side Validation

When the server is configured to enforce sequence counters, it MUST maintain the last-seen counter value per device (identified by the SERIAL field).

When the server has no previously recorded counter for a device (first message ever, or after a server-side reset), the server MUST accept any valid counter value and store it as the new last-seen value.

The server SHOULD accept a message only if its counter is **strictly greater** than the last-seen value. The server MAY allow a configurable acceptance window to tolerate minor reordering. The counter MAY be reset by server-side policy (e.g., after an idle timeout or manual reset by the device owner).

Sequence counter validation (when enabled) applies to every uplink frame, including PING. The server MUST update the last-seen counter value regardless of method.

When the uplink frame includes a sequence counter, the server echoes it in the ACK response for correlation purposes (see §9.5). Sequence counter enforcement (monotonic validation) applies only to client→server messages.

### 10.3 Representation

In TagoTiP, the sequence counter is included in the frame header with a `!` prefix followed by the decimal integer:

```
PUSH|!42|4deedd7bab8817ec|sensor-01|[temperature:=32]
PING|!5|4deedd7bab8817ec|sensor-01
```

---

## 11. Examples

### 11.1 Simple Push

```
PUSH|4deedd7bab8817ec|weather-denver|[temperature:=32;humidity:=65]
```

### 11.2 Push with Sequence Counter

```
PUSH|!1|4deedd7bab8817ec|weather-denver|[temperature:=32;humidity:=65]
```

### 11.3 Typed Values

```
PUSH|4deedd7bab8817ec|sensor-0A1F|[temperature:=32.5#C;status=online;active?=true]
```

Negative number example:

```
PUSH|4deedd7bab8817ec|sensor-0A1F|[temperature:=-15.3#C]
```

### 11.4 With Location and Altitude

```
PUSH|4deedd7bab8817ec|drone-07|[altitude:=305#m;position@=39.74,-104.99,305]
```

### 11.5 With Metadata

```
PUSH|4deedd7bab8817ec|sensor-01|[temperature:=32{source=dht22,quality=high}]
```

### 11.6 Body-Level Defaults

```
PUSH|4deedd7bab8817ec|sensor-01|^batch_42@1694567890000{firmware=2.1}[temperature:=32#C;humidity:=65#%]
```

### 11.7 Variable-Level Timestamps (Datalogger)

```
PUSH|4deedd7bab8817ec|datalogger-7|[temp:=32@1694567890000;temp:=33@1694567900000;temp:=31@1694567910000]
```

### 11.8 Passthrough (Hex)

```
PUSH|4deedd7bab8817ec|sensor-01|>xDEADBEEF01020304
```

### 11.9 Passthrough (Base64)

```
PUSH|4deedd7bab8817ec|sensor-01|>b3q2+7wECAwQ=
```

### 11.10 Retrieve Last Value

```
PULL|4deedd7bab8817ec|weather-denver|[temperature]
```

### 11.11 Retrieve Last Value with Sequence Counter

```
PULL|!7|4deedd7bab8817ec|weather-denver|[temperature]
```

### 11.12 Keepalive

```
PING|4deedd7bab8817ec|sensor-01
```

### 11.13 Full Conversation Flow

```
→ PING|4deedd7bab8817ec|weather-denver
← ACK|PONG

→ PUSH|4deedd7bab8817ec|weather-denver|[temperature:=32#F;humidity:=65#%;active?=true]
← ACK|OK|3

→ PULL|4deedd7bab8817ec|weather-denver|[temperature]
← ACK|OK|[temperature:=32#F@1694567890000]

← ACK|CMD|reboot

→ PUSH|4deedd7bab8817ec|weather-denver|[invalid=broken
← ACK|ERR|invalid_payload
```

### 11.14 Conversation with Sequence Counter

```
→ PING|!1|4deedd7bab8817ec|weather-denver
← ACK|!1|PONG

→ PUSH|!2|4deedd7bab8817ec|weather-denver|[temperature:=32#F]
← ACK|!2|OK|1

→ PUSH|!3|4deedd7bab8817ec|weather-denver|[humidity:=65#%]
← ACK|!3|OK|1

→ PUSH|!2|4deedd7bab8817ec|weather-denver|[pressure:=1013#hPa]
← ACK|!2|ERR|invalid_seq
```

---

## 12. Parsing Rules

### 12.1 Frame Parsing

1. Read the message (delimited by transport: `\n` for TCP, end of datagram for UDP, end of HTTP body, etc.)
2. Split by `|` into fields (respecting `\|` escape sequences)
3. If field 1 is `ACK`, check if field 2 starts with `!` — if yes, parse as `[ACK, SEQ, STATUS[, DETAIL]]`; otherwise parse as `[ACK, STATUS[, DETAIL]]`
4. Otherwise, check if field 2 starts with `!` — if yes, parse as `[METHOD, SEQ, AUTH, SERIAL[, BODY]]`; otherwise parse as `[METHOD, AUTH, SERIAL[, BODY]]`
5. Validate METHOD against known methods
6. If SEQ is present in an uplink frame, parse the decimal integer after `!` and validate against the last-seen counter (when counter enforcement is enabled; see §10.2)
7. Route to method-specific parser

**Field-count matrix (after `|`-splitting, respecting escapes):**

| Method | With `!N` | Without `!N` | Notes |
|---|---|---|---|
| PUSH | `METHOD \| SEQ \| AUTH \| SERIAL \| BODY` (5 fields) | `METHOD \| AUTH \| SERIAL \| BODY` (4 fields) | BODY is required |
| PULL | `METHOD \| SEQ \| AUTH \| SERIAL \| BODY` (5 fields) | `METHOD \| AUTH \| SERIAL \| BODY` (4 fields) | BODY = `[VARNAME;...]` |
| PING | `METHOD \| SEQ \| AUTH \| SERIAL` (4 fields) | `METHOD \| AUTH \| SERIAL` (3 fields) | No BODY |
| ACK  | `ACK \| SEQ \| STATUS \| DETAIL` (4 fields) | `ACK \| STATUS \| DETAIL` (3 fields) | DETAIL is optional → min 2 or 3 fields |

For ACK without `!N`: minimum 2 fields (`ACK|STATUS`), maximum 3 (`ACK|STATUS|DETAIL`).
For ACK with `!N`: minimum 3 fields (`ACK|!N|STATUS`), maximum 4 (`ACK|!N|STATUS|DETAIL`).

### 12.2 PUSH Body Parsing

1. If BODY starts with `>`, this is a **passthrough**: read encoding flag (`x` or `b`), deliver the data to the payload parser without further parsing
2. Otherwise, scan for `[` — everything before `[` is body-level modifiers, everything inside `[]` is variables
3. Parse body-level modifiers for optional `^GROUP`, `@TIMESTAMP`, `{METADATA}` (MUST appear in this order when present; reject duplicates with `invalid_payload`)
4. Split variable content by `;` into individual variables (respecting `\;` escape)
5. For each variable, parse left-to-right (single pass, no backtracking):
   - **Name**: Read until operator is found (`:=`, `?=`, `@=`, or `=`)
   - **Operator**: Determines value type
   - **Value**: Read until `#`, `@`, `^`, `{`, `;`, or `]` (respecting escapes)
   - **#unit**: If `#` found, read until `@`, `^`, `{`, `;`, or `]`. MUST NOT appear with `@=` operator.
   - **@timestamp**: If `@` found, read digits until `^`, `{`, `;`, or `]`
   - **^group**: If `^` found, read until `{`, `;`, or `]`
   - **{metadata}**: If `{` found, read until `}` and parse key-value pairs by `,` (respecting `\,` and `\}` escapes). Each metadata pair is split on the first `=`; subsequent `=` characters are part of the value.

### 12.3 PULL Body Parsing

The BODY is a bracket-wrapped list of variable names: `[var1;var2;...]`. Strip the enclosing `[` and `]`, then split by `;` to obtain individual variable names, each matching `1*VARNAMECHAR`. A single variable is valid (e.g., `[temperature]`).

### 12.4 Operator Disambiguation

The parser MUST check for multi-character operators first:

1. Check for `:=` → Number
2. Check for `?=` → Boolean
3. Check for `@=` → Location
4. Fallback to `=` → String

---

## 13. Size Comparison

The same data point expressed across formats:

**HTTP/JSON (~487 bytes with headers):**

```json
{
  "variable": "temperature",
  "value": 32,
  "unit": "F",
  "group": "batch-42",
  "time": "1694567890000",
  "location": {"lat": 39.74, "lng": -104.99},
  "metadata": {"source": "dht22"}
}
```

**TagoTiP (~112 bytes):**

```
PUSH|4deedd7bab8817ec|sensor-01|^batch_42@1694567890000[temperature:=32#F;position@=39.74,-104.99{source=dht22}]
```

**TagoTiP/S (~115 bytes):**

```
Headless inner frame (90 bytes):
  sensor-01|^batch_42@1694567890000[temperature:=32#F;position@=39.74,-104.99{source=dht22}]
  (removed "PUSH|4deedd7bab8817ec|" = 22 bytes)
Envelope: 1 (flags) + 4 (counter) + 8 (auth hash) + 4 (device hash) + 90 (ciphertext) + 8 (auth tag) = 115 bytes
```

| Format | Approximate Size | vs. HTTP/JSON |
|---|---|---|
| HTTP/JSON | ~487 bytes | — |
| TagoTiP | ~112 bytes | ~4.3× smaller |
| TagoTiP/S | ~115 bytes | ~4.2× smaller |

TagoTiP sizes exclude transport-layer overhead (TCP/IP headers). The HTTP/JSON body alone is ~180 bytes; the ~487 figure includes typical HTTP request headers. TagoTiP/S adds encryption overhead (25-33 bytes depending on cipher suite) but removes the method and auth hash fields from the inner frame.

---

## 14. Grammar (ABNF)

```abnf
; Core rules (ALPHA, DIGIT, HEXDIG, LF, etc.) per RFC 5234, Appendix B.

; === Uplink Frames (Client → Server) ===
; LF is REQUIRED on stream transports (TCP); OPTIONAL on message transports (UDP, MQTT, HTTP)

frame           = push-frame / pull-frame / ping-frame

push-frame      = "PUSH" "|" [seq "|"] auth "|" serial "|" push-body LF
pull-frame      = "PULL" "|" [seq "|"] auth "|" serial "|" pull-body LF
ping-frame      = "PING" "|" [seq "|"] auth "|" serial LF
                                                        ; Future: METHOD "/" 1*DIGIT

seq             = "!" counter-value                     ; Optional sequence counter
counter-value   = "0" / (%x31-39 *DIGIT)               ; No leading zeros

auth            = 16HEXDIG                               ; Authorization Hash (8 bytes as hex)

serial          = 1*100SERIALCHAR                        ; Device serial number (max 100 bytes)

; PUSH
push-body       = passthrough-body / structured-body
passthrough-body = ">x" 1*(2HEXDIG)                     ; Hex-encoded passthrough (byte pairs)
                / ">b" 1*BASE64CHAR                     ; Base64-encoded passthrough
structured-body = [body-mods] "[" var-list "]"
body-mods       = ["^" group] ["@" timestamp] ["{" meta-list "}"]
var-list        = variable *99(";" variable)              ; max 100 variables

variable        = var-name ":=" num-value [common-suffixes]
                / var-name "=" str-value [common-suffixes]
                / var-name "?=" bool-value [common-suffixes]
                / var-name "@=" loc-value [loc-suffixes]

var-name        = 1*100VARNAMECHAR                       ; max 100 bytes

num-value       = ["-"] int-part ["." 1*DIGIT]
int-part        = "0" / (%x31-39 *DIGIT)              ; 0, or non-zero digit followed by any digits
str-value       = 1*VALCHAR
bool-value      = "true" / "false"
loc-value       = coordinate "," coordinate ["," coordinate]
coordinate      = ["-"] int-part ["." 1*DIGIT]

common-suffixes = ["#" unit] ["@" timestamp] ["^" group] ["{" meta-list "}"]
loc-suffixes    = ["@" timestamp] ["^" group] ["{" meta-list "}"]
                                                        ; no #unit for location (§6.3.2)

unit            = 1*25UNITCHAR                           ; max 25 bytes
timestamp       = 1*DIGIT                              ; UNIX ms
group           = 1*100VARNAMECHAR                       ; max 100 bytes
meta-list       = meta-pair *31("," meta-pair)           ; max 32 metadata pairs
meta-pair       = meta-key "=" meta-value
meta-key        = 1*100VARNAMECHAR                       ; max 100 bytes
meta-value      = 1*METAVALCHAR

; PULL
pull-body       = "[" pull-list "]"
pull-list       = var-name *99(";" var-name)              ; max 100 variables

pull-response   = "[" var-list "]"                          ; Bracket-wrapped, same as PUSH body

; === Downlink Frames (Server → Client) ===

ack-frame       = "ACK" "|" [seq "|"] ack-status ["|" ack-detail] LF
                                                        ; seq starts with "!" — unambiguous vs. ack-status (alphabetic)
ack-status      = "OK" / "PONG" / "CMD" / "ERR"
ack-detail      = 1*DIGIT                              ; PUSH OK: count of accepted data points
                / pull-response                            ; PULL OK: bracket-wrapped variable list
                / 1*DETAILCHAR                             ; CMD detail or ERR error code

; Character classes below cover the ASCII subset only.
; Non-ASCII UTF-8 sequences (RFC 3629) are also valid in VALCHAR,
; METAVALCHAR, and UNITCHAR positions when the implementation supports UTF-8.

; === Character classes ===
VARNAMECHAR     = %x61-7A / DIGIT / "_"                ; lowercase a-z, digits, underscore
SERIALCHAR      = ALPHA / DIGIT / "-" / "_"            ; serial numbers (hyphens allowed)
VALCHAR         = %x20-22 / %x24-3A / %x3C-3F / %x41-5A / %x5F-60 / %x61-7A / %x7E
                / "\" ("|" / "[" / "]" / ";" / "," / "{" / "}" / "#" / "@" / "^" / "n" / "\")
                                                        ; printable ASCII excluding # ; @ [ \ ] ^ { | }
                                                        ; with escape sequences for structural characters
METAVALCHAR     = %x20-22 / %x24-2B / %x2D-3A / %x3C-3F / %x41-5A / %x5F-60 / %x61-7A / %x7E
                / "\" ("|" / "[" / "]" / ";" / "," / "{" / "}" / "#" / "@" / "^" / "n" / "\")
                                                        ; like VALCHAR but also excludes unescaped ","
UNITCHAR        = %x20-22 / %x24-3A / %x3C-3F / %x41-5A / %x5F-60 / %x61-7A / %x7E
                                                        ; printable ASCII excluding # ; @ [ \ ] ^ { | }
                                                        ; No escape sequences — units are plain text
DETAILCHAR      = %x21-7B / %x7D-7E                    ; VCHAR excluding "|"
BASE64CHAR      = ALPHA / DIGIT / "+" / "/" / "="
                                                        ; Padding position enforced by decoder
```

**Note:** The character classes above precisely exclude structural delimiters from their base ranges. `VALCHAR` allows unescaped `,` (used literally in string values), while `METAVALCHAR` excludes it (since `,` separates metadata pairs). The `variable` production is split by operator type to enforce type-specific value formats (§6.3) and the rule that `#unit` MUST NOT be used with `@=` (§6.3.2). See §12.2 for detailed parsing rules.

---

## 15. Symbol Reference

| Symbol | Meaning | Context |
|---|---|---|
| `\|` | Field separator | Frame level |
| `!` | Sequence counter prefix | Before counter value (e.g., `!42`) |
| `[]` | Variable block delimiters | Encloses variables for a device |
| `;` | Variable separator | Inside `[]` |
| `,` | Metadata pair separator | Inside `{}` |
| `:=` | Number assignment | Variable operator |
| `=` | String assignment | Variable operator |
| `?=` | Boolean assignment | Variable operator |
| `@=` | Location assignment | Variable operator |
| `#` | Unit suffix | After variable value |
| `@` | Timestamp suffix | After value/unit |
| `^` | Group suffix/prefix | Body-level modifier or variable level |
| `{}` | Metadata block | Body-level modifier or variable level |
| `>x` | Hex passthrough payload | PUSH body prefix |
| `>b` | Base64 passthrough payload | PUSH body prefix |
| `\n` | Frame terminator | Stream transports (TCP) |
| `\` | Escape prefix | Before `\|`, `;`, `]`, `}`, `n`, `\`, etc. |

---

## 16. Security Considerations

- The Authorization Hash is a truncated SHA-256 of the token; it does not expose the original token. However, TLS or equivalent transport-level encryption is RECOMMENDED in production environments
- Authorization Tokens SHOULD NOT be hardcoded in source code shared publicly
- The server MUST validate the Authorization Hash and match it against the Device Serial Number before processing any message
- The optional sequence counter provides replay protection but does NOT provide confidentiality

> For encryption-based security without TLS, see [TagoTiPs.md](TagoTiPs.md) (TagoTiP/S).

---

## 17. License

This specification is **open source**, published under the [Apache License 2.0](LICENSE).

Anyone is free to implement TagoTiP — clients, servers, libraries, gateways, or any other component — for any purpose, including commercial use, without requiring permission from TagoIO Inc. The Apache 2.0 license includes an express patent grant to all implementers.

The names "TagoTiP", "TagoTiP/S", and "TagoIO" are trademarks of TagoIO Inc. See [NOTICE](NOTICE) for trademark details.

Copyright 2026 TagoIO Inc.
