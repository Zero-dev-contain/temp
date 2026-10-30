# Eidolon — Secure Transport for Company Infrastructure

[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](#project-status)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/sagernet/sing-box)
[![Go Version](https://img.shields.io/badge/go-1.26+-blue.svg)](https://golang.org)
[![Core Engine](https://img.shields.io/badge/engine-Chromium%20Net%20%7C%20BoringSSL-red.svg)](https://chromium.googlesource.com/chromium/src/net/)
[![Carrier](https://img.shields.io/badge/carrier-MoQT%20%2F%20WebTransport--over--H3-purple.svg)](https://datatracker.ietf.org/wg/moq/about/)
[![Crypto](https://img.shields.io/badge/crypto-ChaCha20--Poly1305%20%7C%20AES--GCM%20%7C%20Hybrid--PQC-orange.svg)](https://tools.ietf.org/html/rfc8439)
[![License](https://img.shields.io/badge/license-GPLv3-lightgrey.svg)](LICENSE)
[![CGO](https://img.shields.io/badge/CGO-enabled-success.svg)](#prerequisites)

**Eidolon** is a secure, MITM-resistant transport for connecting company infrastructure over hostile or untrusted networks, built on a high-performance fork of [sing-box](https://github.com/SagerNet/sing-box). Its purpose is a hardened, authenticated, end-to-end-encrypted channel between client and server — one that an on-path adversary cannot read, splice, impersonate, or replay. To achieve browser-grade transport security without the subtle discrepancies of emulated stacks, Eidolon natively embeds Google Chromium's actual network stack (`net/`, BoringSSL, and Chromium QUIC/HTTP-3) via a high-throughput CGO/C++ bridge, and carries tunnel traffic as **real MoQT (Media over QUIC Transport) over WebTransport-over-HTTP/3**.

The security core is a **context-bound token handshake** that binds authentication to the session's ephemeral key material (defeating MITM key substitution and replay), an **independent inner AEAD layer** keyed from an RFC 5705 session exporter (so even a terminating front-end or a spoofed decoy cannot read the payload), and a **QUIC-native data plane** — reliable MoQT tracks for stream flows, QUIC datagrams with application-layer FEC for loss-tolerant flows, plus connection migration for seamless network handover.

Eidolon is also censorship- and DPI-resistant — authentic Chromium TLS/QUIC fingerprints, a zero-delay transparent decoy fallback for active probes, and an on-demand media cover service — but in this first stage that camouflage is deliberately kept low-profile rather than advertised. There is little sense in parading an armored vehicle a mile off; the stealth machinery is present and engaged, not on display.

> <small style="color: #6c757d;">*Note on nomenclature: the alpha doesn't invent anything groundbreaking — it weaves together already-proven concepts (authentic browser stacks, MoQT, exporter-bound AEAD, FEC) into one hardened channel. The next stage carries that idea in its name: **Weaver**.*</small>

---

## Project Status

**Eidolon (alpha).** The transport basis is complete and validated end-to-end: authentic Chromium carrier, MoQT data plane (reliable tracks + datagrams + app-layer FEC), context-bound authentication, inner AEAD, connection racing/migration, sleep/wake keep-alive, and the on-demand cover service. This is the foundation layer — a working, MITM-resistant secure channel.

**Next: Eidolon Weaver.** The follow-on stage adapts this basis to real company infrastructure — multi-node server topologies, key/secret lifecycle and federation at scale, operational tooling, and fleet management. Weaver is where the server-side work for production company deployments lands; it builds on the alpha, it does not replace it.

---

## Table of Contents

- [Project Status](#project-status)
- [Description & Threat Model](#description--threat-model)
  - [The Secure-Channel Problem](#the-secure-channel-problem)
  - [Threat Model & Mitigations](#threat-model--mitigations)
  - [Comparative Protocol Matrix](#comparative-protocol-matrix)
- [Key Features](#key-features)
  - [Secure Channel & Cryptography (core)](#secure-channel--cryptography-core)
  - [Transport & Resilience](#transport--resilience)
  - [Camouflage & Anti-Censorship (engaged, understated)](#camouflage--anti-censorship-engaged-understated)
  - [Deployment & Operational Modes](#deployment--operational-modes)
- [Architecture & Technical Design](#architecture--technical-design)
  - [High-Level Data Flow](#high-level-data-flow)
  - [Wire Protocol & Packet Specifications](#wire-protocol--packet-specifications)
  - [Cryptographic State Machine](#cryptographic-state-machine)
  - [Camouflage & DPI Evasion Subsystems](#camouflage--dpi-evasion-subsystems)
  - [Hybrid Multiplexer (QUIC-preferred MoQT + TCP fallback)](#hybrid-multiplexer-quic-preferred-moqt--tcp-fallback)
  - [Caddy Shield Reverse Proxy Fronting](#caddy-shield-reverse-proxy-fronting)
- [Configuration Guide](#configuration-guide)
  - [Inbound Configuration Options](#inbound-configuration-options)
  - [Outbound Configuration Options](#outbound-configuration-options)
  - [Deployment Scenarios](#deployment-scenarios)
    - [Scenario 1: Zero-Domain Fallback (Camouflage Mode)](#scenario-1-zero-domain-fallback-camouflage-mode)
    - [Scenario 2: Self-Hosted Mode (Standard TLS / Certificates)](#scenario-2-self-hosted-mode-standard-tls--certificates)
    - [Scenario 3: Caddy Shield Reverse Proxy Fronting](#scenario-3-caddy-shield-reverse-proxy-fronting)
    - [Scenario 4: Federated Key Management (Opora Sync)](#scenario-4-federated-key-management-opora-sync)
- [Quick Start & Deployment](#quick-start--deployment)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Running Server and Client](#running-server-and-client)
  - [Verifying Connectivity](#verifying-connectivity)
- [Troubleshooting & Security Considerations](#troubleshooting--security-considerations)
  - [Common Operational Issues](#common-operational-issues)
  - [Security Hardening Checklist](#security-hardening-checklist)
  - [Kernel Tuning (BBR & FQ)](#kernel-tuning-bbr--fq)
- [Development & Testing](#development--testing)
  - [Repository Layout](#repository-layout)
  - [Running the Physical Test Suite](#running-the-physical-test-suite)

---

## Description & Threat Model

### The Secure-Channel Problem

Eidolon's primary job is to carry a company's traffic between endpoints that sit on networks nobody controls — public internet, hostile ISPs, shared corporate Wi-Fi, mobile carriers. The adversary assumed is **on-path and active**: able to observe, inject, reset, redirect, and replay. The channel must therefore be:

1. **Confidential end-to-end** — readable only by the two endpoints, never by a terminating proxy, a TLS-intercepting middlebox, or a decoy the adversary stands up.
2. **MITM-resistant** — an attacker who records and replays a legitimate handshake, or who substitutes their own key material, must not be able to establish or hijack a session.
3. **Replay-proof and side-channel-hardened** — captured authenticators are single-use and time-bound, and validation leaks no timing information.
4. **Resilient** — it survives UDP blackholing, network handover (Wi-Fi↔cellular), and idle/sleep without tearing down the session or leaking a correlatable signature.

As a secondary property, the channel is also **indistinguishable from ordinary web traffic**, because the same active adversary frequently also performs traffic classification and will block what it can identify. Modern inspection goes well beyond IP blacklists and static SNI blocking:

1. **Active Probing**: Autonomous scanning clusters replay intercepted handshakes or issue probe variations against suspected endpoints to trigger distinct protocol responses, abnormal TCP resets, or customized TLS alert codes.
2. **TLS ClientHello Fingerprinting (JA3 / JA4)**: Middleboxes hash TLS extensions, cipher suites, curves, point formats, and ALPN tokens. Emulated stacks (Go `crypto/tls` or patched libraries) exhibit subtle discrepancies — extension ordering, GREASE values, signature algorithms — that reveal non-browser clients.
3. **HTTP/2 & HTTP/3 / QUIC Fingerprinting**: Inconsistencies in initial window sizes, header-table sizes, max concurrent streams, QUIC transport parameters, or frame interleaving expose emulated HTTP layers.
4. **Traffic Analysis & Website Fingerprinting (WF)**: ML classifiers (Deep Fingerprinting, k-FP, CUMUL) analyze packet direction, inter-arrival jitter, and cumulative size distributions. Even over TLS, unshaped sessions leak distinct patterns.

Eidolon neutralizes the confidentiality/MITM threats as its core guarantee, and treats the fingerprinting vectors as a camouflage layer that — per the project's current stage — stays engaged but understated.

### Threat Model & Mitigations

```
+---------------------------------------------------------------------------------------------------------+
|                                          ADVERSARY ATTACK VECTORS                                        |
+------------------------------------+------------------------------------+-------------------------------+
| Attack Vector                      | Adversary Mechanism                | Eidolon Physical Defense      |
+------------------------------------+------------------------------------+-------------------------------+
| Passive DPI / Signature Inspection | SNI scanning, packet header regex, | Native Chromium TLS 1.3 and   |
|                                    | protocol heuristics.               | QUIC stacks; zero plaintext   |
|                                    |                                    | proxy signatures on wire.     |
+------------------------------------+------------------------------------+-------------------------------+
| Active Probing & Replay            | TCP replay, SYN scans, malformed   | Zero-Delay Fallback: invalid  |
|                                    | ClientHellos, probe fuzzing.       | tokens transparently splice   |
|                                    |                                    | unmodified stream to decoy.   |
+------------------------------------+------------------------------------+-------------------------------+
| Replay / MitM Key Substitution     | Intercepting authorized ClientHello| Context-Bound HMAC: token is  |
|                                    | and replaying with adversary's     | cryptographically bound to    |
|                                    | ephemeral X25519 KeyShare.         | client's ephemeral KeyShare.  |
+------------------------------------+------------------------------------+-------------------------------+
| TLS & HTTP Fingerprinting          | JA3/JA4, QUIC transport params,    | Native Chromium C++ library   |
|                                    | HTTP/2 SETTINGS frame ordering.    | (`libeidolon.so`) generates   |
|                                    |                                    | authentic Chrome signatures.  |
+------------------------------------+------------------------------------+-------------------------------+
| Timing & Cache Side-Channels       | Byte-by-byte comparison timing,    | Strict constant-time HMAC     |
|                                    | cache-lookup latency variations.   | evaluation with dual-window   |
|                                    |                                    | symmetrical dummy lookups.    |
+------------------------------------+------------------------------------+-------------------------------+
| Website Fingerprinting (WF)        | Packet length distributions,       | PaddedConn (8-packet cutoff), |
|                                    | burst volumes, flow timing (RTT).  | BurstShaper (1-4MB chunking), |
|                                    |                                    | adaptive 15% chaffing.        |
+------------------------------------+------------------------------------+-------------------------------+
```

### Comparative Protocol Matrix

| Feature | Shadowsocks (2022) | Trojan / Trojan-Go | VMess / VLESS | Xray REALITY | NaïveProxy | **Eidolon** |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TLS / QUIC Stack** | None (Raw AEAD) | Go `crypto/tls` | Go / uTLS | Go / uTLS | Chromium Net Stack | **Chromium Net Stack (`libeidolon.so`)** |
| **Tunnel Carrier** | Raw TCP | TLS stream | TCP / mKCP / WS | TLS stream | HTTP/2 CONNECT | **Real MoQT over WebTransport-over-H3** |
| **Active Probing Defense** | None (Drop/RST) | Decoy Website | Decoy Website | Decoy TLS Splice | Frontend Forwarding (Caddy) | **Zero-Delay Fallback & Caddy Shield** |
| **Authentication Placement**| Initial Salt / Header | TLS Password (Body) | Header / Addons | TLS ClientHello SessionID | HTTP Authorization Header | **In-band carrier preamble (QUIC); SessionID on TCP fallback**|
| **MITM / KeyShare Substitution Defense**| N/A | No | No | No | N/A | **Yes (token binds client ephemeral KeyShare)** |
| **Timing Side-Channel Immunity** | Partial | No | No | Partial | High | **Yes (Full constant-time + dummy cache)** |
| **Data Plane** | Stream | Stream | Stream | Stream | HTTP/2 Streams | **MoQT reliable tracks + QUIC datagrams (RFC 9221) + app-layer FEC**|
| **Transport Selection** | Single | Single | Single | Single | Single | **QUIC-preferred racing + TCP (smux) fallback (Happy-Eyeballs)**|
| **Network Handover** | No | No | No | No | No | **Yes (QUIC connection migration, Wi-Fi↔cellular)** |
| **Traffic Shaping / Chaffing**| None | None | None | None | First 8 reads/writes padding | **PaddedConn + Adaptive Chaff; DASH/HLS BurstShaper on fallback**|
| **Post-Quantum Cryptography**| None | None | Experimental | Limited | Dependent on Chrome | **Chromium-native hybrid (X25519 + ML-KEM/Kyber)** |
| **Deployment Flexibility** | Standalone | Web Server | Web Server | Standalone | Caddy Plugin | **Self-Hosted TLS, Decoy Fallback, Caddy Shield**|

---

## Key Features

### Secure Channel & Cryptography (core)

- **Authentic Chromium Network Stack**: Real Chromium networking primitives via `libeidolon.so` (BoringSSL + Chromium QUIC/HTTP-3), so the transport-security properties and the on-wire fingerprint are a browser's, not an emulation's.
- **Context-Bound Ephemeral Token Authentication (anti-MITM)**: A 32-byte HMAC-SHA256 token cryptographically binds the current time window ($\pm 5\text{s}$) to the session's **ephemeral key material**. An adversary who records and replays a handshake, or substitutes their own key material, cannot authenticate — the token is valid only for the key it was bound to. The binding is per-lane: the QUIC/MoQT carrier carries the token **in-band** in the authenticated track preamble, channel-bound to the session's RFC 5705 exporter (both the reliable and datagram lanes); the TCP-fallback lane binds it over the TLS `key_share` natively (BoringSSL) in the `SessionId` field. A double-terminating MITM holds a *different* per-leg exporter and cannot forge a token for the server leg without the pre-shared secret.
- **RFC 5705 Keying Material Exporter (anti-decoy / anti-intercept)**: Inner keys are derived from the established TLS/QUIC session via RFC 5705 exporter labels (`"eidolon-traffic-key"`). A terminating front-end, a TLS-intercepting middlebox, or a spoofed decoy **cannot** derive the inner key and cannot read payload — confidentiality is end-to-end to the real endpoint, not to the TLS terminator.
- **Independent Inner AEAD Layer (secret-salted)**: Inner bidirectional streams are sealed in ChaCha20-Poly1305 (RFC 8439) — with an AES-GCM path where hardware acceleration (AES-NI / ARMv8 Crypto) makes it cheaper — HKDF-SHA256 key derivation, independent per-direction sequence counters, and explicit framing. The inner key is derived from the session exporter **salted with the pre-shared `master_secret`** (`HKDF-Extract(salt = master_secret, ikm = exporter)`), so even an attacker who terminates both TLS legs — holding both per-leg exporters — cannot derive the inner key without the secret, and cannot bridge the tunnel.
- **Post-Quantum Hybrid Key Exchange**: Hybrid post-quantum key agreement negotiated natively by the Chromium stack (X25519 + ML-KEM/Kyber), with graceful fallback to classical X25519.
- **Constant-Time Verification & Replay Protection**: Token validation runs across all three time windows ($[-1, 0, +1]$) with `subtle.ConstantTimeCompare` and symmetrical dummy cache lookups; tokens are single-use against generational replay caches. No early-exit, no timing leak.

### Transport & Resilience

- **Real MoQT Carrier over WebTransport-over-H3**: The tunnel is carried as genuine Media over QUIC Transport (draft-16) on an inline Chromium MoQT endpoint, inside a **per-session randomized namespace**. Reliable (TCP-like) flows map to reliable MoQT tracks; loss-tolerant (UDP) flows map to **QUIC datagrams (RFC 9221)**.
- **Application-Layer FEC**: Datagram flows are protected by systematic forward error correction (XOR-2D → Reed-Solomon over GF(2⁸), NEON-accelerated), recovering losses at 0-RTT without retransmission; parity is adaptive-ready (BBRv3/ECN-driven).
- **Connection Racing & Brokenness Tracking (Happy-Eyeballs)**: QUIC is preferred and raced against a TCP (`smux`) fallback; if UDP/QUIC is blackholed it falls back seamlessly, and a penalty tracker marks QUIC broken with exponential backoff (5 m → 10 m → 1 h) instead of re-racing every time.
- **Connection Migration**: QUIC path migration (handover Wi-Fi↔cellular) keeps the tunnel alive across network changes without a full reconnect — MTU reset + DPLPMTUD re-probe + connection-ID rotation on migration.
- **Sleep/Wake Keep-Alive**: Power-state-aware heartbeat (active / background / doze), kept strictly under the negotiated idle-timeout, with a high-priority wake resync ping and 0-RTT resumption on reconnect.
- **Kernel-Level Network Optimization**: Automated Linux tuning — BBR congestion control, FQ pacing, disabled idle slow-start, 64 MiB socket buffers — plus server-side UDP GSO batch writing and ACK-frequency reduction.

### Camouflage & Anti-Censorship (engaged, understated)

- **Zero-Delay Transparent Fallback**: Unauthorized probes (scanners, random ClientHellos, port checks) trigger an immediate, transparent splice (`io.Copy`) to a designated decoy site (e.g. `microsoft.com:443`). Probes receive authentic decoy certificates and responses — no dropped packets, custom alerts, or reset signatures.
- **On-Demand Media Cover Service (Variant 3)**: The server co-hosts a real MoQ media service in a public (non-token-gated) namespace — a restreamed lo-fi/radio source (ffmpeg) or a synthetic source. An active prober that subscribes receives a genuine live media stream; the content source only starts when a real subscription arrives. Tunnel and cover share one MoQT dialect behind one `:443`/H3 front.
- **PaddedConn Initial Length Obfuscation**: The first 8 packets are framed with a 4-byte header and 16–63 bytes of high-entropy padding ($H \ge 7.99$ bits/byte), flattening handshake size spikes.
- **Adaptive Chaffing & DASH/HLS Shaping (fallback)**: Dummy frames (MSB `0x8000`) are injected (~15%) and emitted on idle to blind statistical classifiers; on the TCP-fallback lane, BurstShaper buffers bulk transfers into 1–4 MB bursts resembling DASH/HLS media.

### Deployment & Operational Modes

- **Zero-Domain Fallback Mode (REALITY-Style)**: Operates without a custom domain or certificate; unauthenticated traffic is transparently forwarded to a legitimate donor site.
- **Self-Hosted TLS Mode**: Terminates standard TLS with production certificates (Caddy / Let's Encrypt / custom PEM), ALPN `h3`, `h2`, `http/1.1`.
- **Caddy Shield Fronting (`caddy-eidolon-shield`)**: Caddy v2 plugin providing Layer-4 SNI/UDP demultiplexing (verbatim L4 relay of QUIC `:443` → the inline MoQT core), decoy website serving, and a loopback secret-rotation API.
- **Federated Node Sync (Opora)**: Client-node syncer that periodically pulls Ed25519-signed master secrets and configuration from an Opora orchestration controller — the seed of the fleet management that **Weaver** will build out.

---

## Architecture & Technical Design

### High-Level Data Flow

```
[ Client Application (Browser / OS / VpnService) ]
                 │
                 ▼
     [ sing-box Eidolon Outbound ]
                 │ (QUIC-preferred racing; TCP fallback on UDP blackhole)
    ┌────────────┴────────────────────────────────────┐
    ▼ (PRIMARY)                                        ▼ (FALLBACK)
[ QUIC Carrier: Native Chromium WebTransport-over-H3 ]   [ TCP Lane: Native Chromium TLS 1.3 ]
    │ Real MoQT (draft-16), per-session namespace          │ (SessionID Token Injection)
    │ In-band token preamble on track "u"                  │ (smux + PaddedConn + BurstShaper)
    │ Reliable tracks (streams) + QUIC datagrams + FEC     │
    └────────────┬────────────────────────────────────────┘
                 │
                 ▼ (Encrypted & Obfuscated Wire Traffic — looks like H3/HTTPS)
          [ Censor / DPI / On-Path Adversary ]
                 │
                 ▼
     [ Caddy Shield :443 — L4 verbatim relay (TCP+UDP) ]
                 │ (SNI/flow match → inline core; else → decoy site)
                 ▼
     [ sing-box Eidolon Inbound + inline MoQT server ] ──(Unauthenticated probe / cover sub)──┐
                 │                                                                            │
                 │ (Constant-Time, KeyShare-bound Token Validation: Valid)                    │
                 ▼                                                                            ▼
  [ RFC 5705 Exporter → Inner AEAD (E2E) ]                            ┌──────────────────────┴───────────┐
                 │                                                    ▼                                   ▼
                 ▼                                         [ Zero-Delay Fallback ]        [ On-Demand Cover Service ]
  [ ServerSessionManager (lane pairing) ]                 [ → Decoy Host, e.g.  ]        [ public MoQ track: radio/  ]
                 │                                         [   microsoft.com:443 ]        [ lo-fi (ffmpeg) or synth  ]
                 ▼
    [ sing-box Core Router (Direct / Outbound) ]
                 │
                 ▼
            [ Internet ]
```

The inner AEAD is end-to-end between the two Eidolon endpoints. The Caddy front performs **verbatim Layer-4 relay only** — it never terminates or decrypts the tunnel, so even a fully compromised front-end sees ciphertext bound to a session key it does not hold.

### Wire Protocol & Packet Specifications

Eidolon standardizes on compact, deterministic binary frame formats across each layer of the protocol stack.

#### 1. Carrier Authentication Preamble (primary — QUIC/MoQT)

On the primary carrier, after the WebTransport-over-H3 handshake and MoQT session setup, the client writes an **in-band preamble** as the first bytes of the reliable `"u"` track. The server validates it before any traffic is accepted; the token is **not** carried in an HTTP header (the server never reads `x-eidolon-token`).

```
+----------------------+----------------+----------------------+--------------+
| Reliable Token (32B) | FlowID (16B)   | Datagram Token (32B) | PadLen (2B)  |
+----------------------+----------------+----------------------+--------------+
```

| Field | Length | Description |
| :--- | :--- | :--- |
| `Reliable Token` | 32 B | HMAC-SHA256(MasterSecret, TimeWindow ‖ KeyShare). Single-use, time-bound, KeyShare-bound. |
| `FlowID` | 16 B | Random session identifier used by `ServerSessionManager` to pair the reliable and datagram lanes. |
| `Datagram Token` | 32 B | Separate fresh token channel-bound to the exported session key (`keyShare = sessionKey`), authenticating the datagram lane. The reliable token cannot be reused (it is single-use). |
| `PadLen` | 2 B | Trailing padding length (0 by default). |

The datagram lane's cb_port is connected **eagerly** at carrier setup (while the single-use token is fresh, within its ~15 s window), not lazily on first datagram.

#### 1b. Fallback Token Embedding (TCP lane — TLS ClientHello SessionId)

When the QUIC/MoQT carrier is unavailable and Eidolon races to the TCP fallback lane, the token is injected into the 32-byte `SessionId` field of the TLS 1.3 `ClientHello` generated by Chromium's BoringSSL stack:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Record Type (0x16) | Version (0x03, 0x01/0x03) | Length (16b) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Handshake Type (0x01) | Length (24b)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Client Version (0x0303)               | Client Random (32 B)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Session ID Len (0x20) | 32-Byte Context-Bound Token           |
|                       | HMAC-SHA256(Secret, TimeWindow || KS) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Cipher Suites Length  | Cipher Suites List ...                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Compression Methods   | Extensions (including KeyShare 0x0033)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Byte Offset 43**: Session ID length indicator (`0x20` = 32 bytes).
- **Bytes 44–75**: 32-byte HMAC token.
- **Extension `0x0033`**: Client KeyShare containing the client's ephemeral public key.

#### 2. Flow Identification Frame

Immediately after TLS/QUIC handshake completion and session key export, the client writes a 16-byte cryptographically secure pseudo-random Flow ID into the stream:

| Field | Length | Description |
| :--- | :--- | :--- |
| `FlowID` | 16 Bytes | Unique session identifier used by `ServerSessionManager` to pair TCP and QUIC lanes. |

#### 3. Stream Destination Addressing Header

Every multiplexed stream initiated inside `smux` begins with a target addressing header:

```
+---------------+------------------------+-------------------------------+
| Command (1 B) | Address Length M (2 B) | Address String (M Bytes)      |
+---------------+------------------------+-------------------------------+
```

| Field | Length | Value / Encoding | Description |
| :--- | :--- | :--- | :--- |
| `Command` | 1 Byte | `0x00` = TCP, `0x01` = UDP | Protocol transport mode. |
| `Address Length` | 2 Bytes | Big-Endian `uint16` | Length $M$ of the destination address string. |
| `Address` | $M$ Bytes | UTF-8 String | Target endpoint (e.g., `api.example.com:443`, `1.1.1.1:53`). |

#### 4. Initial Packet Length Padding Frame (`PaddedConn`)

Applied strictly to the first 8 packets (`maxPaddings = 8`) of a session:

```
+------------------------+------------------------+-------------------------+------------------------+
| Payload Length P (2 B) | Padding Length N (2 B) | Payload Data (P Bytes)  | Random Padding (N B)   |
+------------------------+------------------------+-------------------------+------------------------+
```

| Field | Length | Value / Encoding | Description |
| :--- | :--- | :--- | :--- |
| `Payload Length` | 2 Bytes | Big-Endian `uint16` | Size $P$ of the encapsulated payload. |
| `Padding Length` | 2 Bytes | Big-Endian `uint16` | Size $N$ of padding (16 to 63 bytes for packets 1–8; 0 thereafter). |
| `Payload` | $P$ Bytes | Binary Data | Application data payload. |
| `Padding` | $N$ Bytes | PRNG ($H \ge 7.99$) | Cryptographically random padding bytes discarded upon receipt. |

#### 5. Inner AEAD Stream Framing (`AEADStreamConn`)

Transmitted over the established transport. Each logical transmission is divided into two authenticated records:

```
+------------------------------------+------------------------------------+
| Length Block (18 Bytes)            | Payload Block (P + 16 Bytes)       |
+------------------+-----------------+------------------+-----------------+
| CipherLen (2 B)  | Poly1305 (16 B) | CipherData (P B) | Poly1305 (16 B) |
+------------------+-----------------+------------------+-----------------+
```

- **Length Block (18 Bytes)**:
  - Plaintext: 2-byte Big-Endian unsigned integer.
  - **Bit 15 (MSB `0x8000`)**: Chaff Flag. If set (`rawLen & 0x8000 != 0`), the block represents dummy cover traffic. The receiver strips the flag (`payloadLen = rawLen & 0x7FFF`), decrypts the dummy payload, and silently drops it.
  - **Bits 0–14 (`0x3FFF`)**: Payload length ($0 \le P \le 16383$ bytes).
  - Authenticated via Poly1305 AEAD tag (16 bytes) using independent nonce counter.
- **Payload Block ($P + 16$ Bytes)**:
  - Encrypted application payload ($P$ bytes) authenticated with a 16-byte Poly1305 tag using an incremented nonce.

#### 6. UDP-over-TCP Frame (`uoTStreamPacketConn`)

When multiplexing UDP packets across a reliable stream lane:

```
+------------------------+-------------------------------+
| Packet Length L (2 B)  | UDP Payload (L Bytes)         |
+------------------------+-------------------------------+
```

- **Packet Length (2 Bytes)**: Big-Endian `uint16` ($L \le 65535$). Packets exceeding 65535 bytes are rejected.
- **UDP Payload ($L$ Bytes)**: Raw datagram payload.

---

### Cryptographic State Machine

```
   [ Client ]                                                    [ Server ]
       │                                                             │
       │ 1. Current Time (t = UnixTime / 5)                          │
       │    Generate Ephemeral KeyShare (X25519)                     │
       │    Token = HMAC-SHA256(MasterSecret, t || KeyShare)         │
       │    ClientHello (SessionID = Token, KeyShare)                │
       ├────────────────────────────────────────────────────────────>│
       │                                                             │ 2. Peek 1024 Bytes
       │                                                             │    Extract SessionID & KeyShare
       │                                                             │    Constant-Time Verify (t-1, t, t+1)
       │                                                             │    Check Replay Cache
       │                                                             │    [Match ? Continue : FallbackToDest]
       │ 3. TLS 1.3 ServerHello & Finish                             │
       │<────────────────────────────────────────────────────────────┤
       │                                                             │
       │ 4. RFC 5705 Key Material Export ("eidolon-traffic-key")     │
       │    Derive Master Session Key (32 Bytes)                     │
       │    HKDF-SHA256 Expansion ("eidolon-inner-aead")             │
       │    Client: WriteKey=K1, ReadKey=K2   Server: WriteKey=K2, ReadKey=K1
       │                                                             │
       │ 5. Send FlowID (16 Bytes)                                   │
       ├────────────────────────────────────────────────────────────>│
       │                                                             │ 6. Pairing Window (1500 ms)
       │                                                             │    Register in ServerSessionManager
       │ 7. Bidirectional Encrypted AEAD Stream                      │
       │<═══════════════════════════════════════════════════════════>│
```

#### Constant-Time Verification & Replay Protection

To eliminate cache and execution-time side-channels:
1. `ValidateTokenConstantTime` computes expected HMACs across three consecutive time windows ($[-1, 0, +1]$) corresponding to $5\text{-second}$ intervals:
   $$\text{offset} \in \{-1, 0, +1\}, \quad t_{\text{window}} = \lfloor \text{UnixTime} / 5 \rfloor + \text{offset}$$
2. All candidates are evaluated using `subtle.ConstantTimeCompare`. The loop does not terminate early upon a match.
3. The server queries dual generational replay caches (`currentTokens` and `pastTokens`, rotated every 10 seconds).
4. If a token is invalid, equivalent dummy lookups are executed against `dummyTokens` and `dummyPastTokens` to balance memory bus and branch predictor timings.

---

### Camouflage & DPI Evasion Subsystems

#### 1. Native Chromium CGO Bridge (`libeidolon.so`)
Rather than attempting to simulate TLS and QUIC parameters, Eidolon links against Chromium's production network stack:
- **POSIX**: Creates `socketpair(AF_UNIX, SOCK_STREAM, 0)` endpoints; one descriptor is retained by Go via `net.FileConn`, while the native descriptor is handed off to Chromium's `net::TCPClientSocket`.
- **Windows**: Initializes a loopback TCP pipe via `bridge_windows.go`, extracting socket handles safely via `SyscallConn().Control`.
- **Chromium IO Thread**: Managed by `base::Thread` configured with `MessagePumpType::IO`. Socket reading and writing run asynchronously on native event loops.
- **Fingerprint Parity**: TLS extensions, GREASE identifiers, elliptic curve parameters, and ALPN sequences strictly replicate the underlying Chromium engine.

#### 2. Zero-Delay Transparent Decoy Fallback
If incoming data does not present an authorized token:
- Inbound logs: `Active probe detected. Executing Zero-Delay Fallback to: <dest>`.
- The connection is not reset (`RST`) or closed with a TLS alert.
- A background goroutine connects to `options.Dest` and splices the buffered initial read bytes (`PeekedConn`) and subsequent incoming stream directly to the decoy host using bidirectional `io.Copy`.
- Active scanners observing the port see an authentic, responsive web server with valid TLS certificates and authentic HTTP responses.


#### 3. Traffic Shaping & Chaff Injection (`BurstShaperConn`)
To counter website fingerprinting classifiers (e.g. Deep Fingerprinting):
- Bulk payloads are buffered and flushed in bursts sized between 1 MB and 4 MB (`generateBurstLimit()`).
- Interactive payloads trigger an adaptive flush timer with 150 ms to 450 ms jitter (`baseFlushTime = 300ms`).
- When the queue is idle, `WriteChaff()` transmits dummy encrypted records tagged with `0x8000`.
- During active writes, adaptive chaff packets (16 to 63 bytes) are injected with ~15% probability.

---

### Hybrid Multiplexer (QUIC-preferred MoQT + TCP fallback)

The client maintains an auto-healing connection pool (`SessionPool`). The model is **browser-like**, not symmetric: one QUIC/MoQT carrier is preferred, with a TCP `smux` lane as Happy-Eyeballs fallback — not an evenly round-robined dual pool.

```
                         [ SessionPool ]
                                │
        ┌───────────────────────┴────────────────────────┐
        ▼ (PRIMARY, maxQUICLanes = 1)                     ▼ (FALLBACK, maxTCPLanes = 3)
   [ quicPool ]                                      [ tcpPool ]
   MoQT carrier over Chromium WebTransport/H3        up to 3x smux.Session (Chromium TLS 1.3)
   reliable tracks (u/d) + datagram tracks (ud/dd)   reliable streams (UDP-over-TCP for datagrams)
        │                                                 │
        └───────────────────────┬─────────────────────────┘
                                │ (GetStreamPreferred: QUIC first, TCP fallback)
                                ▼
                       [ Application Stream / Flow ]
```

- **Connection Racing (Happy-Eyeballs)**: QUIC Initial and TCP SYN are attempted together; QUIC answering first wins and TCP is dropped. Lane mix is dynamic: pure QUIC when healthy, 1/1 race while probing, pure TCP while QUIC is in backoff.
- **Brokenness Tracker**: After a QUIC failure, QUIC is marked broken with exponential backoff (5 m → 10 m → 1 h) and not re-raced until it expires; this doubles as the "QUIC works for this endpoint" cache.
- **UDP Blackhole Resilience**: If UDP is blocked, the QUIC dial fails gracefully and traffic routes over the TCP fallback without application hang.
- **Auto-Healing Worker (`CheckAndHeal`)**: Dead lanes are purged and background replenishment runs under atomic locking (`isDialing`).
- **Server-Side Pairing**: `ServerSessionManager` pairs the reliable and datagram lanes of a session by `FlowID`; an unpaired session operates in degraded single-lane mode.

---

### Caddy Shield Reverse Proxy Fronting

For deployments leveraging [Caddy v2](https://caddyserver.com/), the `caddy-eidolon-shield` module acts as an intelligent security fronting layer. In the current MoQT architecture the primary mechanism is a **verbatim Layer-4 relay** — Caddy never terminates or decrypts the tunnel:

- **Layer 4 SNI/UDP Relay (`eidolon_l4`)** — *primary*: A listener wrapper on `:443` that inspects TLS ClientHello records (TCP) and relays QUIC on UDP `:443`. Connections matching `proxy_domain` are relayed byte-for-byte to the inline Eidolon MoQT core (`127.0.0.1:8443`); all other SNIs pass to Caddy's standard HTTP pipeline (the decoy site). Because the relay is verbatim, token validation and TLS/QUIC termination happen inside the Eidolon core, not in Caddy.
- **HTTP Token Shield (`eidolon_shield`)** — *legacy/alternate*: An HTTP-reverse-proxy mode that validates an `X-Eidolon-Token` header and falls through to serve legitimate files for unauthorized requests. Retained for HTTP-fronted deployments; the MoQT carrier does **not** use a header token (authentication is the in-band carrier preamble).
- **Secret Rotation**: An internal loopback endpoint allows dynamic secret rotation without restarting Caddy.

---

## Configuration Guide

Eidolon configurations follow standard sing-box JSON syntax.

### Inbound Configuration Options

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `type` | `string` | **Required** | Must be `"eidolon"`. |
| `tag` | `string` | `""` | Inbound identifier tag. |
| `listen` | `string` | `"0.0.0.0"` | IP address to bind server listener. |
| `listen_port` | `uint16` | `8443` | Listening port for inbound TCP/QUIC traffic. |
| `master_secret`| `string` | **Required** | Secret key used for HMAC-SHA256 token verification. |
| `dest` | `string` | `"127.0.0.1:8080"` | Decoy host address and port for Zero-Delay Fallback (e.g. `microsoft.com:443`). |
| `server_names` | `[]string` | `[]` | List of anticipated SNI domain names for TLS validation. |
| `private_key` | `string` | `""` | Ephemeral private key for REALITY-style decoy mode. Leave empty for Self-Hosted mode. |
| `tls` | `object` | `nil` | TLS configuration object for Self-Hosted mode. |
| `tls.enabled` | `bool` | `false` | Enable TLS termination. |
| `tls.server_name` | `string` | `""` | Server name for certificate selection. |
| `tls.certificate_path` | `string`| `""` | Path to TLS certificate fullchain PEM file. |
| `tls.key_path` | `string` | `""` | Path to TLS private key PEM file. |
| `tls.certificate` | `[]string` | `[]` | Inline PEM certificate lines. |
| `tls.key` | `[]string` | `[]` | Inline PEM private key lines. |
| `tls.insecure` | `bool` | `false` | Allow insecure TLS verification (testing only). |
| `federation` | `object` | `nil` | Configuration for Opora federated key management. |
| `federation.enabled` | `bool` | `false` | Enable automated secret synchronization. |
| `federation.opora_url`| `string`| `""` | Endpoint URL of the Opora controller. |
| `federation.token` | `string` | `""` | Bearer token for Opora API authentication. |
| `federation.pub_key` | `string`| `""` | Ed25519 public key (hex) for verifying config signatures. |
| `cover` | `object` | `nil` | On-demand MoQ cover service (public, non-token-gated namespace). |
| `cover.enabled` | `bool` | `false` | Enable the cover service. A prober that subscribes to the public track gets a real media stream. |
| `cover.source` | `string` | `"synthetic"` | Content source: `"ffmpeg"` (restream a radio/lo-fi URL → Opus/Ogg), `"synthetic"` (self-contained keystream), or `"none"`. |
| `cover.input` | `string` | `""` | For `ffmpeg`: input stream URL or file (e.g. a public lo-fi/radio stream). |
| `cover.ffmpeg_args` | `[]string` | `[]` | Verbatim ffmpeg arguments (overrides the default Opus/Ogg pipeline). |
| `cover.track` | `string` | `"audio"` | Public track name advertised to subscribers. |
| `cover.bitrate` | `int` | `12000` | Target bitrate (bytes/s; ~96 kbit/s). |
| `cover.namespace_pool` | `[]string` | `[]` | Word pool for plausible per-session namespace names (empty = built-in). |

> **Note (cover + ffmpeg):** `source: "ffmpeg"` requires the `ffmpeg` binary on the server and a `libeidolon.so` that includes the broadcaster-socket `FD_CLOEXEC` fix; otherwise an ffmpeg process can leak when a prober unsubscribes. Use `source: "synthetic"` (self-contained, no external process) if unsure. The bundled `deploy_eidolon_server.sh` provisions the cover service and defaults to an ffmpeg radio restream (overridable via `COVER_*` env vars).

### Outbound Configuration Options

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `type` | `string` | **Required** | Must be `"eidolon"`. |
| `tag` | `string` | `""` | Outbound identifier tag. |
| `server` | `string` | **Required** | Server IP address or domain name. |
| `server_port` | `uint16` | **Required** | Server port. |
| `master_secret`| `string` | **Required** | Master secret key used for token generation. |
| `server_name` | `string` | `""` | SNI domain name used in TLS ClientHello for camouflage. |
| `public_key` | `string` | `""` | Server's public key (if using REALITY-style validation). |

---

### Deployment Scenarios

#### Scenario 1: Zero-Domain Fallback (Camouflage Mode)

In this mode, the server operates without custom domain names or public certificates. Unauthorized probes are transparently forwarded to `microsoft.com:443`.

**Server Configuration (`config-server.json`)**:
```json
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "eidolon",
      "tag": "eidolon-in",
      "listen": "0.0.0.0",
      "listen_port": 443,
      "master_secret": "4f9b8c2e1a7d3f5e6b8a0c2d4e6f8a1b3c5d7e9f2a4b6c8d0e1f3a5b7c9d1e3f",
      "dest": "microsoft.com:443"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": "eidolon-in",
        "outbound": "direct"
      }
    ]
  }
}
```

**Client Configuration (`config-client.json`)**:
```json
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "eidolon",
      "tag": "eidolon-out",
      "server": "YOUR_SERVER_IP",
      "server_port": 443,
      "master_secret": "4f9b8c2e1a7d3f5e6b8a0c2d4e6f8a1b3c5d7e9f2a4b6c8d0e1f3a5b7c9d1e3f",
      "server_name": "microsoft.com"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": "mixed-in",
        "outbound": "eidolon-out"
      }
    ]
  }
}
```

---

#### Scenario 2: Self-Hosted Mode (Standard TLS / Certificates)

In Self-Hosted mode, the server terminates TLS with valid certificates (e.g. issued by Let's Encrypt or Caddy) and advertises standard ALPN negotiation (`h3`, `h2`, `http/1.1`).

**Server Configuration (`config-server-tls.json`)**:
```json
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "eidolon",
      "tag": "eidolon-in",
      "listen": "0.0.0.0",
      "listen_port": 8443,
      "master_secret": "7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
      "dest": "127.0.0.1:8080",
      "server_names": [
        "proxy.example.com"
      ],
      "tls": {
        "enabled": true,
        "server_name": "proxy.example.com",
        "certificate_path": "/etc/ssl/certs/fullchain.pem",
        "key_path": "/etc/ssl/private/privkey.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

---

#### Scenario 3: Caddy Shield Reverse Proxy Fronting

Use Caddy v2 as a fronting web server. Caddy handles public HTTPS traffic for a legitimate website while intercepting Eidolon traffic.

**Caddyfile (`/etc/caddy/Caddyfile`)**:
```caddyfile
{
    order eidolon_shield before file_server
}

proxy.example.com {
    tls admin@example.com

    route {
        eidolon_shield {
            upstream 127.0.0.1:8443
            secret "7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"
        }

        # Legitimate website served to regular visitors and unauthorized probes
        file_server {
            root /var/www/html
        }
    }
}
```

---

#### Scenario 4: Federated Key Management (Opora Sync)

In federated deployments, proxy nodes synchronize secrets periodically with an Opora cluster:

```json
{
  "inbounds": [
    {
      "type": "eidolon",
      "tag": "eidolon-in",
      "listen": "0.0.0.0",
      "listen_port": 443,
      "master_secret": "initial-bootstrap-secret",
      "dest": "cloudflare.com:443",
      "federation": {
        "enabled": true,
        "opora_url": "https://opora.internal.net",
        "token": "bearer-bootstrap-token-string",
        "pub_key": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  ]
}
```

---

## Quick Start & Deployment

### Prerequisites

- **Operating System**: Linux x86_64 (Kernel $\ge 5.4$ recommended for BBR/FQ).
- **Go Runtime**: Go 1.20 or newer (built and tested with Go 1.26).
- **Compiler**: GCC / G++ supporting C++17.
- **Shared Libraries**: `libeidolon.so` (must be placed in library search path).
- **Permissions**: Root or `CAP_NET_ADMIN` / `CAP_NET_BIND_SERVICE` for low ports and sysctl tuning.

### Building from Source

1. Clone the repository and navigate to the project directory:
   ```bash
   cd /root/workspace/handover/sing-box-fork
   ```

2. Build the sing-box binary with CGO enabled:
   ```bash
   CGO_ENABLED=1 go build -v -o sing-box ./cmd/sing-box
   ```

3. Configure runtime dynamic linker path:
   ```bash
   export LD_LIBRARY_PATH="$(pwd)/protocol/eidolon/lib:$LD_LIBRARY_PATH"
   ```

4. Verify binary compilation and library linking:
   ```bash
   ./sing-box version
   ```
   *Expected output*:
   ```
   sing-box version 1.12.19-neko-1
   Environment: go1.26.2 linux/amd64
   CGO: enabled
   ```

### Running Server and Client

#### Starting the Server
```bash
export LD_LIBRARY_PATH="/root/workspace/handover/sing-box-fork/protocol/eidolon/lib:$LD_LIBRARY_PATH"
./sing-box run -c config-server.json
```

#### Starting the Client
```bash
export LD_LIBRARY_PATH="/root/workspace/handover/sing-box-fork/protocol/eidolon/lib:$LD_LIBRARY_PATH"
./sing-box run -c config-client.json
```

### Verifying Connectivity

Verify proxy functionality through the client's mixed SOCKS5/HTTP inbound (port 1080):

```bash
# Test HTTP/HTTPS proxy forwarding
curl -x socks5h://127.0.0.1:1080 -I https://www.google.com

# Verify client IP matches the proxy server
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
```

---

## Troubleshooting & Security Considerations

### Common Operational Issues

#### 1. `error while loading shared libraries: libeidolon.so`
- **Cause**: The dynamic linker cannot find the native C++ Chromium bridge library.
- **Resolution**: Export the library directory before executing `sing-box`:
  ```bash
  export LD_LIBRARY_PATH="/path/to/sing-box-fork/protocol/eidolon/lib:$LD_LIBRARY_PATH"
  # Or install system-wide:
  sudo cp protocol/eidolon/lib/libeidolon.so /usr/local/lib/
  sudo ldconfig
  ```

#### 2. Probe Fallback Triggered on Authorized Connections
- **Cause**: Clock skew between client and server exceeds the $\pm 5\text{-second}$ window.
- **Resolution**: Ensure NTP synchronization is active on both hosts:
  ```bash
  sudo systemctl restart systemd-timesyncd
  timedatectl status
  ```

#### 3. `smux stream limit reached`
- **Cause**: More than 2,048 concurrent streams opened across a single session.
- **Resolution**: Increase outbound pool concurrency limit or optimize connection recycling.

#### 4. `permission denied` During Sysctl Optimization
- **Cause**: `OptimizeSysctls()` requires root privileges to configure `/proc/sys/net/`.
- **Resolution**: Run the server process with root privileges or grant `CAP_NET_ADMIN`.

---

### Security Hardening Checklist

1. **High-Entropy Secrets**: Generate cryptographically secure master secrets:
   ```bash
   openssl rand -hex 32
   ```
2. **Decoy Domain Selection**:
   - Choose decoy domains supporting **TLS 1.3** and **HTTP/2 or HTTP/3**.
   - Select domains with large global traffic volumes in your geographic area (e.g., `cloudflare.com`, `microsoft.com`, `apple.com`).
   - Ensure the decoy does not immediately issue HTTP 301/302 redirects to separate authentication portals.
3. **Decoy Responsiveness**: Verify that the decoy host resolves quickly from the server node. If the decoy is unreachable, fallback operations fall back to standard TCP connection timeouts.
4. **Secret Rotation**: Rotate secrets periodically using the Caddy Shield API (`/_internal/update_secret`) or Opora federation without restarting background processes.

---

### Kernel Tuning (BBR & FQ)

Eidolon includes an automated kernel optimizer (`OptimizeSysctls` in `sysctl.go`). Operators may also apply these system settings directly:

```ini
# /etc/sysctl.d/99-eidolon.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
```

Apply immediately:
```bash
sudo sysctl -p /etc/sysctl.d/99-eidolon.conf
```

---

## Development & Testing

### Repository Layout

```
sing-box-fork/
├── cmd/
│   └── sing-box/              # Main executable entrypoint
├── protocol/
│   └── eidolon/               # Core Eidolon Protocol Implementation
│       ├── aead.go            # Inner ChaCha20-Poly1305 / AES-GCM framing & adaptive chaff
│       ├── bridge.go          # CGO bridge (POSIX socketpair & Windows loopback)
│       ├── bridge.h           # C++ header exports (eidolon_dial_moqt, cover, power, etc.)
│       ├── crypto.go          # Constant-time, KeyShare-bound token verification & replay cache
│       ├── exporter.go        # RFC 5705 TLS/QUIC Exporter ("eidolon-traffic-key")
│       ├── inbound.go         # Inbound server, zero-delay fallback, TLS config
│       ├── inbound_mux.go     # ServerSessionManager & lane pairing lifecycle
│       ├── inbound_quic.go    # Native Chromium QUIC/MoQT listener
│       ├── inbound_datagram.go# Server datagram lane (channel-bound token, cb_port)
│       ├── outbound.go        # Outbound client, SessionPool, racing, brokenness tracker, migration
│       ├── datagram.go        # QUIC datagram lane (RFC 9221) framing
│       ├── datagram_fec.go    # FEC wiring over the datagram wire (idle-flush, block IDs)
│       ├── datagram_flowctl.go# Datagram flow control
│       ├── datagram_dplpmtud.go# DPLPMTUD / path-MTU for datagrams
│       ├── cover_ingest.go    # Phase 6 cover service: on-demand source → native broadcaster
│       ├── padding.go         # PaddedConn (4-byte header, 8-packet cutoff)
│       ├── shaper.go          # BurstShaperConn (1-4MB chunking, flush jitter — TCP fallback)
│       ├── sysctl.go          # Kernel BBR & FQ pacing tuning
│       ├── uot.go             # UDP-over-TCP stream encapsulation
│       ├── cover/             # Cover content sources (synthetic keystream, ffmpeg restream)
│       ├── fec/               # App-layer FEC (XOR-2D + Reed-Solomon, GF(2⁸)+NEON)
│       ├── flowctl/           # Receiver-driven flow control & ECN-bleaching detector
│       ├── federation/        # Opora node syncer & Ed25519 signature validation
│       └── lib/
│           ├── libeidolon.so  # Compiled native Chromium network stack (incl. inline MoQT server)
│           └── libeidolon_net.so -> libeidolon.so
├── caddy-eidolon-shield/      # Caddy v2 security fronting & L4 relay module
│   ├── eidolon_shield.go      # (legacy) HTTP token validation & secret rotation API
│   └── eidolon_l4.go          # Layer-4 SNI/UDP verbatim relay → inline MoQT core
├── option/
│   ├── inbound_eidolon.go     # Inbound configuration options
│   └── outbound_eidolon.go    # Outbound configuration options
└── tests/
    └── eidolon/               # Physical validation test suite (Batches 1-4)
```

### Running the Physical Test Suite

The Eidolon test suite exercises networking, cryptography, and obfuscation logic without mocks or dummy assertions. 

> **Important**: Always provide `LD_LIBRARY_PATH` when running tests to ensure the native Chromium library loads successfully. Tests must be run against the verified implementation test suites (Batches 1 through 4).

```bash
cd /root/workspace/handover/sing-box-fork

# Run full verified test suite with race detection enabled
LD_LIBRARY_PATH="$(pwd)/protocol/eidolon/lib" go test -race -v ./tests/eidolon/...
```

To run individual test batches:

```bash
# Batch 1: Core Networking & Multiplexing Matrix (TC-001 to TC-020)
LD_LIBRARY_PATH="$(pwd)/protocol/eidolon/lib" go test -v ./tests/eidolon/batch1_impl_test.go

# Batch 2: Native Chromium CGO Bridge Matrix (TC-021 to TC-040)
LD_LIBRARY_PATH="$(pwd)/protocol/eidolon/lib" go test -v ./tests/eidolon/batch2_impl_test.go

# Batch 3: DPI Evasion, Shaper & Obfuscation (TC-041 to TC-060)
LD_LIBRARY_PATH="$(pwd)/protocol/eidolon/lib" go test -v ./tests/eidolon/batch3_impl_test.go ./tests/eidolon/batch3_dpi_test.go ./tests/eidolon/batch3_missing_test.go

# Batch 4: Token Auth, Fallback & Caddy Shield (TC-061 to TC-080)
LD_LIBRARY_PATH="$(pwd)/protocol/eidolon/lib" go test -v ./tests/eidolon/batch4_impl_test.go ./tests/eidolon/batch4_fallback_test.go ./tests/eidolon/batch4_caddy_test.go ./tests/eidolon/batch4_tls_test.go
```

---

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3) in alignment with the upstream sing-box project.