# Eidolon Secure Proxy

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/sagernet/sing-box)
[![Go Version](https://img.shields.io/badge/go-1.26+-blue.svg)](https://golang.org)
[![Core Engine](https://img.shields.io/badge/engine-Chromium%20Net%20%7C%20BoringSSL-red.svg)](https://chromium.googlesource.com/chromium/src/net/)
[![Crypto](https://img.shields.io/badge/crypto-ChaCha20--Poly1305%20%7C%20X25519Kyber768-orange.svg)](https://tools.ietf.org/html/rfc8439)
[![License](https://img.shields.io/badge/license-GPLv3-lightgrey.svg)](LICENSE)
[![CGO](https://img.shields.io/badge/CGO-enabled-success.svg)](#prerequisites)

> <small style="color: #6c757d;">*^ Note on nomenclature: While functional, this protocol could arguably be dubbed a "bootleg" implementation—it doesn't invent anything groundbreaking, but merely weaves together already proven concepts.*</small>

**Eidolon** is an enterprise-grade, next-generation stealth proxy protocol integrated into a high-performance fork of [sing-box](https://github.com/SagerNet/sing-box). Designed to survive state-of-the-art Deep Packet Inspection (DPI), active scanning, and machine learning traffic classifiers, Eidolon abandons superficial protocol simulation. Instead, it natively embeds Google Chromium's actual network stack (`net/`, BoringSSL, and Chromium QUIC/HTTP-3) via a high-throughput CGO/C++ bridge. 

By combining authentic browser TLS/QUIC stacks with a context-bound TOTP authentication handshake, zero-delay transparent decoy fallback, dynamic DASH/HLS burst shaping, post-quantum hybrid cryptography, and dual-lane multi-path multiplexing, Eidolon renders proxy traffic mathematically and behaviorally indistinguishable from standard HTTPS and HTTP/3 browsing sessions.

---

## Table of Contents

- [Description & Threat Model](#description--threat-model)
  - [The Circumvention Dilemma](#the-circumvention-dilemma)
  - [Threat Model & Mitigations](#threat-model--mitigations)
  - [Comparative Protocol Matrix](#comparative-protocol-matrix)
- [Key Features](#key-features)
  - [Protocol & Cryptography](#protocol--cryptography)
  - [Camouflage & Anti-Censorship](#camouflage--anti-censorship)
  - [Performance & Multiplexing](#performance--multiplexing)
  - [Deployment & Operational Modes](#deployment--operational-modes)
- [Architecture & Technical Design](#architecture--technical-design)
  - [High-Level Data Flow](#high-level-data-flow)
  - [Wire Protocol & Packet Specifications](#wire-protocol--packet-specifications)
  - [Cryptographic State Machine](#cryptographic-state-machine)
  - [Camouflage & DPI Evasion Subsystems](#camouflage--dpi-evasion-subsystems)
  - [Multi-Lane Hybrid Multiplexer (TCP + QUIC)](#multi-lane-hybrid-multiplexer-tcp--quic)
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

### The Circumvention Dilemma

Modern censorship infrastructure has evolved beyond simple IP blacklists, DNS poisoning, and static SNI blocking. Advanced network adversaries employ:

1. **Active Probing**: Autonomous scanning clusters replay intercepted handshakes or issue probe variations against suspected proxy endpoints to trigger distinct protocol responses, abnormal TCP resets, or customized TLS alert codes.
2. **TLS ClientHello Fingerprinting (JA3 / JA4)**: Censorship middleboxes calculate hashes of TLS extensions, cipher suites, elliptic curves, point formats, and ALPN tokens. Emulated implementations (such as Go `crypto/tls` or patched libraries) inevitably exhibit subtle discrepancies (e.g. extension ordering, GREASE values, signature algorithms) that reveal non-browser clients.
3. **HTTP/2 & HTTP/3 Preambles & SETTINGS Fingerprinting**: Inconsistencies in initial window sizes, header table sizes, max concurrent streams, or frame interleaving expose emulated HTTP/2 or HTTP/3 layers.
4. **Traffic Analysis & Website Fingerprinting (WF)**: Machine learning classifiers (e.g. Deep Fingerprinting, k-FP, CUMUL) analyze packet direction, inter-arrival timing jitter, and cumulative packet size distributions. Even over TLS, unshaped proxy sessions leak distinct packet size patterns (e.g., small interactive handshakes followed by immediate streaming bursts).

Eidolon was engineered from the ground up to neutralize every vector in this threat model.

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
| **TLS Stack** | None (Raw AEAD) | Go `crypto/tls` | Go / uTLS | Go / uTLS | Chromium Net Stack | **Chromium Net Stack (`libeidolon.so`)** |
| **Active Probing Defense** | None (Drop/RST) | Decoy Website | Decoy Website | Decoy TLS Splice | Frontend Forwarding (Caddy) | **Zero-Delay Fallback & Caddy Shield** |
| **Authentication Placement**| Initial Salt / Header | TLS Password (Body) | Header / Addons | TLS ClientHello SessionID | HTTP Authorization Header | **SessionID + Ephemeral KeyShare Binding** |
| **KeyShare Substitution Defense**| N/A | No | No | No | N/A | **Yes (HMAC binds Client KeyShare)** |
| **Timing Side-Channel Immunity** | Partial | No | No | Partial | High | **Yes (Full constant-time + dummy cache)** |
| **Multiplexing Layer** | smux / none | None / smux | Mux.Cool / smux | None / Mux | HTTP/2 Streams | **Dual-Lane Hybrid (TCP smux + QUIC Pool)**|
| **Multi-Path / Degradation** | No | No | No | No | No | **Yes (Auto-healing TCP/QUIC failover)** |
| **Traffic Shaping / Chaffing**| None | None | None | None | First 8 reads/writes padding | **BurstShaper (1-4MB) + Adaptive Chaff (15%)**|
| **Post-Quantum Cryptography**| None | None | Experimental | Limited | Dependent on Chrome | **Native X25519Kyber768 (`0x6399`)** |
| **Deployment Flexibility** | Standalone | Web Server | Web Server | Standalone | Caddy Plugin | **Self-Hosted TLS, Decoy Fallback, Caddy Shield**|

---

## Key Features

### Protocol & Cryptography

- **Authentic Chromium Network Stack**: Employs real Chromium networking primitives via `libeidolon.so` (built against BoringSSL and Chromium QUIC). Eliminates all heuristic and JA3/JA4 fingerprinting discrepancies.
- **Context-Bound Ephemeral Token Authentication**: Generates a 32-byte HMAC-SHA256 token embedded in the TLS 1.3 `SessionId` field. The token cryptographically binds the current time window ($\pm 5\text{s}$) with the client's ephemeral TLS KeyShare (`0x0033` extension), preventing MITM replay attacks and key substitution.
- **RFC 5705 Keying Material Exporter**: Inner encryption keys are derived directly from the established TLS or QUIC session using RFC 5705 exporter labels (`"eidolon-traffic-key"`). Man-in-the-Middle interceptors or spoofed decoys cannot decrypt payload streams.
- **Independent Inner AEAD Layer**: Inner bidirectional streams are encapsulated in ChaCha20-Poly1305 (IETF RFC 8439) with HKDF-SHA256 key derivation, independent sequence counters, and explicit framing.
- **Post-Quantum Hybrid Key Exchange**: Native support for hybrid post-quantum key agreement (`X25519Kyber768` / `0x6399`), providing quantum resistance with automatic graceful fallback to classical X25519.
- **Constant-Time Verification**: Server-side token validation executes across all three time windows ($[-1, 0, +1]$) using `subtle.ConstantTimeCompare`, paired with symmetrical dummy cache lookups to eliminate microarchitectural timing leaks.

### Camouflage & Anti-Censorship

- **Zero-Delay Transparent Fallback**: Unauthorized probes (scanners, random TLS ClientHellos, port checks) trigger an immediate, transparent TCP splice (`io.Copy`) to a designated decoy website (e.g. `microsoft.com:443`). Probes receive authentic decoy certificates and responses without dropped packets, custom alerts, or reset signatures.
- **PaddedConn Initial Length Obfuscation**: The first 8 packets of every connection are framed with a 4-byte header and 16 to 63 bytes of high-entropy cryptographic padding ($H \ge 7.99\text{ bits/byte}$), flattening the packet size distribution spikes characteristic of initial handshakes.
- **BurstShaper Dynamic Chunking**: Large data transfers are buffered and emitted in dynamic bursts ranging from 1 MB to 4 MB, closely replicating the variable segment sizes of legitimate DASH/HLS streaming media (e.g. YouTube, Netflix).
- **Interactive Flush Timer with Jitter**: Interactive, low-volume traffic is flushed within an adaptive jitter window of 150 ms to 450 ms (`baseFlushTime = 300ms`), preventing flow latency correlation while preserving responsiveness.
- **Cover Traffic & Adaptive Chaffing**: Inject dummy frames (marked with MSB `0x8000`) with ~15% probability during active writes, and automatically emit cover traffic when the connection is idle, blinding statistical traffic classifiers.

### Performance & Multiplexing

- **Dual-Lane Hybrid Session Pool**: Concurrently maintains parallel TCP (`smux`) and UDP (`QUIC`) lanes within an auto-healing connection pool (`SessionPool`).
- **Dynamic Load Balancing & Failover**: Application streams are round-robin balanced across active lanes. If an ISP throttles or blackholes UDP (QUIC), traffic seamlessly falls back to TCP; if TCP stalls, QUIC absorbs the throughput.
- **Auto-Healing Worker**: An asynchronous health worker monitors active lanes, prunes dead connections, and replenishes the connection pool without stalling active user sessions.
- **Optimized UDP-over-TCP (UoT)**: Robust UDP packet framing over TCP streams with 2-byte length headers, MTU boundary clamping, and oversized packet protection.
- **Kernel-Level Network Optimization**: Automated Linux kernel tuning configuring TCP BBR congestion control, FQ packet pacing, disabled idle slow-start, and 64 MiB socket buffer high-water marks.

### Deployment & Operational Modes

- **Zero-Domain Fallback Mode (REALITY-Style)**: Operates without requiring a custom domain or TLS certificate. Authenticates incoming connections via TLS ClientHello SessionID and transparently forwards unauthenticated traffic to a legitimate donor site.
- **Self-Hosted TLS Mode**: Directly terminates standard TLS using production certificates (e.g., Caddy, Let's Encrypt, custom PEM) with hardcoded ALPN (`h3`, `h2`, `http/1.1`).
- **Caddy Shield Fronting (`caddy-eidolon-shield`)**: An enterprise Caddy v2 plugin providing Layer 4 SNI demultiplexing, HTTP/3 `X-Eidolon-Token` validation, decoy website serving, and an authenticated loopback secret rotation API (`/_internal/update_secret`).
- **Federated Node Sync (Opora)**: Integrated client-node syncer that periodically pulls Ed25519-signed master secrets and dynamic configuration updates from an Opora orchestration controller.

---

## Architecture & Technical Design

### High-Level Data Flow

```
[ Client Application (Browser / OS) ]
                 │
                 ▼
     [ sing-box Eidolon Outbound ]
                 │
    ┌────────────┴───────────────────────────┐
    ▼                                        ▼
[ TCP Lane: Native Chromium TLS 1.3 ]    [ QUIC Lane: Native Chromium HTTP/3 ]
    │ (SessionID Token Injection)            │ (X-Eidolon-Token + 32B Padding)
    │ (PaddedConn Initial Obfuscation)       │ (QUIC Packet Obfuscation)
    └────────────┬───────────────────────────┘
                 │
                 ▼ (Encrypted & Obfuscated Wire Traffic)
          [ Censor / DPI ]
                 │
                 ▼
     [ sing-box Eidolon Inbound ] ─────────(Unauthenticated Probe)──────┐
                 │                                                      │
                 │ (Constant-Time Token Validation: Valid)              │
                 ▼                                                      ▼
  [ TLS Handshake Termination & RFC 5705 Exporter ]           [ Zero-Delay Fallback ]
                 │                                                      │
                 ▼                                                      ▼
  [ PaddedConn (8-packet cutoff) & BurstShaper ]              [ Decoy Host (e.g., ]
                 │                                            [ microsoft.com:443) ]
                 ▼
  [ ServerSessionManager (1.5s Pairing Window) ]
                 │
                 ▼
    [ sing-box Core Router (Direct / Outbound) ]
                 │
                 ▼
            [ Internet ]
```

### Wire Protocol & Packet Specifications

Eidolon standardizes on compact, deterministic binary frame formats across each layer of the protocol stack.

#### 1. Initial Handshake Token Embedding (TLS ClientHello)

The authentication token is injected directly into the 32-byte `SessionId` field of the standard TLS 1.3 `ClientHello` packet generated by Chromium's BoringSSL stack:

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

### Multi-Lane Hybrid Multiplexer (TCP + QUIC)

The client maintains an auto-healing connection pool (`SessionPool`) across both TCP and QUIC transports:

```
                         [ SessionPool ]
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
   [ tcpPool ]                                    [ quicPool ]
   3x smux.Session (over Chromium TLS 1.3)        3x smux.Session (over Chromium HTTP/3)
        │                                               │
        └───────────────────────┬───────────────────────┘
                                │ (Round-Robin Stream Dispatch)
                                ▼
                       [ Application Stream ]
```

- **Round-Robin Balancing**: Active streams are balanced evenly across both pools (`atomic.AddUint32(&rrIndex, 1) % total`).
- **UDP Blackhole Resilience**: If UDP is blocked by a firewall, QUIC dials fail gracefully and 100% of traffic routes over TCP without application hang.
- **TCP Throttling Resilience**: If TCP is throttled, QUIC lanes absorb the load.
- **Auto-Healing Worker (`CheckAndHeal`)**: Dead lanes are purged and background replenishment is initiated using atomic locking (`isDialing`).
- **Server-Side Pairing**: `ServerSessionManager` maintains a 1.5-second pairing window upon receiving the first transport lane. If both lanes connect within the window, perfect pairing is achieved; otherwise, the session operates in degraded single-lane mode.

---

### Caddy Shield Reverse Proxy Fronting

For deployments leveraging [Caddy v2](https://caddyserver.com/), the `caddy-eidolon-shield` module acts as an intelligent security fronting layer:

- **Layer 4 SNI Routing (`eidolon_l4`)**: Inspects TLS ClientHello records. Connections matching `proxy_domain` are transparently proxied to the Eidolon core, while all other SNIs pass to Caddy's standard HTTP pipeline.
- **HTTP/3 Token Interception (`eidolon_shield`)**: Validates the `X-Eidolon-Token` header. Authorized requests have the token stripped and are proxied upstream; unauthorized requests fall through to serve legitimate website files (200 OK / 404).
- **Zero-Downtime Secret Rotation**: Exposes an internal HTTP endpoint (`POST /_internal/update_secret`) bound to localhost (`127.0.0.1:11223`) allowing dynamic secret rotation without restarting Caddy.

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
│       ├── aead.go            # Inner ChaCha20-Poly1305 framing & adaptive chaff
│       ├── bridge.go          # CGO bridge (POSIX socketpair & Windows loopback)
│       ├── bridge.h           # C++ header exports (eidolon_dial_tcp, etc.)
│       ├── crypto.go          # TOTP constant-time token verification & replay cache
│       ├── exporter.go        # RFC 5705 TLS Exporter ("eidolon-traffic-key")
│       ├── inbound.go         # Inbound server, zero-delay fallback, TLS config
│       ├── inbound_mux.go     # ServerSessionManager & 1.5s pairing lifecycle
│       ├── inbound_quic.go    # Native Chromium QUIC listener & HTTP/3 CONNECT
│       ├── outbound.go        # Outbound client, SessionPool & auto-healing
│       ├── padding.go         # PaddedConn (4-byte header, 8-packet cutoff)
│       ├── shaper.go          # BurstShaperConn (1-4MB chunking, flush jitter)
│       ├── sysctl.go          # Kernel BBR & FQ pacing tuning
│       ├── uot.go             # UDP-over-TCP stream encapsulation
│       ├── federation/        # Opora node syncer & Ed25519 signature validation
│       └── lib/
│           ├── libeidolon.so  # Compiled native Chromium network stack
│           └── libeidolon_net.so -> libeidolon.so
├── caddy-eidolon-shield/      # Caddy v2 security fronting & L4 SNI module
│   ├── eidolon_shield.go      # HTTP/3 token validation & secret rotation API
│   └── eidolon_l4.go          # Layer 4 SNI demuxer & transparent proxy
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
