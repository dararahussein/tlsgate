# tlsgate

`tlsgate` is a non-blocking Layer-4/Layer-7 reverse proxy and edge threat engine that inspects raw TLS `ClientHello` frames on the wire prior to handshake completion, computes **JA4** client fingerprints, detects spoofed client identities, and enforces distributed rate limits backed by an optional eBPF/XDP fast-path packet filter.

## Architecture

```text
Incoming TCP/TLS Traffic
          |
          v
+-------------------------------------------------------------------+
|  [Optional Linux Fast Path] eBPF XDP Blocklist (xdp_blocklist.c)  |
|  Pinned BPF LPM/Hash Map -> XDP_DROP before sk_buff allocation    |
+---------------------------------+---------------------------------+
                                  | XDP_PASS
                                  v
+-------------------------------------------------------------------+
|  Asyncio Raw TCP Listener & Wire-Level TLS Parser                 |
|  1. Peek RFC 8446 ClientHello record (ciphers, extensions, SNI)   |
|  2. Filter RFC 8701 GREASE values & compute JA4 fingerprint       |
|  3. Pre-handshake policy check (drop before asymmetric crypto)    |
+---------------------------------+---------------------------------+
                                  | Allowed -> Replay buffer & start_tls()
                                  v
+-------------------------------------------------------------------+
|  Policy & Threat Engine                                           |
|  - L1 in-memory LRU/TTL cache + atomic Redis Lua sliding window   |
|  - HTTP User-Agent vs. wire-level JA4 mismatch detection          |
|  - Fail-open circuit breaker on Redis degradation                 |
+---------------------------------+---------------------------------+
                                  |
                 +----------------+----------------+
                 |                                 |
                 v                                 v
      Upstream Backend Pool           WebSocket Stream & PostgreSQL
```

### Core Capabilities

* **Pre-Handshake Wire Inspection:** Parses binary TLS 1.2/1.3 `ClientHello` frames directly from raw TCP buffers (`SNI`, `ALPN`, `supported_versions`, `signature_algorithms`, cipher suites, and extension ordering) with RFC 8701 GREASE filtering to generate deterministic **JA4** fingerprints before spending CPU on TLS termination.
* **Client Spoofing Detection:** Correlates decrypted HTTP `User-Agent` headers against known TLS stack profiles (e.g., flagging `python-requests`, `curl`, or Go `crypto/tls` clients claiming a Chrome/BoringSSL `User-Agent`).
* **Two-Tier Distributed Rate Limiting:** Combines a process-local L1 LRU cache for hot-key absorption with atomic **Redis Lua** sliding-window counters keyed by `(subnet, JA4, route)`, falling back cleanly via a circuit breaker if Redis becomes unreachable.
* **Kernel Fast-Path Offload (Linux):** Pushes high-confidence abusive IPs into a pinned eBPF **XDP** map so repeat flood traffic is dropped at the NIC driver layer (`XDP_DROP`) prior to TCP handshake state allocation.

## Repository Layout

```text
tlsgate/
├── bpf/                        # Optional C eBPF/XDP IP blocklist program
├── lua/                        # Atomic Redis Lua rate-limiting scripts
├── src/tlsgate/
│   ├── proxy/                  # Non-blocking asyncio listener, TLS upgrade & upstream pool
│   ├── fingerprint/            # Binary RFC 8446 ClientHello parser & JA4 generator
│   ├── policy/                 # L1 cache, Redis Lua client, circuit breaker & spoofing rules
│   └── telemetry/              # Live WebSocket event feed & PostgreSQL flow sink
├── tests/
│   └── fixtures/               # Captured ClientHello payloads (Chrome, curl, requests)
└── benchmarks/                 # Throughput, p99 proxy latency & bot-simulation harness
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Optional on Linux: compile XDP fast-path filter
make xdp

# Run unit & parser tests
make test
```
