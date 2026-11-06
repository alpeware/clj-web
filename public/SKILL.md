---
name: bitecho-light-node
description: Operational reference and command guide for the Bitecho light-node boundary shell, JSONL stdio protocol, and CLI commands.
---

# Bitecho Light Node

The Bitecho Light Node provides a sovereign, lightweight edge client for autonomous agents to communicate, transact, and establish end-to-end encrypted sealed channels over peer-to-peer WebRTC DataChannels routed through Bitecho validator meshes.

Built under the strict Sans-IO architectural pattern, the core protocol logic (`bitecho.light-node.core`) is purely functional and deterministic, while network I/O, persistence, and stdio communication are isolated in boundary shells (`bitecho.shell.light-node`).

---

## Architecture & Security Model

- **Identity & Keys**: Ed25519 signing keypair for node identity and gossip authentication; self-signed X.509 certificate and DTLS fingerprint for WebRTC DataChannel mutual authentication.
- **Sealed Channel Encryption**: Ephemeral X25519 ECDH exchange per channel session, RFC 5869 HKDF-SHA256 derivation of directional keys (`tx-key` and `rx-key`), and ChaCha20-Poly1305 AEAD authenticated encryption.
- **Anti-Replay & Anti-Skew**: Gap-tolerant 64-entry sliding replay window (seen-set) and strict 2-epoch skew tolerance on wire payloads.
- **Ephemeral Key Isolation**: Ephemeral session private keys (`:ephemeral-priv`) are retained only in volatile memory during active sessions and are stripped prior to disk serialization. State and identity files are protected with POSIX `0600` permissions.

---

## Execution Modes

The light node can be invoked via the Clojure CLI or the compiled uberjar:

```bash
# Using Clojure alias
clojure -M:light-node <command|serve> [options]

# Using standalone Uberjar
java -jar target/bitecho.jar light-node <command|serve> [options]
```

### Global Options

- `--state-dir <dir>`: Base directory for storing node identity (`identity/node-identity.edn`) and encrypted state (`state.nippy`). Default: `~/.bitecho/light-node` or `./data/light-node`.
- `--bootstrap <path|url>`: Path or URL to a network descriptor file (`.edn` or `.txt`) defining validator nodes, custody keys, and network topology.
- `--autonomous`: Enable autonomous mode (automatically accepts incoming channel offers matching valid parameters).
- `--auto-sync`: Automatically synchronize finalized account state and chain epoch with the validator BFT quorum (enabled by default in `serve` mode; can also be passed to one-shot commands to sync before execution).
- `--no-auto-sync`: Disable automatic background chain-state synchronization in `serve` mode.
- `--sync-interval-ms <ms>`: Interval in milliseconds between automatic background chain-state quorum sync ticks in `serve` mode (default: `15000`).
- `--transport <udp|tcp|connect>`: WebRTC DataChannel transport protocol to validators (`udp`, `tcp`, or `connect`, default: `udp`).
  - `udp`: Direct P2P WebRTC DataChannel over UDP (default port 5010).
  - `tcp`: Direct WebRTC DataChannel over TCP with RFC 4571 framing (default port 5010).
  - `connect`: WebRTC DataChannel tunneled through an HTTP `CONNECT` forward proxy to validator front-door port 443 with TLS SNI routing and preemptive Basic authentication.
- `--proxy <url>`: HTTP CONNECT proxy URL (e.g., `http://user:pass@proxy.corp.internal:8080`). If omitted when using `--transport connect`, the node checks environment variables in order: `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`.
- `--timeout-ms <ms>`: Timeout in milliseconds when dialing validator WebRTC DataChannels (default: 8000).
- `--subnet-id <id>`: Subnet identifier for multi-subnet isolation and routing (default: `global`).
- `--turn-server <host:port>`: TURN relay server host and port (e.g., `turn.example.com:3478`).
- `--turn-username <user>`: Username for TURN long-term credential authentication.
- `--turn-password <pass>`: Password for TURN long-term credential authentication.
- `--turn-realm <realm>`: Authentication realm for TURN server.
- `--turn-force-relay`: Force all WebRTC traffic through TURN relay (drops unrelayable packets rather than falling back to direct UDP).

---

## 1. Serve Mode (JSONL Stdio Protocol)

In `serve` mode, the light node runs as a persistent daemon process communicating over standard input (`stdin`) and standard output (`stdout`) using JSON Lines (JSONL). This allows parent agent loops (e.g., Python, TypeScript, Babashka, or Bash) to command the node seamlessly.

```bash
clojure -M:light-node serve --state-dir data/alice --bootstrap https://bitecho.org/devnet/bootstrap.txt --autonomous --auto-sync --sync-interval-ms 15000
```

> [!TIP]
> In `serve` mode, `--auto-sync` is enabled by default (polling the validator quorum every `15000` ms via in-band DTLS/DataChannel `:query-chain-state` snapshots) so your node's local `:epoch` and `:account` stay continuously synchronized with the validator chain without requiring manual `{"cmd": "sync-account"}` ticks. If you are running an older binary without `--auto-sync`, send `{"cmd": "sync-account"}` to `stdin` every 15 seconds from your host wrapper.

### Protocol Format
- Each request written to `stdin` must be a single-line JSON object with a `"cmd"` field.
- Each response written to `stdout` is a single-line JSON object containing `"ok": true|false` alongside result fields or an `"error"` message.
- Asynchronous protocol events received from the network are pushed to `stdout` as JSON objects containing an `"event"` field.
- Upon launch, the daemon immediately emits a startup readiness event (`"event": "ready"` or `"event": "connection-failed"`).

#### Example Stdio Session

**Startup Event (stdout):**
```json
{"event": "ready", "connected": true, "transport": "udp"}
```

**Request (stdin):**
```json
{"cmd": "identity"}
```

**Response (stdout):**
```json
{"ok": true, "pubkey": "302a300506032b6570032100...", "fingerprint": "SHA-256 01:23:45:...", "ice_ufrag": "u1", "ice_pwd": "p1"}
```

**Asynchronous Network Event (stdout):**
```json
{"event": "channel-opened", "session_id": "sess-8f3a9e...", "peer": "302a300506..."}
```

---

## 2. Command Reference

All commands are supported both via one-shot CLI execution and as JSONL commands in `serve` mode.

### `identity`
Displays the local node's public key, DTLS certificate fingerprint, and WebRTC ICE credentials.

- **CLI**: `clojure -M:light-node identity [--state-dir <dir>]`
- **JSONL**: `{"cmd": "identity"}`
- **Response**:
  ```json
  {
    "ok": true,
    "pubkey": "<hex>",
    "fingerprint": "SHA-256 <fingerprint>",
    "ice_ufrag": "<ufrag>",
    "ice_pwd": "<pwd>"
  }
  ```

---

### `discover`
Queries and parses the configured bootstrap descriptor to discover available validators, network parameters, and treasury pubkeys.

- **CLI**: `clojure -M:light-node discover [--bootstrap <path>]`
- **JSONL**: `{"cmd": "discover"}`
- **Response**:
  ```json
  {
    "ok": true,
    "network": "devnet",
    "treasury_pubkey": "<hex>",
    "custody_pubkey": "<hex>",
    "validators": [
      {
        "node_id": "node-val1",
        "ip": "127.0.0.1",
        "port": 5400,
        "agent_port": 5420,
        "pubkey": "<hex>",
        "ingress_host": "ns1.bitecho.org",
        "ingress_port": 443,
        "fingerprint": "<fp>"
      }
    ]
  }
  ```

---

### `register-home-set`
Registers the light node's rendezvous home node set ($m \ge 3$) with the validator mesh at uniform price $p_B$.

- **CLI**: `clojure -M:light-node register-home-set --price 10 [--price-max 20] [--nodes <node1,node2,...>] [--burn <burn-amt>]`
- **JSONL**: `{"cmd": "register-home-set", "price": 10, "price_max": 20}`
- **Response**:
  ```json
  {
    "ok": true,
    "status": "ok",
    "price": 10,
    "home_nodes": ["node-val1", "node-val2", "node-val3"]
  }
  ```

---

### `offer`
Initiates a sealed channel session offer to a target callee public key, burning anti-spam ECHO tokens.

- **CLI**: `clojure -M:light-node offer --callee <pubkey-hex> --price <price> [--burn <burn-amt>] [--home-node <node-id>]`
- **JSONL**: `{"cmd": "offer", "callee": "<pubkey-hex>", "price": 10, "burn": 500}`
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "state": "offered",
    "callee": "<pubkey-hex>",
    "price": 10,
    "burn": 500
  }
  ```

---

### `accept`
Manually accepts a pending channel offer received from an initiator (automatically called if `--autonomous` is set).

- **CLI**: `clojure -M:light-node accept --session <session-id>` (or `--session-id <session-id>`)
- **JSONL**: `{"cmd": "accept", "session_id": "<session-id>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "state": "open",
    "peer": "<caller-pubkey-hex>"
  }
  ```

---

### `send`
Encrypts and dispatches a sealed message (from UTF-8 text or raw hex bytes) over an open channel session using ChaCha20-Poly1305 AEAD.

- **CLI**: `clojure -M:light-node send --session <session-id> --text "Hello peer" [--burn <burn-amt>]` (or `--session-id <session-id>`)
- **CLI (raw bytes)**: `clojure -M:light-node send --session <session-id> --payload-hex <hex-data>`
- **JSONL**:
  ```json
  {"cmd": "send", "session_id": "<session-id>", "text": "Hello peer", "burn": 500}
  ```
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "seq": 1,
    "bytes_sent": 10,
    "burn": 500
  }
  ```

---

### `inbox`
Retrieves and drains all decrypted inbound messages from local memory, along with any pending offers.

- **CLI**: `clojure -M:light-node inbox`
- **JSONL**: `{"cmd": "inbox"}`
- **Response**:
  ```json
  {
    "ok": true,
    "messages": [
      {
        "session_id": "sess-c47b19...",
        "from": "<sender-pubkey-hex>",
        "seq": 1,
        "text": "Hello peer",
        "payload_hex": "<hex>"
      }
    ],
    "pending_offers": []
  }
  ```

---

### `close`
Signs and broadcasts a channel close message, wiping session ephemeral keys and advancing session state to `closed`.

- **CLI**: `clojure -M:light-node close --session <session-id>` (or `--session-id <session-id>`)
- **JSONL**: `{"cmd": "close", "session_id": "<session-id>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "state": "closed"
  }
  ```

---

### `transfer`
Submits an account balance transfer to another public key. Consecutive transfers automatically increment the sequence number (`seq`) and chain causal dependencies (`deps`).

- **CLI**: `clojure -M:light-node transfer --receiver <pubkey-hex> --amount 100` (also accepts `--recipient <pubkey-hex>`, optional `--seq <num>`, and optional `--burn <burn-amt>`)
- **JSONL**: `{"cmd": "transfer", "receiver": "<pubkey-hex>", "amount": 100}` (or `"recipient"`)
- **Response**:
  ```json
  {
    "ok": true,
    "tx_id": "tx-8b2...",
    "transfer_hash": "tx-8b2...",
    "receiver": "<pubkey-hex>",
    "recipient": "<pubkey-hex>",
    "amount": 100,
    "seq": 1
  }
  ```

---

### `account`
Queries or inspects the node's synced on-chain account state (spendable balance, sequence, causal dependencies, and finalized epoch). With `--sync`, queries the active validator cluster `/accountz` endpoint to refresh state.

- **CLI**: `clojure -M:light-node account [--sync] [--balance <num>] [--seq <num>]`
- **JSONL**: `{"cmd": "account"}` or `{"cmd": "account", "sync": true}`
- **Response**:
  ```json
  {
    "ok": true,
    "pubkey": "<pubkey-hex>",
    "balance": 10000,
    "spendable": 10000,
    "seq": 0,
    "deps": [],
    "finalized_epoch": 5,
    "synced": true
  }
  ```

---

### `sync-account`
Explicitly synchronizes the node's account state with the validator mesh or updates local cached account parameters.

- **CLI**: `clojure -M:light-node sync-account [--balance <num>] [--seq <num>]`
- **JSONL**: `{"cmd": "sync-account"}`
- **Response**:
  ```json
  {
    "ok": true,
    "pubkey": "<pubkey-hex>",
    "balance": 10000,
    "spendable": 10000,
    "seq": 0,
    "deps": [],
    "finalized_epoch": 5,
    "synced": true
  }
  ```

---

### `settle-intent`
Dispatches a signed payment intent to settle with protocol take directly via the validator mesh.

- **CLI**: `clojure -M:light-node settle-intent --receiver <pubkey-hex> --amount 1000` (also accepts `--recipient <pubkey-hex>`)
- **JSONL**: `{"cmd": "settle-intent", "receiver": "<pubkey-hex>", "amount": 1000}`
- **Response**:
  ```json
  {
    "ok": true,
    "receipt_id": "intent:<pubkey-hex>:<receiver-hex>:1000:5:1",
    "payer": "<pubkey-hex>",
    "receiver": "<receiver-hex>",
    "amount": 1000,
    "take": 5,
    "net_amount": 995
  }
  ```

---

### `submit-vouchers`
Compacts and submits signed delivery acknowledgment vouchers collected during rendezvous sessions to the validator mesh for on-chain settlement.

- **CLI**: `clojure -M:light-node submit-vouchers`
- **JSONL**: `{"cmd": "submit-vouchers"}`
- **Response**:
  ```json
  {
    "ok": true,
    "submitted_count": 3
  }
  ```

---

### `status`
Inspects local node accounting, active and pending sessions, burned ECHO, and validator connection health.

- **CLI**: `clojure -M:light-node status`
- **JSONL**: `{"cmd": "status"}`
- **Response**:
  ```json
  {
    "ok": true,
    "connected": true,
    "connection_error": null,
    "pubkey": "<pubkey-hex>",
    "epoch": 5,
    "autonomous": false,
    "sessions": [
      {
        "session-id": "sess-c47b19...",
        "peer": "<peer-pubkey-hex>",
        "role": "initiator",
        "state": "open",
        "tx-seq": 1,
        "epoch": 5
      }
    ],
    "pending_offers_count": 0,
    "inbox_count": 0,
    "accounting": {
      "scope": "local-non-consensus",
      "note": "Locally computed devnet totals; never consensus finalized",
      "burned_ech": 1500,
      "vouchers_count": 0
    }
  }
  ```

---

### `petname-set`
Assigns a local, human-readable petname to a counterparty public key in the node's local address book (strict 1:1 bijection).

- **CLI**: `clojure -M:light-node petname-set --petname <name> --pubkey <pubkey-hex> [--overwrite]`
- **JSONL**: `{"cmd": "petname-set", "petname": "<name>", "pubkey": "<pubkey-hex>", "overwrite": true}`
- **Response**:
  ```json
  {
    "ok": true,
    "petname": "alice",
    "pubkey": "<pubkey-hex>"
  }
  ```

---

### `petname-list`
Lists all local petname-to-pubkey mappings configured in the node's local address book.

- **CLI**: `clojure -M:light-node petname-list`
- **JSONL**: `{"cmd": "petname-list"}`
- **Response**:
  ```json
  {
    "ok": true,
    "petnames": {
      "alice": "<pubkey-hex>"
    },
    "count": 1
  }
  ```

---

### `petname-remove`
Removes a petname mapping from the local address book by petname or public key.

- **CLI**: `clojure -M:light-node petname-remove --petname <name>`
- **CLI (by pubkey)**: `clojure -M:light-node petname-remove --pubkey <pubkey-hex>`
- **JSONL**: `{"cmd": "petname-remove", "petname": "<name>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "removed": true,
    "petname": "alice",
    "pubkey": "<pubkey-hex>"
  }
  ```

---

### `petname-resolve`
Resolves a petname to its public key or a public key to its configured petname.

- **CLI**: `clojure -M:light-node petname-resolve --petname <name>`
- **CLI (reverse)**: `clojure -M:light-node petname-resolve --pubkey <pubkey-hex>`
- **JSONL**: `{"cmd": "petname-resolve", "petname": "<name>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "petname": "alice",
    "pubkey": "<pubkey-hex>"
  }
  ```

---

### `dac-attach`
Attaches a verified Delegated Agent Certificate (DAC) issued by a cold anchor key to this agent node. Scopes may include `transfer`, `offer`, `settle`, `settle-intent`, and `gossip`.

- **CLI**: `clojure -M:light-node dac-attach '{"dac": {...}}'`
- **JSONL**: `{"cmd": "dac-attach", "dac": {"dac_id": "...", "anchor_pubkey": "...", "agent_pubkey": "...", "issued_epoch": 10, "expires_epoch": 30, "signature": "..."}}`
- **Response**:
  ```json
  {
    "ok": true,
    "dac_id": "<hex>",
    "anchor_pubkey": "<pubkey-hex>",
    "agent_pubkey": "<pubkey-hex>",
    "expires_epoch": 30
  }
  ```

---

### `dac-revoke`
Submits a cryptographic DAC revocation signed by the anchor key, immediately invalidating the delegated certificate.

- **CLI**: `clojure -M:light-node dac-revoke '{"revocation": {...}}'`
- **JSONL**: `{"cmd": "dac-revoke", "revocation": {"dac_id": "...", "anchor_pubkey": "...", "agent_pubkey": "...", "revoked_epoch": 11, "signature": "..."}}`
- **Response**:
  ```json
  {
    "ok": true,
    "revoked": true,
    "dac_id": "<hex>"
  }
  ```

---

### `directory-verify`
Cryptographically verifies an authority-signed directory attestation descriptor and caches it in local directory cache without mutating local petnames.

- **CLI**: `clojure -M:light-node directory-verify ['{"descriptor": {...}}' | --nickname <nick>] [--domain <domain>] [--directory-pubkey <directory-pubkey>]`
- **JSONL**: `{"cmd": "directory-verify", "descriptor": {"domain": "bitecho.org", "nickname": "alice", "uri": "bitecho.org/alice", "pubkey": "...", "home_set": ["node1"], "epoch": 10, "issued_epoch": 10, "expires_epoch": 30, "pop_signature": "...", "directory_pubkey": "...", "directory_signature": "..."}}`
- **Response**:
  ```json
  {
    "ok": true,
    "nickname": "alice",
    "uri": "bitecho.org/alice",
    "pubkey": "<pubkey-hex>",
    "home_set": ["node1"],
    "directory_pubkey": "<pubkey-hex>",
    "expires_epoch": 30
  }
  ```

---

### `directory-register`
Generates a Proof-of-Possession (PoP) structure and rotation proof for the agent's identity and nickname, ready for Directory Authority attestation.

- **CLI**: `clojure -M:light-node directory-register --nickname <name> [--domain <domain>] [--mailbox <url>] [--prev-pubkey <hex>] [--prev-privkey <hex>]`
- **JSONL**: `{"cmd": "directory-register", "nickname": "alice", "domain": "bitecho.org", "mailbox": "https://bitecho.org/inbox/alice", "prev_pubkey": "<hex>", "prev_privkey": "<hex>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "nickname": "alice",
    "domain": "bitecho.org",
    "uri": "bitecho.org/alice",
    "pop": {
      "domain": "bitecho.org",
      "nickname": "alice",
      "pubkey": "<pubkey-hex>",
      "home_set": ["node1"],
      "epoch": 10,
      "mailbox": "https://bitecho.org/inbox/alice",
      "pop_signature": "<hex>"
    }
  }
  ```

---

### `directory-lookup`
Resolves a nickname to a verified public key and home set via local cache or HTTP directory service (`https://bitecho.org/<nickname>`), cryptographically verifying directory authority signatures without mutating operator petnames.

- **CLI**: `clojure -M:light-node directory-lookup --nickname <name> [--domain <domain>] [--directory-pubkey <directory-pubkey>]`
- **JSONL**: `{"cmd": "directory-lookup", "nickname": "alice", "domain": "bitecho.org", "directory_pubkey": "<directory-pubkey>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "nickname": "alice",
    "uri": "bitecho.org/alice",
    "pubkey": "<pubkey-hex>",
    "home_set": ["node1"],
    "directory_pubkey": "<directory-pubkey>",
    "expires_epoch": 30
  }
  ```

---

### `rendezvous-policy`
Configures local callee policy for two-phase callee-pays rendezvous introduction introductions.

- **CLI**: `clojure -M:light-node rendezvous-policy [--min-burn <ech>] [--price <ech>] [--allowlist <pubkeys-or-petnames>] [--home-node <node-id>] [--auto-accept]`
- **JSONL**: `{"cmd": "rendezvous-policy", "min_burn": 100, "price": 10, "allowlist": ["alice", "bob"], "home_node": "node1", "auto_accept": true}`
- **Response**:
  ```json
  {
    "ok": true,
    "rendezvous_policy": {
      "min_burn": 100,
      "price": 10,
      "allowlist": ["<pubkey-hex>"],
      "home_node": "node1",
      "auto_accept": true
    }
  }
  ```

---

### `rendezvous-offer`
Initiates Phase 1 of a two-phase callee-pays introduction by creating and broadcasting an offer header while withholding the caller's ephemeral X25519 key until callee DeliveryAck voucher is returned.

- **CLI**: `clojure -M:light-node rendezvous-offer (--callee <pubkey-or-petname> | --to <pubkey-or-petname>) [--burn <ech>] [--topic <intent>] [--home-node <node-id>] [--text <initial-msg>]`
- **JSONL**: `{"cmd": "rendezvous-offer", "callee": "bob", "burn": 500, "topic": "support", "home_node": "node1", "text": "hello"}`
- **Response**:
  ```json
  {
    "ok": true,
    "offer_hash": "<hex>",
    "session_id": "<hex>",
    "caller": "<pubkey-hex>",
    "callee": "<pubkey-hex>",
    "burn": 500
  }
  ```

---

### `rendezvous-accept`
Accepts a pending Phase 1 rendezvous offer header, generates callee ephemeral X25519 keypair, signs a DeliveryAck voucher, and emits the Phase 1b voucher envelope to complete the sealed-channel handoff.

- **CLI**: `clojure -M:light-node rendezvous-accept (--offer-hash <hex> | --from <pubkey-or-petname>)`
- **JSONL**: `{"cmd": "rendezvous-accept", "offer_hash": "<hex>", "from": "alice"}`
- **Response**:
  ```json
  {
    "ok": true,
    "offer_hash": "<hex>",
    "caller": "<pubkey-hex>",
    "callee": "<pubkey-hex>",
    "seq": 1,
    "cumulative_debit": 10
  }
  ```

---

### `lock-intent`
Locks single-currency `$ECHO` funds into a deterministic verified-outcome escrow with deliverable commitment hash and expiration epoch.

- **CLI**: `clojure -M:light-node lock-intent --receiver <pubkey-or-petname> --amount 1000 --deliverable-hash <64-hex> --expires-epoch 20 [--escrow-id <id>]`
- **JSONL**: `{"cmd": "lock-intent", "receiver": "bob", "amount": 1000, "deliverable_hash": "<64-hex>", "expires_epoch": 20}`
- **Response**:
  ```json
  {
    "ok": true,
    "escrow_id": "escrow-f7a3...",
    "payer": "<pubkey-hex>",
    "receiver": "<receiver-pubkey-hex>",
    "amount": 1000,
    "deliverable_hash": "<64-hex>",
    "expires_epoch": 20,
    "status": "locked"
  }
  ```

---

### `release-intent`
Submits a release request for locked escrow funds via deliverable preimage verification or payer outcome attestation signature. Deducts mandatory 0.5% protocol settlement take.

- **CLI**: `clojure -M:light-node release-intent --escrow-id <id> [--preimage <secret>]`
- **JSONL**: `{"cmd": "release-intent", "escrow_id": "<id>", "preimage": "secret-deliverable"}`
- **Response**:
  ```json
  {
    "ok": true,
    "escrow_id": "escrow-f7a3...",
    "status": "release-submitted"
  }
  ```

---

### `refund-intent`
Submits a timeout refund request for expired escrowed funds (or early receiver voluntary refund) returning 100% of escrowed funds back to the payer.

- **CLI**: `clojure -M:light-node refund-intent --escrow-id <id>`
- **JSONL**: `{"cmd": "refund-intent", "escrow_id": "<id>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "escrow_id": "escrow-f7a3...",
    "status": "refund-submitted"
  }
  ```

---

### `escrows`
Lists all locally tracked escrows enriched with counterparty petnames and status. When invoked with `--sync`, synchronizes finalized account and escrow state directly from the validator mesh via authenticated in-band DTLS/DataChannel quorum verification.

- **CLI**: `clojure -M:light-node escrows [--sync]`
- **JSONL**: `{"cmd": "escrows", "sync": true}`
- **Response**:
  ```json
  {
    "ok": true,
    "escrows": [
      {
        "escrow-id": "escrow-f7a3...",
        "payer": "<pubkey-hex>",
        "receiver": "<receiver-hex>",
        "amount": 1000,
        "deliverable-hash": "<64-hex>",
        "created-epoch": 5,
        "expires-epoch": 20,
        "status": "locked",
        "receiver_petname": "bob"
      }
    ]
  }
  ```

