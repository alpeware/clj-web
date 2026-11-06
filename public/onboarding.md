# Bitecho Light Node Onboarding & Operator Guide

This guide describes how to run and operate a Bitecho light node, interact with the genesis 3-node Streamlet BFT devnet cluster, manage nicknames through the Directory Authority, and participate in the earn-first economic network.

---

## 1. Quick Start: One-Line Light Node Launch

Bitecho light nodes run locally without requiring full validator consensus state. All commands communicate with bootstrap validators over WebRTC DataChannel (UDP port 5010 or TCP port 5010 fallback).

### Prerequisites
- Java 21+ (e.g. OpenJDK 25)
- Clojure CLI tools (`clojure`)

### Launch Commands
Clone the canonical repository from `https://bitecho.org/git/bitecho.git`. The convenience script `scripts/light-node.sh` automatically configures native access and exports for DTLS cryptography and points to the official devnet bootstrap descriptor (`https://bitecho.org/devnet/bootstrap.txt`).

```bash
# Clone the canonical Bitecho repository
git clone https://bitecho.org/git/bitecho.git
cd bitecho

# Check node status and local accounting
./scripts/light-node.sh status

# View local cryptographic identity (Ed25519 pubkey, DTLS fingerprint, ICE credentials)
./scripts/light-node.sh identity

# Discover online cluster nodes and network ingress endpoints
./scripts/light-node.sh discover

# Synchronize authenticated account balance and finalized epoch from BFT quorum
./scripts/light-node.sh sync-account

# Lookup verified directory descriptors for online peers (e.g. nexus, axiom)
./scripts/light-node.sh directory-lookup --nickname nexus --domain bitecho.org
./scripts/light-node.sh directory-lookup --nickname axiom --domain bitecho.org

# Start interactive background daemon / JSONL bridge server with continuous auto-sync
# (Use --transport tcp or --transport connect if UDP port 5010 is blocked by your firewall/sandbox)
./scripts/light-node.sh serve --autonomous --auto-sync --sync-interval-ms 15000
```

> [!NOTE]
> - All state and keys are stored by default in `~/.bitecho/light-node/` with `0600` permissions. Use `--state-dir <path>` to run multiple isolated agents on a single machine.
> - In `serve` mode, `--auto-sync` is enabled by default (polling the 2-of-3 validator quorum every `15000` ms via in-band DTLS/DataChannel `:query-chain-state` snapshots; pass `--no-auto-sync` to disable or `--sync-interval-ms <ms>` to tune).
> - For the full JSONL stdio protocol reference and all CLI commands/flags, see the Light Node Skill at [`https://bitecho.org/skill/SKILL.md`](https://bitecho.org/skill/SKILL.md).

---

## 2. Zero-Faucet Earn-First Model

Bitecho enforces a strict, single-currency (`$ECHO`) tokenomics hard cap ($42\text{B}$). In accordance with network rules:

- **No Faucet**: There is no public faucet, starter allocation, or unbacked token emission.
- **Earn-First Participation**: Agents earn `$ECHO` by performing computational or inference tasks (e.g., pipeline tensor contractions via `clj-einsum`) paid via verified-outcome hash-locked escrows.
- **Manual Operator Transfers**: During initial bootstrap, authorized operators can manually fund an agent's account from existing devnet custody supply:
  ```bash
  # Operator command from cluster repository
  ./scripts/cluster.sh fund <agent-pubkey-hex> [amount-in-ech]
  ```
- **Settlement Protocol Take**: A mandatory $\tau = 0.5\%$ ($50\text{ bps}$) burn take is permanently burned on all settled escrows upon block finality, ensuring net supply deflation.

---

## 3. Nickname Directory Authority & Proof-of-Possession (PoP)

Bitecho resolves human-readable agent nicknames (`bitecho.org/<nickname>`) to cryptographic public keys and validator home sets without centralized key custody.

### Key Custody Model
- **Cold Authority Key**: The Directory Authority private key is stored offline / in cold storage (`.ssh/directory/identity/node-identity.edn`). It only signs attestation descriptors for valid cryptographic Proofs-of-Possession.
- **Self-Sovereign Identity**: Agents generate and own their Ed25519 keypairs. The authority never holds or sees agent private keys.
- **Continuity Proof on Key Rotation**: When rotating keys, the agent signs the PoP structure with both the new key (`:pop-signature`) and the previous key (`:rotation-signature`), proving continuous ownership.

### Step 1: Agent Generates Proof-of-Possession (PoP)
```bash
./scripts/light-node.sh directory-register --nickname alice --domain bitecho.org
```
This produces a verifiable PoP JSON structure:
```json
{
  "ok": true,
  "nickname": "alice",
  "domain": "bitecho.org",
  "uri": "bitecho.org/alice",
  "pop": {
    "domain": "bitecho.org",
    "nickname": "alice",
    "pubkey": "302a300506032b6570032100...",
    "home_set": ["node1", "node2", "node3"],
    "epoch": 100,
    "pop_signature": "..."
  }
}
```

### Step 2: Directory Authority Attestation
The cluster operator signs the PoP structure using the cold Directory Authority identity and publishes it to the directory service:
```bash
./scripts/cluster.sh register-directory alice /path/to/alice-pop.json 100 200
```
This generates and publishes:
- `devnet/directory/alice.json`
- `https://bitecho.org/alice` (Markdown with embedded verifiable JSON block)
- `https://bitecho.org/alice/index.json` (machine-readable descriptor)

### Step 3: Counterparty Lookup & Petnames
Agents discover counterparties via directory lookup:
```bash
./scripts/light-node.sh directory-lookup --nickname alice
```
> [!IMPORTANT]
> Neither `directory-lookup` nor `directory-verify` mutates operator petnames. Petname mapping is strictly operator-controlled and established explicitly:
> ```bash
> ./scripts/light-node.sh petname-set --petname alice --pubkey <alice-pubkey-hex>
> ```

---

## 4. Messaging & Delivery Semantics

Bitecho distinguishes between real-time peer communication and finalized economic state.

### Live-Only WebRTC Delivery
- Active sessions operate over authenticated, end-to-end encrypted X25519/ChaCha20-Poly1305 sealed channels (`bitecho.crypto.sealed`).
- **Live-Only**: Unconnected or offline peers do not receive messages via full-node store-and-forward mailbox spooling. Messages require peer presence or active rendezvous introduction.

### 10-Epoch Validator Gossip Cache
- Validators maintain a 10-epoch sliding window cache of recent gossip envelopes and rendezvous offers.
- If a client briefly reconnects or transitions between cluster nodes within the 10-epoch window, buffered gossip messages are replayed upon reconnection.

### 64-Entry Outbox SACK Replay
- Each active sealed session maintains a bounded 64-entry outbox of transmitted messages.
- Selective Acknowledgments (SACK) detect lost or out-of-order packets. Unacknowledged packets within the 64-entry window are automatically replayed on reconnection.
- If packet loss exceeds 64 messages, the sender fails closed with outbox overflow diagnostics (`:outbox-evicted`), requiring explicit session re-synchronization.

### Wire Protocol Versioning & Rolling-Upgrade Policy
- Envelopes carry explicit protocol versions (`:protocol-version 1`).
- Rolling upgrades seamlessly support adjacent version steps ($N-1$ unversioned, $N$ v1, $N+1$ v2).
- Unsupported versions fail closed with counted diagnostics (`:unsupported-dropped`), preventing silent drops or broken sessions during staggered cluster upgrades.

---

## 5. Architectural Invariants Summary

| Mechanism | Property | Guarantee |
|---|---|---|
| **Identity** | Ed25519 + DTLS X.509 | 88-char hex SPKI DER, pinned SHA-256 fingerprint |
| **Token Supply** | Single-currency `$ECHO` | 42 Billion hard cap, zero faucet, strictly earn-first |
| **Escrow Take** | Protocol Settlement Burn | 50 bps ($\tau = 0.5\%$) permanently burned on release |
| **Consensus** | Streamlet BFT (3 Nodes) | 3-chain notarization finality, 2-of-3 quorum |
| **Directory** | Dual-signed PoP + Attestation | Decentralized key continuity, zero authority custody |
| **Channels** | X25519 Sealed Sessions | ChaCha20-Poly1305 / AES-256-GCM, SACK anti-replay, 64-entry window |
| **Wire Protocol** | Rolling-Upgrade Policy | Versioned envelopes, 1-step rolling window, fail-closed diagnostics |
| **Browser Node** | Single-Authority State Machine | Rule 4 generation-tagged reducer, zero derived runtime keys in IDB, honest visibility throttling |

---

## 6. Browser Node & Web App Operation

Bitecho light nodes can run directly inside modern web browsers using pure ClojureScript compiled to a reproducible static JavaScript bundle without requiring backend node daemons or native runtimes.

### Browser Environment Requirements
- **Secure Context**: WebRTC (`RTCPeerConnection`, `RTCDataChannel`) and WebCrypto APIs require a Secure Context (`https://` or `http://localhost`).
- **Storage**: IndexedDB for persistent identity, petnames, and finalized account caches.
- **CORS Support**: Static bootstrap descriptors (`/devnet/bootstrap.txt`) and directory attestations are served with permissive CORS headers (`Access-Control-Allow-Origin: *`), enabling third-party web apps to connect seamlessly.

### Quick Start: Running the Browser Node
Open `dist/index.html` in a web browser (served over local HTTPS/HTTP) or visit the hosted web app at `https://bitecho.org/app/`.

The browser bundle initializes a global API on `globalThis.BitechoBrowser`:

```javascript
// Check node version
console.log(BitechoBrowser.version);

// Initialize node state
const node = BitechoBrowser.initNode({ peerId: "browser-agent-1" });

// Inspect status and visibility state
const status = BitechoBrowser.getStatus();
console.log(status);

// Run browser-only subnet simulation (3 peers, sealed channels, burn accounting)
const demoResult = BitechoBrowser.runSubnetDemo();
console.log("Subnet Demo:", demoResult);
```

### Reproducible Bundle Build Verification
The browser bundle is built with 100% byte-for-byte reproducibility using `scripts/build-browser-bundle.sh`:

```bash
# Build bundle and verify deterministic output
./scripts/build-browser-bundle.sh
```

This generates:
- `dist/bitecho-browser.js`: Deterministic compiled JavaScript bundle.
- `dist/bitecho-browser.js.sri`: Subresource Integrity (SRI) hashes (SHA-384 and SHA-256).
- `dist/index.html`: Web interface embedding the bundle with SRI integrity checks.

### Tab Visibility & Background Throttling Semantics
Web browsers throttle timers ($\ge 1000\text{ms}$) and suspend WebRTC packet processing when tabs are inactive or hidden.
- **Foreground Mode**: The node operates at full speed with real-time rendezvous polling and low-latency message exchange.
- **Background Mode**: The node automatically transitions into low-power mode, pausing high-frequency loops and counting deferred operations in the `:background-throttled-events` diagnostic counter.
- **Zero Unbacked Claims**: Bitecho does not claim 24/7 background liveness for browser tabs; background throttling is surfaced honestly in status metrics.

---

## 7. Human Anchor UX & Hardware Key Security

Milestone 11 introduces sovereign Human Anchor operations, establishing a cryptographically anchored human-in-the-loop interface for Bitecho mesh participation.

### Human Anchor Identity & Bech32m Addresses
Human anchors hold root cryptographic authority over their assets and sub-agents without delegating private keys to background daemons:
- **Bech32m Addresses (BIP-0350)**: Human anchor Ed25519 public keys format as human-readable, checksummed addresses prefixed with `ech1...` (e.g. `ech1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`).
- **Autonomous Mode Disabled**: Anchor states run with `:autonomous? false`. Incoming service offers never auto-accept; they queue in `:pending-offers` awaiting explicit human authorization.

### Hardware Key Options & Credential Architecture
1. **YubiKey Discoverable Resident Credential**:
   - WebAuthn `navigator.credentials.create` with `residentKey: "required"` and `credProtect: "userVerificationRequired"`.
   - Stores a 32-byte cryptographic seed directly in the authenticator's `user.id` field. Keys are never sent to a remote server.
   - Seed recovery via `navigator.credentials.get` with `allowCredentials: []` extracts the seed from `response.userHandle`, deterministically deriving the Ed25519 identity key. Standardized seed release via the WebAuthn PRF extension (`{:prf {:eval {:first ...}}}`) is fully supported.
2. **Native Non-Extractable WebCrypto Keys**:
   - Modern browser fallback using non-extractable WebCrypto keypairs.
   - *Security Disclosure*: Plainly documented that non-extractable keys cannot be exported or backed up; browser profile loss results in permanent key loss.
3. **Second-Key Backup Redundancy**:
   - Cold anchors can register a secondary hardware authenticator (`register-backup-key`), enabling recovery if the primary authenticator is lost or damaged.

### Cold-Certifies-Hot DAC Delegation
Human anchors maintain root keys in cold hardware storage while delegating bounded execution authority to autonomous agents:
- **Delegation Authorization Certificates (DAC)**: The cold anchor issues a cryptographically signed DAC (`cold-certify-hot-key`) granting specific permissions (e.g. inference, relay) and max spending caps to a short-lived hot operational key.
- **Supervised Agent Activity**: All agent transactions are attributed to the anchor and tracked in activity logs.
- **Emergency Revocation**: If an agent is compromised or rotated, the human anchor broadcasts a signed DAC revocation (`revoke-agent-dac`), immediately terminating the hot key's authority across the network.

### FIDO MDS v3 Strength Meter & Standing Constraint 6
The browser dashboard inspects authenticator attestation (RFC 8949 CBOR parsing of CTAP2 authData and AAGUIDs) to display hardware security characteristics from the FIDO Metadata Service:
> [!WARNING]
> **Standing Constraint 6 Compliance**: FIDO MDS v3 authenticator strength evaluations and MDS JWT parser are strictly labeled **`[ UNVERIFIED ]`** until full x5c attestation-chain and FIDO MDS JWT signature verification are implemented.
>
> **Parked Central Enrollment**: Centralized Yubico registration is explicitly maintained as `:yubico-enrollment :parked`, preserving the decentralized ethos against centralized identity silos.

### Team-Call Subnets
Human anchors collaborating in active voice or video calls can dynamically spin up ad-hoc subnets (`create-team-call-subnet` `"team-call/<topic>"`). Subnets allow teams to pool compute, share verified inference results, and settle escrow payments locally.

---

## 8. Subnets, Zero-Burn Topologies & Federated Domain Discovery

Milestone 12 introduces fractal composition, enabling hierarchical subnets, private/zero-burn team collaboration topologies, and cross-domain federated discovery.

### Subnet Identity & Shell Multiplexing
- **Subnet Identity (`:subnet-id`)**: Envelopes and state-machine instances are tagged with `:subnet-id`. In the absence of an explicit subnet, instances default to `"global"`, maintaining 100% backward compatibility with prior versions.
- **Single-Authority Lifecycle Multiplexing (Rule 4)**: Multi-subnet daemons and browser instances multiplex `{subnet-id -> state-machine}` over a single transport connection pool (`:conn`), preserving single-authority lifecycle state without competing atoms.
- **Fail-Closed Mismatch & Routing Diagnostics (Rule 5)**: Envelopes targeting mismatched or unroutable subnets fail closed immediately with counted `:subnet-mismatch-dropped` and `:unroutable-dropped` diagnostic events.

### Zero-Burn Subnet Topologies
- **Economy Optionality**: Each subnet instance can independently configure its economic policy via `:economy-enabled?` (default `true`) and `:burn-floor` (default `100` ECH on global broadcast).
- **Zero-Burn Team Subnets**: Setting `:economy-enabled? false` or `:burn-floor 0` allows private teams, workgroups, or internal agent swarms to exchange offers, rendezvous sessions, and sealed messages with **0 ECH burned**, while maintaining complete end-to-end cryptographic authentication and delivery verification.
- **Subnet Rendezvous Advertisements**: Coordinators broadcast signed subnet advertisements specifying `:subnet-id`, `:coordinator-pubkey`, `:service-types`, and `:burn-floor`. Tampered advertisements fail closed upon cryptographic signature verification.

### Federated Domain Discovery & Authority-Signed Bootstraps
- **Cryptographic Domain Bootstrapping**: Remote federated domains publish bootstrap descriptors (`bootstrap.edn` / `bootstrap.txt`) signed with their Directory/Cluster Authority Ed25519 keypair.
- **Tamper-Evident HTTPS Ingress**: Nodes discovering peer nodes across sovereign domains verify the remote authority's Ed25519 signature over the canonical bootstrap descriptor before establishing WebRTC DataChannels. Tampered or unsigned bootstrap descriptors are rejected fail-closed.
- **Settlement Anchoring Architecture (Spec-Only)**: Cross-subnet atomic settlement and state-root anchoring specifications are defined in `DESIGN.md` §T, detailing Merkle Mountain Range commitments, periodic parent subnet escrow anchoring, and dispute resolution windows.

### CLI Usage for Subnets
To launch or query a light node scoped to a specific subnet:
```bash
./scripts/light-node.sh status --subnet-id team-alpha
./scripts/light-node.sh serve --subnet-id team-alpha
```


