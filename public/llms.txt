# Bitecho (bitecho.org)

Welcome to **Bitecho**, a high-performance, decentralized peer-to-peer messaging and coordination protocol built on pure Clojure and WebRTC DataChannels.

## Gentoo / Source-First Philosophy

Bitecho embraces a source-first distribution model inspired by Gentoo Linux:
- **Canonical Git Origin**: Software is published directly from self-hosted canonical bare Git repositories hosted on the Bitecho 3-node cluster.
- **Cryptographic Provenance**: Every repository snapshot is signed with an SSH Ed25519 release key (`verified` tag) documented at [`/keys.txt`](/keys.txt).
- **Zero Opaque Binaries**: Autonomous agents and developers fetch and build pure Clojure source code directly via Clojure CLI (`deps.edn`) with zero intermediate binary registries.

---

## Canonical Git Repositories

| Repository | Default Branch | HEAD Commit | Canonical Clone URL |
| :--- | :--- | :--- | :--- |
| **bitecho** | `main` | `94f5db3e8732` | `https://bitecho.org/git/bitecho.git` |
| **clj-datachannel** | `main` | `3d8dce160007` | `https://bitecho.org/git/clj-datachannel.git` |
| **clj-web** | `master` | `afd9fb65244c` | `https://bitecho.org/git/clj-web.git` |

### Clojure CLI (`deps.edn`) Dependencies

```clojure
;; In your deps.edn
{:deps
 {alpeware/bitecho {:git/url "https://bitecho.org/git/bitecho.git"
                   :git/sha "94f5db3e87320ae541964784c3cebf862f503b76"}
  alpeware/clj-datachannel {:git/url "https://bitecho.org/git/clj-datachannel.git"
                           :git/sha "3d8dce1600070ad1b4f9b843557b60b37bb459e2"}
  alpeware/clj-web {:git/url "https://bitecho.org/git/clj-web.git"
                   :git/sha "afd9fb65244c019a23213f17c6eacddf41553fda"}}}
```

---

## Cryptographic Verification

All canonical repositories include an SSH-signed annotated tag `verified` pointing to the canonical HEAD.

```bash
# 1. Trust the Bitecho release signing key
curl -sSL https://bitecho.org/keys.txt | grep ssh-ed25519 >> ~/.config/git/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

# 2. Clone and verify
git clone https://bitecho.org/git/bitecho.git
cd bitecho
git tag -v verified
```

---

## Cluster Architecture

Bitecho runs across 3 geographically distributed GCP `e2-micro` nodes (`ns1` in US West, `ns2` in US Central, `ns3` in US East):
- **Authoritative DNS** (UDP & TCP port 53): Low-TTL multi-A records with automatic node health filtering.
- **Static Content Engine** (TCP port 80 & 443): JVM 25 Virtual Threads with transparent Gzip, LRU caching, and byte-range streaming.
- **Inbound SMTP** (TCP port 25): STARTTLS listener with domain-allowlist filtering and cluster-wide email replication.
- **ACME v2 Automation**: Automated Let's Encrypt certificate issuance with zero-downtime hot-reloading.
- **P2P Mesh Control Plane** (UDP port 5000): Encrypted WebRTC DataChannels (`clj-datachannel`) for cluster heartbeats, challenge quorum, and state replication.

---

## Backup Mirrors (GitHub)

- [https://github.com/alpeware/bitecho](https://github.com/alpeware/bitecho)
- [https://github.com/alpeware/clj-datachannel](https://github.com/alpeware/clj-datachannel)
- [https://github.com/alpeware/clj-web](https://github.com/alpeware/clj-web)

---

## Quick Links

- [Canonical Git Repositories](/git/)
- [Release Signing Key](/keys.txt)
- [LLM / Agent Overview](/llms.txt)
- [Cluster Healthcheck](/healthz)
