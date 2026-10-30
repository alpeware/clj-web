# clj-web

A self-contained, minimal-dependency Clojure **Authoritative Nameserver (DNS)**, **Inbound SMTP Receiver**, **ACME v2 (Let's Encrypt) Client**, **3-Node P2P Cluster**, and **HTTP/HTTPS Static Content Server** targeting **OpenJDK 25**.

Designed to run across **3x Google Cloud Platform `e2-micro` VMs** (1 GB RAM, 2 shared vCPUs, 30 GB disk, 1 GB/month egress) or any 3 hosts with static IPv4/IPv6 addresses to deliver high-availability static documentation, scripts, Clojure source code, and JAR artifacts primarily for autonomous AI agents and CLI tooling.

See [DESIGN.md](DESIGN.md) for the complete architectural specification and implementation plan.

---

## Features

- **Authoritative DNS Server (UDP & TCP Port 53)**:
  - Pure Clojure RFC 1035 wire parser/serializer (`A`, `AAAA`, `NS`, `SOA`, `MX`, `TXT`, `CAA`).
  - Serves as your domain's personal nameservers (`ns1`, `ns2`, `ns3`) via registrar glue records.
  - **Health-Aware Multi-A / AAAA Routing**: Automatically returns all healthy VM IPs (`TTL 60s`) based on cluster heartbeats for seamless client failover.
  - **Email DNS Records**: Serves `MX` (`10 ns1`, `20 ns2`, `30 ns3`) and `TXT` (`SPF`, `DMARC`, `DKIM`) records out of the box.
  - Hardened with `0x20` bit case preservation, UDP truncation (`TC=1`) with TCP fallback, and per-subnet Response Rate Limiting (RRL) (skipping DNSSEC to prevent UDP amplification bloat and `DS` lockout risk).
- **Inbound SMTP Server (TCP Port 25 with `STARTTLS`)**:
  - Pure Sans-IO RFC 5321 session state machine + Virtual-Thread TCP listener for receiving domain verification, registrar (e.g., Namecheap), and security emails (`admin@`, `hostmaster@`, `postmaster@`, `security@`).
  - Supports `STARTTLS` reusing the hot-swappable Let's Encrypt `SSLContext` (whose certificate covers `ns1..ns3.<domain>`).
  - Strict open-relay rejection (`550 5.7.1`), 128 KB message size cap (`552`), atomic `.eml` storage in `/var/lib/clj-web/mail/`, and automatic `.eml` replication across all 3 cluster nodes.
- **P2P Cluster Control Plane via [`clj-datachannel`](https://github.com/alpeware/clj-datachannel)**:
  - Connects the 3 static-IP nodes over encrypted WebRTC DataChannels (SCTP over DTLS over UDP port 5000) authenticated via pinned SHA-256 certificate fingerprints.
  - Quorum-backed leader election ensures a single leader coordinates Let's Encrypt certificate provisioning and renewal.
  - Replicates HTTP-01 challenge tokens prior to validation, distributes issued TLS keypairs, and syncs received `.eml` emails across peers.
- **Automated Let's Encrypt HTTPS (ACME v2)**:
  - Pure JDK `java.net.http.HttpClient` + `java.security` (ECDSA P-256 / `ES256` JWS) implementation of RFC 8555.
  - **Zero-Downtime TLS Reload**: Atomic `SSLContext` swap in `com.sun.net.httpserver.HttpsServer` and SMTP `STARTTLS` without dropping active connections.
  - Port 80 answers `/.well-known/acme-challenge/*` and redirects all other traffic to `https://` via `308 Permanent Redirect`.
- **Agent-First Static Content Engine**:
  - Built on JDK 25's `com.sun.net.httpserver` with **Virtual Threads** (`newVirtualThreadPerTaskExecutor`).
  - **Two-Tier Serving**: Small/hot files ($\le 2\text{ MB}$: `.md`, `.clj`, `.edn`, `.sh`, `.pom`) are served from a bounded 128 MB RAM cache with pre-computed `.gz` buffers and SHA-256 `ETag`s; large artifacts (`> 2 MB`: `.jar`) stream directly from disk with `Range` (`206 Partial Content`) support.
  - **1 GB/Month Egress Protection**: Aggressive `304 Not Modified`, transparent Gzip compression, per-IP rate limiting, and monthly egress circuit-breakers.

---

## Minimal Runtime Dependencies

- [`org.clojure/clojure`](https://clojure.org/) (`1.12.4`)
- [`org.clojure/data.json`](https://github.com/clojure/data.json) (`2.5.1`) — ACME v2 JSON/JWS serialization
- [`alpeware/clj-datachannel`](https://github.com/alpeware/clj-datachannel) — Pure Clojure WebRTC DataChannels (SCTP/DTLS/UDP) for 3-node cluster coordination

---

## Quick Start (Local Development)

### Prerequisites

- **Java 25** (OpenJDK 25+)
- **Clojure CLI** (`1.12+`)

### Run Tests, Linter & Formatter

```bash
# Run unit & generative property tests
clojure -M:test

# Lint with clj-kondo
clojure -M:lint

# Format with cljfmt
clojure -M:format
```

---

## Deploying on 3x Hosts (GCP `e2-micro` + Namecheap Glue Records)

### Step 1: Provision 3 Static-IP VMs

Create 3 `e2-micro` instances (e.g., in `us-central1`, `us-east1`, `us-west1` to stay within GCP's Always Free tier) with static external IPv4 addresses (`IP1`, `IP2`, `IP3`) and open firewall rules for:
- `udp/53`, `tcp/53` (Authoritative DNS)
- `tcp/25` (Inbound SMTP)
- `tcp/80`, `tcp/443` (HTTP & HTTPS)
- `udp/5000` (Cluster `clj-datachannel` mesh, restricted to `IP1`, `IP2`, `IP3`)

### Step 2: Register Personal Nameservers (Glue Records) at Namecheap

Follow Namecheap's [Personal Nameservers guide](https://www.namecheap.com/support/knowledgebase/article.aspx/768/10/how-do-i-register-personal-nameservers-for-my-domain/):
1. Go to **Domain List** $\rightarrow$ **Manage** $\rightarrow$ **Advanced DNS** $\rightarrow$ **Personal DNS Server**.
2. Register your three glue records:
   - `ns1.yourdomain.com` $\rightarrow$ `IP1`
   - `ns2.yourdomain.com` $\rightarrow$ `IP2`
   - `ns3.yourdomain.com` $\rightarrow$ `IP3`
3. Under the **Domain** tab $\rightarrow$ **Nameservers**, select **Custom DNS** and enter `ns1.yourdomain.com`, `ns2.yourdomain.com`, and `ns3.yourdomain.com`.

### Step 3: Configure & Start `clj-web` on Each Node

Place `/etc/clj-web/config.edn` on each VM (setting `:node/id` to `:ns1`, `:ns2`, or `:ns3`) and deploy your static files to `/var/www/clj-web/public` via `git` or `rsync`.

```bash
java \
  -Xms256m -Xmx512m \
  -XX:MaxMetaspaceSize=96m \
  -XX:MaxDirectMemorySize=64m \
  -XX:+UseCompactObjectHeaders \
  -XX:+UseZGC \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar clj-web.jar /etc/clj-web/config.edn
```

Once at least 2 of the 3 nodes are online, they automatically form a DTLS/SCTP mesh, elect a leader, obtain a Let's Encrypt certificate (covering `<domain>` and `ns1..ns3.<domain>`) via HTTP-01, distribute the TLS bundle to all peers, and begin serving HTTPS (port 443) and `STARTTLS` Inbound SMTP (port 25).

---

## Cluster Automation (`scripts/cluster.sh`)

`scripts/cluster.sh` is an idempotent management script for provisioning, deploying, and inspecting the 3-node cluster on GCP `e2-micro` instances.

### 1. Provision Cluster (`init`)

Provisions GCP projects, links billing, reserves static external IPv4 addresses, configures firewall rules, boots `e2-micro` Debian 12 instances, and bootstraps OpenJDK 25 and `clj-web.service`:

```bash
./scripts/cluster.sh init
```

Upon completion, `init` prints the Namecheap Personal Nameserver glue records (`ns1`, `ns2`, `ns3`) and writes `.cluster.env` and `cluster.edn`.

### 2. Deploy & Restart (`deploy`)

Builds the local standalone uberjar (`target/clj-web.jar`), uploads it via `rsync`, queries each node's DTLS SHA-256 fingerprint, renders per-node `/etc/clj-web/config.edn` configs with pinned fingerprints, syncs `public/` web assets, and restarts `clj-web.service`:

```bash
# Production Let's Encrypt certificate
./scripts/cluster.sh deploy

# Or test with Let's Encrypt Staging environment
./scripts/cluster.sh deploy --staging
```

### 3. Inspect Cluster Health (`status`)

Displays the live status of all 3 cluster nodes, including GCP VM state, static IPs, `systemctl is-active`, RAM consumption, DNS A-record resolution, and inbound email count:

```bash
./scripts/cluster.sh status
```

Additional operational subcommands:
- `./scripts/cluster.sh logs [ns1|ns2|ns3]` — View or follow systemd journal logs.
- `./scripts/cluster.sh mail [ns1|ns2|ns3]` — List received and replicated `.eml` emails.
- `./scripts/cluster.sh ssh <ns1|ns2|ns3>` — Open an interactive SSH session to a node.

---

## License

Copyright © 2026 Alpeware.
