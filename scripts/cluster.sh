#!/usr/bin/env bash
# ==============================================================================
# scripts/cluster.sh - Cluster management tooling for bitecho.org (clj-web)
# Manages provisioning, bootstrap, deployment, operations, and status across
# 3 geographically distributed GCP e2-micro nodes (ns1, ns2, ns3).
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source local overrides if present
if [[ -f "${ROOT_DIR}/.cluster.env" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.cluster.env"
fi

DOMAIN="${DOMAIN:-bitecho.org}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-00A760-ADD23B-93C934}"
SSH_USER="${SSH_USER:-cljweb}"
SSH_KEY_DIR="${ROOT_DIR}/.ssh"
SSH_KEY="${SSH_KEY_DIR}/clj_web_ed25519"
SIGNING_KEY="${SSH_KEY_DIR}/bitecho_signing_ed25519"

NODES=("ns1" "ns2" "ns3")

declare -A DEFAULT_PROJECT=(
  [ns1]="bitecho-ns1"
  [ns2]="bitecho-ns2"
  [ns3]="bitecho-ns3"
)

declare -A FALLBACK_PROJECT=(
  [ns1]="alpeware-bitecho-ns1"
  [ns2]="alpeware-bitecho-ns2"
  [ns3]="alpeware-bitecho-ns3"
)

declare -A REGION=(
  [ns1]="us-west1"
  [ns2]="us-central1"
  [ns3]="us-east1"
)

declare -A ZONE=(
  [ns1]="us-west1-b"
  [ns2]="us-central1-a"
  [ns3]="us-east1-b"
)

declare -A INSTANCE=(
  [ns1]="bitecho-ns1"
  [ns2]="bitecho-ns2"
  [ns3]="bitecho-ns3"
)

declare -A ADDRESS_NAME=(
  [ns1]="bitecho-ns1-ip"
  [ns2]="bitecho-ns2-ip"
  [ns3]="bitecho-ns3-ip"
)

# Helpers to resolve dynamic or configured properties
get_project() {
  local node="$1"
  local env_var="PROJECT_${node}"
  if [[ -n "${!env_var:-}" ]]; then
    echo "${!env_var}"
    return
  fi
  local def_proj="${DEFAULT_PROJECT[$node]}"
  if gcloud projects describe "$def_proj" &>/dev/null; then
    echo "$def_proj"
  else
    echo "${FALLBACK_PROJECT[$node]}"
  fi
}

get_ip() {
  local node="$1"
  local env_var="IP_${node}"
  if [[ -n "${!env_var:-}" ]]; then
    echo "${!env_var}"
    return
  fi
  local proj
  proj="$(get_project "$node")"
  local reg="${REGION[$node]}"
  local addr="${ADDRESS_NAME[$node]}"
  gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" --format='value(address)' 2>/dev/null || true
}

ssh_cmd() {
  local node="$1"
  shift
  local ip
  ip="$(get_ip "$node")"
  if [[ -z "$ip" ]]; then
    echo "Error: IP address for node ${node} could not be resolved. Run 'cluster.sh init' first." >&2
    return 1
  fi
  ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}" "$@"
}

ensure_firewall_rule() {
  local project="$1"
  local name="$2"
  local allow="$3"
  local ranges="$4"
  local tags="$5"
  if gcloud compute firewall-rules describe "$name" --project="$project" &>/dev/null; then
    echo "Updating firewall rule ${name} in ${project}..."
    gcloud compute firewall-rules update "$name" \
      --project="$project" \
      --allow="$allow" \
      --source-ranges="$ranges" \
      --target-tags="$tags" \
      --quiet
  else
    echo "Creating firewall rule ${name} in ${project}..."
    gcloud compute firewall-rules create "$name" \
      --project="$project" \
      --allow="$allow" \
      --source-ranges="$ranges" \
      --target-tags="$tags" \
      --quiet
  fi
}

cmd_init() {
  echo "=== Initializing 3-Node Cluster for ${DOMAIN} ==="

  # 1. SSH key generation
  echo "--> Ensuring cluster SSH key at ${SSH_KEY}..."
  mkdir -p "${SSH_KEY_DIR}"
  chmod 700 "${SSH_KEY_DIR}"
  if [[ ! -f "${SSH_KEY}" ]]; then
    ssh-keygen -t ed25519 -N "" -C "${SSH_USER}@${DOMAIN}" -f "${SSH_KEY}"
  fi
  chmod 600 "${SSH_KEY}"
  chmod 644 "${SSH_KEY}.pub"
  local ssh_pub
  ssh_pub="$(cat "${SSH_KEY}.pub")"
  local ssh_meta="${SSH_USER}:${ssh_pub}"

  # 2. Resolve/create projects, link billing, enable compute
  declare -A RESOLVED_PROJECTS=()
  for node in "${NODES[@]}"; do
    local def_proj="${DEFAULT_PROJECT[$node]}"
    local fb_proj="${FALLBACK_PROJECT[$node]}"
    local target_proj="$def_proj"

    echo "--> Resolving GCP project for ${node}..."
    if ! gcloud projects describe "$target_proj" &>/dev/null; then
      echo "Project ${target_proj} does not exist or is not accessible. Attempting to create..."
      if ! gcloud projects create "$target_proj" --name="$target_proj" --quiet &>/dev/null; then
        echo "Could not create ${target_proj}; attempting fallback project ${fb_proj}..."
        target_proj="$fb_proj"
        if ! gcloud projects describe "$target_proj" &>/dev/null; then
          gcloud projects create "$target_proj" --name="$target_proj" --quiet
        fi
      fi
    fi
    RESOLVED_PROJECTS[$node]="$target_proj"
    echo "Using project ${target_proj} for ${node}."

    echo "Linking billing account ${BILLING_ACCOUNT} to ${target_proj}..."
    gcloud billing projects link "$target_proj" --billing-account="${BILLING_ACCOUNT}" --quiet || true

    echo "Enabling compute.googleapis.com on ${target_proj}..."
    gcloud services enable compute.googleapis.com --project="$target_proj" --quiet
  done

  # 3. Reserve regional static external IPv4 addresses
  declare -A RESOLVED_IPS=()
  for node in "${NODES[@]}"; do
    local proj="${RESOLVED_PROJECTS[$node]}"
    local reg="${REGION[$node]}"
    local addr="${ADDRESS_NAME[$node]}"

    echo "--> Checking static external IPv4 ${addr} in ${proj} (${reg})..."
    if ! gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" &>/dev/null; then
      echo "Reserving static external IPv4 ${addr} in ${proj} (${reg})...."
      gcloud compute addresses create "$addr" --project="$proj" --region="$reg" --quiet
    fi
    local ip
    ip="$(gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" --format='value(address)')"
    RESOLVED_IPS[$node]="$ip"
    echo "Static IP for ${node}: ${ip}"
  done

  local ip1="${RESOLVED_IPS[ns1]}"
  local ip2="${RESOLVED_IPS[ns2]}"
  local ip3="${RESOLVED_IPS[ns3]}"
  local cluster_ranges="${ip1}/32,${ip2}/32,${ip3}/32"

  # 4. Create/update firewall rules in each project
  for node in "${NODES[@]}"; do
    local proj="${RESOLVED_PROJECTS[$node]}"
    echo "--> Configuring firewall rules in ${proj}..."
    ensure_firewall_rule "$proj" "clj-web-public" "udp:53,tcp:53,tcp:25,tcp:80,tcp:443" "0.0.0.0/0" "clj-web"
    ensure_firewall_rule "$proj" "clj-web-cluster" "udp:5000-5005" "$cluster_ranges" "clj-web"
    ensure_firewall_rule "$proj" "clj-web-ssh" "tcp:22" "0.0.0.0/0" "clj-web"
  done

  # 5. Create e2-micro VM instances
  for node in "${NODES[@]}"; do
    local proj="${RESOLVED_PROJECTS[$node]}"
    local z="${ZONE[$node]}"
    local inst="${INSTANCE[$node]}"
    local ip="${RESOLVED_IPS[$node]}"

    echo "--> Checking VM instance ${inst} in ${proj} (${z})..."
    if ! gcloud compute instances describe "$inst" --project="$proj" --zone="$z" &>/dev/null; then
      echo "Creating VM instance ${inst}..."
      gcloud compute instances create "$inst" \
        --project="$proj" \
        --zone="$z" \
        --machine-type=e2-micro \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --boot-disk-size=30GB \
        --boot-disk-type=pd-standard \
        --address="$ip" \
        --tags=clj-web \
        --metadata="ssh-keys=${ssh_meta},block-project-ssh-keys=TRUE" \
        --quiet
    else
      echo "VM ${inst} exists; ensuring SSH metadata is configured..."
      gcloud compute instances add-metadata "$inst" \
        --project="$proj" \
        --zone="$z" \
        --metadata="ssh-keys=${ssh_meta},block-project-ssh-keys=TRUE" \
        --quiet
    fi
  done

  # 6. Wait for SSH readiness and run remote bootstrap
  for node in "${NODES[@]}"; do
    local ip="${RESOLVED_IPS[$node]}"
    echo "--> Waiting for SSH readiness on ${node} (${ip})..."
    local retries=30
    while (( retries > 0 )); do
      if ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}" "echo ssh-ok" &>/dev/null; then
        break
      fi
      sleep 5
      (( retries-- ))
    done
    if (( retries == 0 )); then
      echo "Error: SSH connection to ${node} (${ip}) timed out." >&2
      return 1
    fi

    echo "--> Running remote bootstrap script on ${node} (${ip})..."
    ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}" bash -s << 'REMOTE_BOOTSTRAP'
set -euo pipefail

# 1. Swapfile (1GB)
if ! swapon --show | grep -q '/swapfile'; then
  echo "Configuring 1GB /swapfile..."
  sudo fallocate -l 1G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=1024
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  if ! grep -q '/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  fi
fi

# 2. Package dependencies
echo "Installing prerequisites via apt..."
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends curl ca-certificates rsync dnsutils

# 3. OpenJDK 25
if [ ! -x /opt/jdk-25/bin/java ]; then
  echo "Installing OpenJDK 25 into /opt/jdk-25..."
  sudo mkdir -p /opt/jdk-25
  TMP_JDK="$(mktemp /tmp/jdk25-XXXXXX.tar.gz)"
  curl -fsSL -o "$TMP_JDK" "https://api.adoptium.net/v3/binary/latest/25/ga/linux/x64/jdk/hotspot/normal/eclipse"
  sudo tar -xzf "$TMP_JDK" -C /opt/jdk-25 --strip-components=1
  rm -f "$TMP_JDK"
fi

# 4. Free ports 53 (systemd-resolved stub) and 25 (exim4)
echo "Disabling systemd-resolved DNS stub listener on port 53 and stopping exim4 on port 25..."
sudo mkdir -p /etc/systemd/resolved.conf.d
cat << 'RESOLVED_CFG' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf > /dev/null
[Resolve]
DNSStubListener=no
RESOLVED_CFG
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved || true
sudo systemctl stop exim4 2>/dev/null || true
sudo systemctl disable exim4 2>/dev/null || true

# Log rotation (journald)
sudo mkdir -p /etc/systemd/journald.conf.d
cat << 'JOURNALD_CFG' | sudo tee /etc/systemd/journald.conf.d/size-limit.conf > /dev/null
[Journal]
SystemMaxUse=100M
MaxFileSec=7day
JOURNALD_CFG
sudo systemctl restart systemd-journald || true

# 5. App directories
echo "Creating application directories..."
sudo mkdir -p /opt/clj-web /etc/clj-web /var/lib/clj-web /var/www/clj-web/public
sudo chown -R "$(id -un):$(id -gn)" /opt/clj-web /etc/clj-web /var/lib/clj-web /var/www/clj-web/public

# 5. systemd unit file
echo "Writing /etc/systemd/system/clj-web.service..."
cat << 'UNIT' | sudo tee /etc/systemd/system/clj-web.service > /dev/null
[Unit]
Description=clj-web node
After=network.target

[Service]
Type=simple
User=cljweb
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
Restart=always
RestartSec=3
ExecStart=/opt/jdk-25/bin/java \
  -Xms256m -Xmx512m -XX:MaxMetaspaceSize=96m -XX:MaxDirectMemorySize=64m \
  -XX:+UseCompactObjectHeaders -XX:+UseZGC \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/clj-web/clj-web.jar run /etc/clj-web/config.edn

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
REMOTE_BOOTSTRAP
  done

  # 7. Save state to .cluster.env and cluster.edn
  echo "--> Saving cluster state to .cluster.env and cluster.edn..."
  cat > "${ROOT_DIR}/.cluster.env" << ENV_EOF
# Auto-generated by cluster.sh init on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
DOMAIN="${DOMAIN}"
BILLING_ACCOUNT="${BILLING_ACCOUNT}"
SSH_USER="${SSH_USER}"
PROJECT_ns1="${RESOLVED_PROJECTS[ns1]}"
IP_ns1="${ip1}"
PROJECT_ns2="${RESOLVED_PROJECTS[ns2]}"
IP_ns2="${ip2}"
PROJECT_ns3="${RESOLVED_PROJECTS[ns3]}"
IP_ns3="${ip3}"
ENV_EOF

  cat > "${ROOT_DIR}/cluster.edn" << EDN_EOF
;; Auto-generated by cluster.sh init on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
{:domain "${DOMAIN}"
 :nodes {:ns1 {:project "${RESOLVED_PROJECTS[ns1]}" :region "${REGION[ns1]}" :zone "${ZONE[ns1]}" :ip "${ip1}"}
         :ns2 {:project "${RESOLVED_PROJECTS[ns2]}" :region "${REGION[ns2]}" :zone "${ZONE[ns2]}" :ip "${ip2}"}
         :ns3 {:project "${RESOLVED_PROJECTS[ns3]}" :region "${REGION[ns3]}" :zone "${ZONE[ns3]}" :ip "${ip3}"}}}
EDN_EOF

  # Namecheap instructions
  echo ""
  echo "================================================================================"
  echo "Cluster initialization complete! Namecheap Personal DNS Glue Record Setup:"
  echo "--------------------------------------------------------------------------------"
  echo "In Namecheap -> Manage ${DOMAIN} -> Advanced DNS -> Personal DNS Server:"
  echo "  Standard Nameserver: ns1.${DOMAIN}  -> IP: ${ip1}"
  echo "  Standard Nameserver: ns2.${DOMAIN}  -> IP: ${ip2}"
  echo "  Standard Nameserver: ns3.${DOMAIN}  -> IP: ${ip3}"
  echo ""
  echo "Under Domain -> Nameservers -> Custom DNS:"
  echo "  ns1.${DOMAIN}"
  echo "  ns2.${DOMAIN}"
  echo "  ns3.${DOMAIN}"
  echo "================================================================================"
}

publish_git_repos() {
  echo "--> Publishing canonical Git repositories and generating documentation..."
  mkdir -p "${SSH_KEY_DIR}"
  chmod 700 "${SSH_KEY_DIR}"
  if [[ ! -f "${SIGNING_KEY}" ]]; then
    echo "Generating release signing key at ${SIGNING_KEY}..."
    ssh-keygen -t ed25519 -N "" -C "release@${DOMAIN}" -f "${SIGNING_KEY}"
  fi
  chmod 600 "${SIGNING_KEY}"
  chmod 644 "${SIGNING_KEY}.pub"

  mkdir -p "${ROOT_DIR}/public/git"

  # Write public/keys.txt
  local pubkey
  pubkey="$(cat "${SIGNING_KEY}.pub")"
  cat << KEYS_EOF > "${ROOT_DIR}/public/keys.txt"
# Bitecho Release Signing Public Key (SSH Ed25519)
# Identity: release@${DOMAIN}
#
# To verify signed git tags:
#   1. Add this key to your allowed_signers file:
#      curl -sSL https://${DOMAIN}/keys.txt | grep -v '^#' >> ~/.config/git/allowed_signers
#   2. Configure git:
#      git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
#   3. Verify tag:
#      git tag -v verified
#
# Allowed signers entry:
release@${DOMAIN} ${pubkey}
KEYS_EOF

  local repos=("bitecho" "clj-datachannel" "clj-web")
  local -A repo_shas=()
  local -A repo_branches=()

  for repo in "${repos[@]}"; do
    local src_repo="$(cd "${ROOT_DIR}/.." && pwd)/${repo}"
    local bare_repo="${ROOT_DIR}/public/git/${repo}.git"

    if [[ ! -d "${src_repo}/.git" ]]; then
      echo "Error: Source repository not found at ${src_repo}" >&2
      return 1
    fi

    # Unshallow if shallow clone to ensure complete dumb-HTTP bare repo
    if [ "$(git -C "${src_repo}" rev-parse --is-shallow-repository)" = "true" ]; then
      echo "  Unshallowing ${repo}..."
      git -C "${src_repo}" fetch --unshallow
    fi

    local def_branch
    def_branch="$(git -C "${src_repo}" symbolic-ref --short HEAD 2>/dev/null || git -C "${src_repo}" branch --show-current 2>/dev/null || echo "master")"
    if [[ -z "$def_branch" ]]; then def_branch="master"; fi

    # Sign annotated tag 'verified' in source repo before bare clone so both share the identical tag object
    git -C "${src_repo}" \
      -c gpg.format=ssh \
      -c user.signingkey="${SIGNING_KEY}" \
      -c user.name="Bitecho Release" \
      -c user.email="release@${DOMAIN}" \
      tag -s -f verified HEAD -m "Verified snapshot of ${repo} on ${DOMAIN}"

    echo "Exporting bare repository for ${repo} (${def_branch})..."
    rm -rf "${bare_repo}"
    git clone --bare --quiet "${src_repo}" "${bare_repo}"

    # Ensure HEAD points to default branch
    git --git-dir="${bare_repo}" symbolic-ref HEAD "refs/heads/${def_branch}"

    # Pack objects, update dumb HTTP server info, and verify repository integrity
    rm -rf "${bare_repo}/objects/info/commit-graphs" "${bare_repo}/objects/info/commit-graph"
    git --git-dir="${bare_repo}" repack -a -d -q
    git --git-dir="${bare_repo}" update-server-info
    git --git-dir="${bare_repo}" fsck --full > /dev/null
    if [[ -f "${bare_repo}/hooks/post-update.sample" ]]; then
      cp -f "${bare_repo}/hooks/post-update.sample" "${bare_repo}/hooks/post-update"
      chmod +x "${bare_repo}/hooks/post-update"
    fi

    local head_sha
    head_sha="$(git --git-dir="${bare_repo}" rev-parse HEAD)"
    repo_shas["$repo"]="$head_sha"
    repo_branches["$repo"]="$def_branch"
    echo "  ${repo}: ${def_branch} @ ${head_sha}"
  done

  local b_sha="${repo_shas[bitecho]}"
  local b_branch="${repo_branches[bitecho]}"
  local d_sha="${repo_shas[clj-datachannel]}"
  local d_branch="${repo_branches[clj-datachannel]}"
  local w_sha="${repo_shas[clj-web]}"
  local w_branch="${repo_branches[clj-web]}"

  cat << GIT_INDEX_EOF > "${ROOT_DIR}/public/git/index.md"
# Canonical Git Repositories

Self-hosted bare Git repositories for the Bitecho software ecosystem, served directly over HTTPS via dumb HTTP transport (\`git update-server-info\`). Every repository includes an SSH-signed annotated tag \`verified\` cryptographically attesting the snapshot against the public key at [\`/keys.txt\`](/keys.txt).

---

## 1. bitecho

Core decentralized peer-to-peer messaging and coordination protocol in Clojure.

- **Clone URL**: \`https://${DOMAIN}/git/bitecho.git\`
- **Default Branch**: \`${b_branch}\`
- **HEAD / Verified Target**: \`${b_sha}\`
- **GitHub Backup Mirror**: [https://github.com/alpeware/bitecho](https://github.com/alpeware/bitecho)

### Clojure CLI (\`deps.edn\`)

\`\`\`clojure
alpeware/bitecho {:git/url "https://${DOMAIN}/git/bitecho.git"
                 :git/sha "${b_sha}"}
\`\`\`

---

## 2. clj-datachannel

Pure Clojure WebRTC DataChannels library (SCTP over DTLS over UDP) targeting OpenJDK 25.

- **Clone URL**: \`https://${DOMAIN}/git/clj-datachannel.git\`
- **Default Branch**: \`${d_branch}\`
- **HEAD / Verified Target**: \`${d_sha}\`
- **GitHub Backup Mirror**: [https://github.com/alpeware/clj-datachannel](https://github.com/alpeware/clj-datachannel)

### Clojure CLI (\`deps.edn\`)

\`\`\`clojure
alpeware/clj-datachannel {:git/url "https://${DOMAIN}/git/clj-datachannel.git"
                         :git/sha "${d_sha}"}
\`\`\`

---

## 3. clj-web

Self-contained 3-node cluster system combining authoritative DNS (:53), static HTTPS (:443) with Virtual Threads, inbound SMTP (:25) with STARTTLS, ACME v2 Let's Encrypt automation, and WebRTC DataChannel cluster mesh control plane (:5000).

- **Clone URL**: \`https://${DOMAIN}/git/clj-web.git\`
- **Default Branch**: \`${w_branch}\`
- **HEAD / Verified Target**: \`verified\`
- **GitHub Backup Mirror**: [https://github.com/alpeware/clj-web](https://github.com/alpeware/clj-web)

### Clojure CLI (\`deps.edn\`)

\`\`\`clojure
alpeware/clj-web {:git/url "https://${DOMAIN}/git/clj-web.git"
                 :git/tag "verified"}
\`\`\`

---

## Cryptographic Verification

All repositories publish an SSH-signed annotated tag \`verified\` pointing to the release snapshot.

1. **Configure Git Allowed Signers**:
   \`\`\`bash
   curl -sSL https://${DOMAIN}/keys.txt | grep ssh-ed25519 >> ~/.config/git/allowed_signers
   git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
   \`\`\`

2. **Verify Repository Tag**:
   \`\`\`bash
   git clone https://${DOMAIN}/git/bitecho.git
   cd bitecho
   git tag -v verified
   \`\`\`
GIT_INDEX_EOF

  cat << INDEX_EOF > "${ROOT_DIR}/public/index.md"
# Bitecho (bitecho.org)

Welcome to **Bitecho**, a high-performance, decentralized peer-to-peer messaging and coordination protocol built on pure Clojure and WebRTC DataChannels.

## Gentoo / Source-First Philosophy

Bitecho embraces a source-first distribution model inspired by Gentoo Linux:
- **Canonical Git Origin**: Software is published directly from self-hosted canonical bare Git repositories hosted on the Bitecho 3-node cluster.
- **Cryptographic Provenance**: Every repository snapshot is signed with an SSH Ed25519 release key (\`verified\` tag) documented at [\`/keys.txt\`](/keys.txt).
- **Zero Opaque Binaries**: Autonomous agents and developers fetch and build pure Clojure source code directly via Clojure CLI (\`deps.edn\`) with zero intermediate binary registries.

---

## Canonical Git Repositories

| Repository | Default Branch | HEAD / Verified Target | Canonical Clone URL |
| :--- | :--- | :--- | :--- |
| **bitecho** | \`${b_branch}\` | \`${b_sha:0:12}\` | \`https://${DOMAIN}/git/bitecho.git\` |
| **clj-datachannel** | \`${d_branch}\` | \`${d_sha:0:12}\` | \`https://${DOMAIN}/git/clj-datachannel.git\` |
| **clj-web** | \`${w_branch}\` | \`verified\` | \`https://${DOMAIN}/git/clj-web.git\` |

### Clojure CLI (\`deps.edn\`) Dependencies

\`\`\`clojure
;; In your deps.edn
{:deps
 {alpeware/bitecho {:git/url "https://${DOMAIN}/git/bitecho.git"
                   :git/sha "${b_sha}"}
  alpeware/clj-datachannel {:git/url "https://${DOMAIN}/git/clj-datachannel.git"
                           :git/sha "${d_sha}"}
  alpeware/clj-web {:git/url "https://${DOMAIN}/git/clj-web.git"
                   :git/tag "verified"}}}
\`\`\`

---

## Cryptographic Verification

All canonical repositories include an SSH-signed annotated tag \`verified\` pointing to the canonical HEAD.

\`\`\`bash
# 1. Trust the Bitecho release signing key
curl -sSL https://${DOMAIN}/keys.txt | grep ssh-ed25519 >> ~/.config/git/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

# 2. Clone and verify
git clone https://${DOMAIN}/git/bitecho.git
cd bitecho
git tag -v verified
\`\`\`

---

## Cluster Architecture

Bitecho runs across 3 geographically distributed GCP \`e2-micro\` nodes (\`ns1\` in US West, \`ns2\` in US Central, \`ns3\` in US East):
- **Authoritative DNS** (UDP & TCP port 53): Low-TTL multi-A records with automatic node health filtering.
- **Static Content Engine** (TCP port 80 & 443): JVM 25 Virtual Threads with transparent Gzip, LRU caching, and byte-range streaming.
- **Inbound SMTP** (TCP port 25): STARTTLS listener with domain-allowlist filtering and cluster-wide email replication.
- **ACME v2 Automation**: Automated Let's Encrypt certificate issuance with zero-downtime hot-reloading.
- **P2P Mesh Control Plane** (UDP port 5000): Encrypted WebRTC DataChannels (\`clj-datachannel\`) for cluster heartbeats, challenge quorum, and state replication.

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
INDEX_EOF

  cp -f "${ROOT_DIR}/public/index.md" "${ROOT_DIR}/public/llms.txt"
  echo "Documentation generated at public/git/index.md, public/index.md, and public/llms.txt"
}

cmd_publish_git() {
  echo "=== Publishing Canonical Git Repositories and Documentation ==="
  publish_git_repos

  echo ""
  echo "--> Syncing public/ directory to all cluster nodes..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    if [[ -z "$ip" ]]; then
      echo "Warning: IP address for node ${node} could not be resolved. Skipping." >&2
      continue
    fi
    echo "Syncing public/ (excluding live app/) to ${node} (${ip})..."
    rsync -az --delete --exclude 'app/' --exclude 'app' -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/public/" "${SSH_USER}@${ip}:/var/www/clj-web/public/"
  done
  echo ""
  echo "=== Git repositories successfully published and synced! ==="
}

cmd_deploy() {
  local staging=false
  local reset_certs=false
  local include_app=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --staging)
        staging=true
        shift
        ;;
      --reset-certs)
        reset_certs=true
        shift
        ;;
      --include-app)
        include_app=true
        shift
        ;;
      *)
        echo "Unknown deploy option: $1" >&2
        return 1
        ;;
    esac
  done

  echo "=== Deploying clj-web to 3-Node Cluster (${DOMAIN}) ==="

  # 1. Build local uberjar
  echo "--> Step 1/6: Building target/clj-web.jar locally..."
  (cd "${ROOT_DIR}" && clojure -T:build uber)

  # Check that IPs are available
  local ip1 ip2 ip3
  ip1="$(get_ip ns1)"
  ip2="$(get_ip ns2)"
  ip3="$(get_ip ns3)"
  if [[ -z "$ip1" || -z "$ip2" || -z "$ip3" ]]; then
    echo "Error: Node static IPs could not be resolved. Ensure 'cluster.sh init' was run." >&2
    return 1
  fi

  # 2. Upload uberjar to all 3 VMs
  echo "--> Step 2/6: Uploading uberjar to all nodes via rsync..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Uploading to ${node} (${ip})..."
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -i ${SSH_KEY}" \
      "${ROOT_DIR}/target/clj-web.jar" "${SSH_USER}@${ip}:/opt/clj-web/clj-web.jar"
  done

  # 3. Generate/fetch DTLS fingerprints
  echo "--> Step 3/6: Fetching DTLS SHA-256 fingerprints from all nodes..."
  declare -A FINGERPRINTS=()
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Fetching fingerprint on ${node}..."
    local fp
    fp=$(ssh_cmd "$node" bash -s << REMOTE_FP
set -euo pipefail
CONFIG_FILE="/etc/clj-web/config.edn"
if [ ! -f "\$CONFIG_FILE" ]; then
  BOOTSTRAP_CFG="/tmp/bootstrap-config.edn"
  echo "{:node/id :${node} :domain \"${DOMAIN}\" :state-dir \"/var/lib/clj-web\"}" > "\$BOOTSTRAP_CFG"
  CONFIG_FILE="\$BOOTSTRAP_CFG"
fi
/opt/jdk-25/bin/java \
  -Xms128m -Xmx256m \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/clj-web/clj-web.jar print-fingerprint "\$CONFIG_FILE" | grep "SHA-256 Fingerprint:" | awk '{print \$NF}'
rm -f /tmp/bootstrap-config.edn
REMOTE_FP
)
    if [[ -z "$fp" ]]; then
      echo "Error: Failed to obtain DTLS fingerprint for ${node}" >&2
      return 1
    fi
    FINGERPRINTS[$node]="$fp"
    echo "${node} fingerprint: ${fp}"
  done

  # 4. Render and upload per-node config.edn
  echo "--> Step 4/6: Rendering and uploading /etc/clj-web/config.edn..."
  local acme_dir="https://acme-v02.api.letsencrypt.org/directory"
  if [[ "$staging" == true ]]; then
    acme_dir="https://acme-staging-v02.api.letsencrypt.org/directory"
    echo "Using Let's Encrypt Staging directory: ${acme_dir}"
  else
    echo "Using Let's Encrypt Production directory: ${acme_dir}"
  fi

  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    local ingress_target_ip=""
    case "$node" in
      ns1) ingress_target_ip="35.212.129.138" ;;
      ns2) ingress_target_ip="35.206.120.143" ;;
      ns3) ingress_target_ip="35.211.71.139" ;;
    esac
    echo "Rendering config for ${node} (${ip}) [ingress target: ${ingress_target_ip}:5010]..."
    local tmp_cfg
    tmp_cfg="$(mktemp /tmp/config-${node}-XXXXXX.edn)"
    cat > "$tmp_cfg" << CFG_EOF
;; /etc/clj-web/config.edn for ${node}
{:node/id :${node}
 :domain "${DOMAIN}"
 :state-dir "/var/lib/clj-web"
 :acme {:enabled? true
        :directory-url "${acme_dir}"
        :contact-email "mailto:admin@${DOMAIN}"
        :renew-before-days 30
        :domains ["${DOMAIN}"
                  "ns1.${DOMAIN}"
                  "ns2.${DOMAIN}"
                  "ns3.${DOMAIN}"]}
 :dns {:bind-ip "0.0.0.0"
       :port 53
       :ttl-seconds 60
       :ns-ttl-seconds 3600
       :hostmaster "hostmaster.${DOMAIN}"
       :subdomains #{"@" "www" "docs" "mvn" "ingress" "node1.ingress" "node2.ingress" "node3.ingress"}}
 :http {:bind-ip "0.0.0.0"
        :http-port 80
        :https-port 443
        :ingress-target {:host "${ingress_target_ip}" :port 5010}
        :content-root "/var/www/clj-web/public"
        :directory-listing? true}
 :smtp {:enabled? true
        :bind-ip "0.0.0.0"
        :port 25}
 :cluster {:bind-ip "0.0.0.0"
           :port 5000
           :nodes {:ns1 {:ip4 "${ip1}" :ip "${ip1}" :port 5000 :fingerprint "${FINGERPRINTS[ns1]}"}
                   :ns2 {:ip4 "${ip2}" :ip "${ip2}" :port 5000 :fingerprint "${FINGERPRINTS[ns2]}"}
                   :ns3 {:ip4 "${ip3}" :ip "${ip3}" :port 5000 :fingerprint "${FINGERPRINTS[ns3]}"}}}}
CFG_EOF

    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -i ${SSH_KEY}" \
      "$tmp_cfg" "${SSH_USER}@${ip}:/etc/clj-web/config.edn.new"
    rm -f "$tmp_cfg"
    ssh_cmd "$node" bash -s << REMOTE_CFG
set -euo pipefail
if [ "${reset_certs}" = "true" ] || { [ -f /etc/clj-web/config.edn ] && ! grep -Fq "${acme_dir}" /etc/clj-web/config.edn; }; then
  echo "ACME environment changed or --reset-certs requested on ${node}; clearing cached certs and ACME account..."
  rm -rf /var/lib/clj-web/certs/* /var/lib/clj-web/acme/*
fi
mv -f /etc/clj-web/config.edn.new /etc/clj-web/config.edn
REMOTE_CFG
  done

  # Export bare git repos, sign release tags, and generate documentation
  publish_git_repos

  # 5. Sync static public/ directory (excluding live app/ unless --include-app is passed)
  echo "--> Step 5/6: Syncing public/ directory to /var/www/clj-web/public/..."
  local app_exclude_args=(--exclude 'app/' --exclude 'app')
  if [[ "$include_app" == true ]]; then
    app_exclude_args=()
  fi
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Syncing public/ to ${node}..."
    rsync -az --delete "${app_exclude_args[@]}" -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/public/" "${SSH_USER}@${ip}:/var/www/clj-web/public/"
  done

  # 6. Enable and restart clj-web.service, verify /healthz
  echo "--> Step 6/6: Restarting clj-web.service and verifying healthz..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Restarting clj-web on ${node}..."
    ssh_cmd "$node" bash -s << 'REMOTE_START'
set -euo pipefail
sudo mkdir -p /etc/systemd/resolved.conf.d
if [ ! -f /etc/systemd/resolved.conf.d/no-stub.conf ]; then
  printf "[Resolve]\nDNSStubListener=no\n" | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf > /dev/null
  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  sudo systemctl restart systemd-resolved || true
fi
sudo systemctl stop exim4 2>/dev/null || true
sudo systemctl disable exim4 2>/dev/null || true

# Log rotation (journald)
sudo mkdir -p /etc/systemd/journald.conf.d
cat << 'JOURNALD_CFG' | sudo tee /etc/systemd/journald.conf.d/size-limit.conf > /dev/null
[Journal]
SystemMaxUse=100M
MaxFileSec=7day
JOURNALD_CFG
sudo systemctl restart systemd-journald || true
sudo systemctl daemon-reload
sudo systemctl enable clj-web
sudo systemctl restart clj-web
REMOTE_START

    echo "Verifying http://127.0.0.1/healthz on ${node}..."
    local retries=20
    local ok=false
    while (( retries > 0 )); do
      if ssh_cmd "$node" "curl -fsSL http://127.0.0.1/healthz" 2>/dev/null | grep -q "ok"; then
        ok=true
        break
      fi
      sleep 2
      (( retries-- ))
    done

    if [[ "$ok" == true ]]; then
      echo "Node ${node} is healthy (healthz returned ok)."
    else
      echo "Warning: Node ${node} healthz check timed out or did not return ok." >&2
    fi
  done

  echo ""
  echo "=== Deployment finished successfully! ==="
}

cmd_status() {
  local rtype="${1:-A}"
  echo "=== 3-Node Cluster Status (${DOMAIN}) ==="
  printf "%-6s %-16s %-10s %-14s %-16s %-16s %-26s %-8s %s\n" \
    "Node" "IP" "State" "Memory" "Disk" "Egress(Mo/NIC)" "Cluster (Role/Nodes/HB)" "Emails" "DNS (${rtype})"
  printf "%-6s %-16s %-10s %-14s %-16s %-16s %-26s %-8s %s\n" \
    "------" "----------------" "----------" "--------------" "----------------" "----------------" "--------------------------" "--------" "----------"

  for node in "${NODES[@]}"; do
    local ip vm_state state mem_usage disk_usage egress_mo_nic cluster_health email_count dns_check
    ip="$(get_ip "$node")"
    if [[ -z "$ip" ]]; then
      ip="UNRESOLVED"
      state="UNKNOWN"
      mem_usage="N/A"
      disk_usage="N/A"
      egress_mo_nic="N/A"
      cluster_health="N/A"
      email_count="0"
      dns_check="N/A"
    else
      local proj
      proj="$(get_project "$node")"
      vm_state="$(gcloud compute instances describe "${INSTANCE[$node]}" --project="$proj" --zone="${ZONE[$node]}" --format='value(status)' 2>/dev/null || echo "UNKNOWN")"
      if [[ "$vm_state" == "RUNNING" ]]; then
        local raw_metrics
        raw_metrics="$(ssh_cmd "$node" bash -s -- "${DOMAIN}" "${rtype}" << 'REMOTE_STATUS' 2>/dev/null || echo "SSH_FAILED"
set -o pipefail
domain="$1"
rtype="$2"

svc=$(systemctl is-active clj-web 2>/dev/null || echo "inactive")
mem=$(free -m 2>/dev/null | awk '/Mem:/ {print $3 "/" $2 "M"}' || echo "N/A")
disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}' || echo "N/A")
dev=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1)
dev=${dev:-ens4}
nic_raw=$(cat /sys/class/net/"$dev"/statistics/tx_bytes 2>/dev/null || echo 0)
emails=$(find /var/lib/clj-web/mail -type f -name '*.eml' 2>/dev/null | wc -l || echo 0)
statusz=$(curl -fsSL --max-time 2 http://127.0.0.1/statusz 2>/dev/null || true)
dns_local=$(dig @127.0.0.1 "$domain" "$rtype" +short +time=2 +tries=1 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || echo "FAILED")
if [ -z "$dns_local" ]; then dns_local="NO_RECORDS"; fi

echo "${svc}|${mem}|${disk}|${nic_raw}|${emails}|${statusz}|${dns_local}"
REMOTE_STATUS
)"
        if [[ -z "$raw_metrics" || "$raw_metrics" == "SSH_FAILED" ]]; then
          state="UNREACHABLE"
          mem_usage="N/A"
          disk_usage="N/A"
          egress_mo_nic="N/A"
          cluster_health="N/A"
          email_count="0"
          dns_check="N/A"
        else
          local raw_svc raw_mem raw_disk raw_nic raw_emails raw_statusz raw_dns
          IFS='|' read -r raw_svc raw_mem raw_disk raw_nic raw_emails raw_statusz raw_dns <<< "$raw_metrics"
          state="${raw_svc:-inactive}"
          mem_usage="${raw_mem:-N/A}"
          disk_usage="${raw_disk:-N/A}"
          email_count="${raw_emails:-0}"

          # Parse statusz
          local role="" leader="" quorum="" hb_ms="" egress_bytes=""
          for kv in $raw_statusz; do
            case "$kv" in
              role=*) role="${kv#role=}" ;;
              leader=*) leader="${kv#leader=}" ;;
              quorum=*) quorum="${kv#quorum=}" ;;
              hb_ms=*) hb_ms="${kv#hb_ms=}" ;;
              egress_bytes=*) egress_bytes="${kv#egress_bytes=}" ;;
            esac
          done

          # Cluster health
          if [[ -n "$role" ]]; then
            local hb_sec
            hb_sec="$(awk -v ms="${hb_ms:-0}" 'BEGIN {printf "%.1fs", ms/1000}')"
            if [[ "$role" == "leader" ]]; then
              cluster_health="leader ${quorum} (${hb_sec})"
            elif [[ "$role" == "follower" ]]; then
              cluster_health="follower->${leader} ${quorum} (${hb_sec})"
            else
              cluster_health="${role} ${quorum} (${hb_sec})"
            fi
          else
            if [[ "$state" == "active" ]]; then
              cluster_health="standalone"
            else
              cluster_health="down"
            fi
          fi

          # Egress (Mo/NIC)
          egress_mo_nic="$(awk -v mo="${egress_bytes:-0}" -v nic="${raw_nic:-0}" '
function human(b) {
  if (b >= 1073741824) return sprintf("%.1fG", b/1073741824);
  if (b >= 1048576) return sprintf("%.1fM", b/1048576);
  if (b >= 1024) return sprintf("%.1fK", b/1024);
  return sprintf("%dB", b);
}
BEGIN {
  printf "%s/%s", human(mo), human(nic);
}')"

          # DNS check
          if command -v dig >/dev/null 2>&1; then
            dns_check="$(dig @"$ip" "${DOMAIN}" "$rtype" +short +time=2 +tries=1 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || echo "FAILED")"
            if [[ -z "$dns_check" ]]; then dns_check="NO_RECORDS"; fi
          else
            dns_check="${raw_dns:-NO_RECORDS}"
          fi
        fi
      else
        state="${vm_state}"
        mem_usage="N/A"
        disk_usage="N/A"
        egress_mo_nic="N/A"
        cluster_health="N/A"
        email_count="0"
        dns_check="N/A"
      fi
    fi

    printf "%-6s %-16s %-10s %-14s %-16s %-16s %-26s %-8s %s\n" \
      "$node" "$ip" "$state" "$mem_usage" "$disk_usage" "$egress_mo_nic" "$cluster_health" "$email_count" "$dns_check"
  done
}

cmd_logs() {
  local target="${1:-}"
  if [[ -n "$target" ]]; then
    echo "=== Streaming logs for ${target} ==="
    ssh -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -i "${SSH_KEY}" -t "${SSH_USER}@$(get_ip "$target")" "sudo journalctl -u clj-web -f"
  else
    for node in "${NODES[@]}"; do
      echo ""
      echo "=== Last 100 log lines for ${node} ==="
      ssh_cmd "$node" "sudo journalctl -u clj-web -n 100 --no-pager" || true
    done
  fi
}

cmd_mail() {
  local target="${1:-}"
  local nodes_to_check=("${NODES[@]}")
  if [[ -n "$target" ]]; then
    nodes_to_check=("$target")
  fi

  for node in "${nodes_to_check[@]}"; do
    echo ""
    echo "=== Inbound Email Listing for ${node} ==="
    ssh_cmd "$node" \
      "/opt/jdk-25/bin/java -Xms128m -Xmx256m --enable-native-access=ALL-UNNAMED --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED --add-exports=java.base/sun.security.x509=ALL-UNNAMED -jar /opt/clj-web/clj-web.jar list-mail /etc/clj-web/config.edn" || true
  done
}

cmd_read_mail() {
  local id="${1:-latest}"
  local node="${2:-ns1}"
  local raw=false
  if [[ "${3:-}" == "--raw" ]] || [[ "${2:-}" == "--raw" ]]; then
    raw=true
    if [[ "${2:-}" == "--raw" ]]; then
      node="ns1"
    fi
  fi

  echo "=== Reading Email (${id}) on ${node} ==="
  if [[ "$raw" == true ]]; then
    ssh_cmd "$node" bash -s -- "$id" << 'REMOTE_RAW_MAIL'
set -euo pipefail
target="$1"
mail_dir="/var/lib/clj-web/mail"
if [[ "$target" == "latest" ]]; then
  file="$(ls -1t "${mail_dir}"/*.eml 2>/dev/null | head -n 1 || true)"
else
  file="${mail_dir}/${target%.eml}.eml"
fi
if [[ -z "$file" || ! -f "$file" ]]; then
  echo "Email not found: ${target}" >&2
  exit 1
fi
cat "$file"
REMOTE_RAW_MAIL
  else
    ssh_cmd "$node" \
      "/opt/jdk-25/bin/java -Xms128m -Xmx256m --enable-native-access=ALL-UNNAMED --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED --add-exports=java.base/sun.security.x509=ALL-UNNAMED -jar /opt/clj-web/clj-web.jar read-mail /etc/clj-web/config.edn '${id}'"
  fi
}

cmd_delete_mail() {
  local target="${1:-}"
  if [[ -z "$target" ]]; then
    echo "Usage: $0 delete-mail <id|latest|all>" >&2
    return 1
  fi

  local resolved_target="$target"
  if [[ "$target" == "latest" ]]; then
    resolved_target="$(ssh_cmd "ns1" "ls -1 /var/lib/clj-web/mail/*.eml 2>/dev/null | sort | tail -n 1 | xargs -r basename" || true)"
    if [[ -z "$resolved_target" ]]; then
      echo "No emails found on ns1 to delete."
      return 0
    fi
    echo "Resolved 'latest' to ${resolved_target}"
  fi

  for node in "${NODES[@]}"; do
    echo "=== Deleting Email (${resolved_target}) on ${node} ==="
    ssh_cmd "$node" bash -s -- "$resolved_target" << 'REMOTE_DELETE_MAIL'
set -euo pipefail
target="$1"
mail_dir="/var/lib/clj-web/mail"
if [[ ! -d "$mail_dir" ]]; then
  echo "No mail directory on $(hostname)."
  exit 0
fi
if [[ "$target" == "all" ]]; then
  count=$(find "$mail_dir" -maxdepth 1 -type f -name '*.eml' | wc -l)
  rm -f "${mail_dir}"/*.eml
  echo "Deleted all (${count}) email(s) on $(hostname)."
else
  file="${mail_dir}/${target%.eml}.eml"
  if [[ -f "$file" ]]; then
    rm -f "$file"
    echo "Deleted $(basename "$file") on $(hostname)."
  else
    echo "Email ${target} not found on $(hostname)."
  fi
fi
REMOTE_DELETE_MAIL
  done
}

cmd_ssh() {
  local target="${1:-}"
  if [[ -z "$target" ]]; then
    echo "Usage: $0 ssh <ns1|ns2|ns3>" >&2
    return 1
  fi
  local ip
  ip="$(get_ip "$target")"
  if [[ -z "$ip" ]]; then
    echo "Error: IP address for ${target} could not be resolved." >&2
    return 1
  fi
  echo "Connecting to ${target} (${ip})..."
  exec ssh -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}"
}

usage() {
  cat << USAGE
Usage: $0 <command> [options]

Commands:
  init                  Provision GCP projects, static IPs, firewall rules, VMs, and bootstrap OpenJDK 25
  deploy [--staging]    Build uberjar, sync public/ assets, generate DTLS fingerprints, render configs, and restart
  publish-git           Export bare git repos, sign release tags, generate docs, and sync to cluster
  status                Display cluster node states, IPs, memory usage, systemd status, DNS records, and email counts
  logs [ns1|ns2|ns3]    View systemd journal logs (streams if specific node is specified)
  mail [ns1|ns2|ns3]    List saved RFC 822 .eml emails replicated across the cluster
  read-mail [id|latest] [ns1|ns2|ns3] [--raw]  Read an inbound email (defaults to latest on ns1)
  delete-mail <id|latest|all>                 Delete an email (or 'latest' / 'all') across all cluster nodes
  ssh <ns1|ns2|ns3>     Open an interactive SSH session to a cluster node
  help, --help, -h      Display this usage manual

Environment Overrides:
  DOMAIN                Cluster apex domain (default: bitecho.org)
  BILLING_ACCOUNT       GCP billing account ID (default: 00A760-ADD23B-93C934)
  SSH_USER              Remote SSH administrative user (default: cljweb)
  .cluster.env          Optional local file storing discovered project IDs and static IPs
USAGE
}

# Main command dispatch
case "${1:-help}" in
  init)
    cmd_init
    ;;
  deploy)
    shift
    cmd_deploy "$@"
    ;;
  publish-git)
    shift
    cmd_publish_git
    ;;
  status)
    cmd_status
    ;;
  logs)
    shift
    cmd_logs "${1:-}"
    ;;
  mail)
    shift
    cmd_mail "${1:-}"
    ;;
  read-mail|read)
    shift
    cmd_read_mail "$@"
    ;;
  delete-mail|delete)
    shift
    cmd_delete_mail "$@"
    ;;
  ssh)
    shift
    cmd_ssh "${1:-}"
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    echo "Unknown command: $1" >&2
    echo "" >&2
    usage >&2
    exit 1
    ;;
esac
