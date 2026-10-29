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
  ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10 -i "${SSH_KEY}" "${SSH_USER}@${ip}" "$@"
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
    ensure_firewall_rule "$proj" "clj-web-cluster" "udp:5000" "$cluster_ranges" "clj-web"
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
      if ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 -i "${SSH_KEY}" "${SSH_USER}@${ip}" "echo ssh-ok" &>/dev/null; then
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
    ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${SSH_KEY}" "${SSH_USER}@${ip}" bash -s << 'REMOTE_BOOTSTRAP'
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

# 4. App directories
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

cmd_deploy() {
  local staging=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --staging)
        staging=true
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
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
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
    echo "Rendering config for ${node} (${ip})..."
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
       :subdomains #{"@" "www" "docs" "mvn"}}
 :http {:bind-ip "0.0.0.0"
        :http-port 80
        :https-port 443
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

    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "$tmp_cfg" "${SSH_USER}@${ip}:/etc/clj-web/config.edn"
    rm -f "$tmp_cfg"
  done

  # 5. Sync static public/ directory
  echo "--> Step 5/6: Syncing public/ directory to /var/www/clj-web/public/..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Syncing public/ to ${node}..."
    rsync -az --delete -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/public/" "${SSH_USER}@${ip}:/var/www/clj-web/public/"
  done

  # 6. Enable and restart clj-web.service, verify /healthz
  echo "--> Step 6/6: Restarting clj-web.service and verifying healthz..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Restarting clj-web on ${node}..."
    ssh_cmd "$node" "sudo systemctl daemon-reload && sudo systemctl enable clj-web && sudo systemctl restart clj-web"

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
  echo "=== 3-Node Cluster Status (${DOMAIN}) ==="
  printf "%-6s %-22s %-16s %-10s %-10s %-14s %-10s %-6s\n" \
    "Node" "Project" "IP" "VM State" "Service" "Memory" "DNS (A)" "Emails"
  printf "%-6s %-22s %-16s %-10s %-10s %-14s %-10s %-6s\n" \
    "------" "----------------------" "----------------" "----------" "----------" "--------------" "----------" "------"

  for node in "${NODES[@]}"; do
    local proj ip vm_state svc_state mem_usage dns_check email_count
    proj="$(get_project "$node")"
    ip="$(get_ip "$node")"
    if [[ -z "$ip" ]]; then
      ip="UNRESOLVED"
      vm_state="UNKNOWN"
      svc_state="UNKNOWN"
      mem_usage="N/A"
      dns_check="N/A"
      email_count="0"
    else
      vm_state="$(gcloud compute instances describe "${INSTANCE[$node]}" --project="$proj" --zone="${ZONE[$node]}" --format='value(status)' 2>/dev/null || echo "UNKNOWN")"
      if [[ "$vm_state" == "RUNNING" ]]; then
        svc_state="$(ssh_cmd "$node" "systemctl is-active clj-web 2>/dev/null || echo inactive" 2>/dev/null || echo "UNREACHABLE")"
        mem_usage="$(ssh_cmd "$node" "free -m | awk '/Mem:/ {print \$3 \"/\" \$2 \"M\"}'" 2>/dev/null || echo "N/A")"
        email_count="$(ssh_cmd "$node" "find /var/lib/clj-web/mail -type f -name '*.eml' 2>/dev/null | wc -l" 2>/dev/null || echo "0")"
        dns_check="$(dig @"$ip" "${DOMAIN}" A +short +time=2 +tries=1 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || echo "FAILED")"
        if [[ -z "$dns_check" ]]; then dns_check="NO_RECORDS"; fi
      else
        svc_state="STOPPED"
        mem_usage="N/A"
        email_count="0"
        dns_check="N/A"
      fi
    fi

    printf "%-6s %-22s %-16s %-10s %-10s %-14s %-10s %-6s\n" \
      "$node" "$proj" "$ip" "$vm_state" "$svc_state" "$mem_usage" "$dns_check" "$email_count"
  done
}

cmd_logs() {
  local target="${1:-}"
  if [[ -n "$target" ]]; then
    echo "=== Streaming logs for ${target} ==="
    ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" -t "${SSH_USER}@$(get_ip "$target")" "sudo journalctl -u clj-web -f"
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
  exec ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" "${SSH_USER}@${ip}"
}

usage() {
  cat << USAGE
Usage: $0 <command> [options]

Commands:
  init                  Provision GCP projects, static IPs, firewall rules, VMs, and bootstrap OpenJDK 25
  deploy [--staging]    Build uberjar, sync public/ assets, generate DTLS fingerprints, render configs, and restart
  status                Display cluster node states, IPs, memory usage, systemd status, DNS records, and email counts
  logs [ns1|ns2|ns3]    View systemd journal logs (streams if specific node is specified)
  mail [ns1|ns2|ns3]    List saved RFC 822 .eml emails replicated across the cluster
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
