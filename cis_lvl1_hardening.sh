#!/usr/bin/env bash

# ==============================================================================
# CIS Level 1 Hardening, nftables Firewall, Auditd Command Logging & Log Group
# Target OS: Ubuntu (24.04 / 26.04 LTS)
# ==============================================================================

set -euo pipefail

# --- Configuration Variables ---
LOG_GROUP="log_auditors"

# Mandatory CIS Level 1 Security Packages (with nftables & auditd)
INSTALL_PACKAGES=(
    "aide"
    "aide-common"
    "apparmor"
    "apparmor-utils"
    "nftables"
    "libpam-pwquality"
    "chrony"
    "rsyslog"
    "systemd-journal-remote"
    "auditd"
    "audispd-plugins"
    "sudo"
    "acl" # Required for granular read-only ACLs on logs without breaking ownership
)

# Prohibited Insecure Services, Conflicting Firewalls, and Unnecessary Daemons
# Note: Remove server daemons from this list if this machine actively hosts them
REMOVE_PACKAGES=(
    "ufw"
    "iptables-persistent"
    "nis"
    "rsh-server"
    "rsh-client"
    "talk"
    "telnetd"
    "telnet"
    "tftp-server"
    "xinetd"
    "ldap-utils"
    "ftp"
    "avahi-daemon"
    "cups"
    "isc-dhcp-server"
    "slapd"
    "nfs-kernel-server"
    "bind9"
    "vsftpd"
    "apache2"
    "nginx"
    "dovecot-imapd"
    "samba"
    "squid"
    "snmpd"
)

# --- Helper Functions ---
log_info()  { echo -e "\e[32m[INFO]\e[0m  $1"; }
log_warn()  { echo -e "\e[33m[WARN]\e[0m  $1"; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1" >&2; }

# Ensure script runs as root
if [[ "$EUID" -ne 0 ]]; then
    log_error "This script must be run with root privileges (use sudo)."
    exit 1
fi

# ==============================================================================
# Step 1: Install Mandatory CIS Level 1 & Auditing Packages
# ==============================================================================
log_info "Updating APT package cache..."
apt-get update -qq

log_info "Installing mandatory CIS Level 1 packages, nftables, and auditd..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${INSTALL_PACKAGES[@]}"

# ==============================================================================
# Step 2: Purge Prohibited & Conflicting Packages (Including UFW)
# ==============================================================================
log_info "Checking for prohibited or conflicting CIS packages..."
PACKAGES_TO_PURGE=()

for pkg in "${REMOVE_PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        PACKAGES_TO_PURGE+=("$pkg")
    fi
done

if [[ ${#PACKAGES_TO_PURGE[@]} -gt 0 ]]; then
    log_warn "Purging packages: ${PACKAGES_TO_PURGE[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "${PACKAGES_TO_PURGE[@]}"
    apt-get autoremove -y -qq
else
    log_info "No prohibited or conflicting packages found installed."
fi

# ==============================================================================
# Step 3: Configure CIS-Compliant nftables Baseline
# ==============================================================================
log_info "Configuring CIS-compliant nftables ruleset (/etc/nftables.conf)..."

if [[ -f /etc/nftables.conf ]]; then
    cp /etc/nftables.conf "/etc/nftables.conf.bak.$(date +%s)"
fi

cat <<'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f

# Flush existing ruleset cleanly
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Accept loopback traffic and drop spoofed loopback packets (CIS Requirement)
        iif "lo" accept
        iif != "lo" ip saddr 127.0.0.0/8 counter drop
        iif != "lo" ip6 saddr ::1 counter drop

        # 2. Stateful connection tracking: allow established/related traffic
        ct state established,related accept
        ct state invalid counter drop

        # 3. Allow essential ICMP/ICMPv6 (ping, path MTU discovery, neighbor discovery)
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
        ip6 nexthdr ipv6-icmp accept

        # Uncomment the line below ONLY if you require remote SSH access:
        # tcp dport 22 ct state new accept

        # Log and drop all other inbound traffic
        log prefix "nftables-input-drop: " flags all counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

chmod 0640 /etc/nftables.conf
systemctl enable --now nftables
nft -f /etc/nftables.conf
log_info "nftables service enabled and baseline ruleset loaded."

# ==============================================================================
# Step 4: Create Security Group & Grant Read-Only Access to All System Logs
# ==============================================================================
log_info "Configuring non-root log access group: '$LOG_GROUP'..."

if ! getent group "$LOG_GROUP" >/dev/null; then
    groupadd "$LOG_GROUP"
    log_info "Created group '$LOG_GROUP'."
else
    log_info "Group '$LOG_GROUP' already exists."
fi

# 1. Grant read access to systemd journal logs (journalctl)
for journal_dir in /var/log/journal /run/log/journal; do
    if [[ -d "$journal_dir" ]]; then
        setfacl -R -m "g:${LOG_GROUP}:rx" "$journal_dir"
        setfacl -dR -m "g:${LOG_GROUP}:rx" "$journal_dir"
    fi
done

# 2. Grant recursive read + traverse (rX) ACLs to /var/log
log_info "Applying read-only ACLs to /var/log..."
setfacl -R -m "g:${LOG_GROUP}:rX" /var/log
setfacl -dR -m "g:${LOG_GROUP}:rX" /var/log

# 3. Ensure rsyslog creates new files compatible with default directory ACLs
cat <<EOF > /etc/rsyslog.d/99-cis-log-permissions.conf
# Allow $LOG_GROUP to read newly created rsyslog files via default directory ACLs
\$FileCreateMode 0640
\$DirCreateMode 0750
\$Umask 0022
EOF

systemctl restart rsyslog 2>/dev/null || true

# ==============================================================================
# Step 5: Configure auditd Access Rights & Log All User Commands (execve)
# ==============================================================================
log_info "Configuring auditd log group permissions and full command logging..."

# 1. Configure log_group inside /etc/audit/auditd.conf so auditd preserves group access
if grep -q "^log_group\s*=" /etc/audit/auditd.conf; then
    sed -i "s/^log_group\s*=.*/log_group = ${LOG_GROUP}/" /etc/audit/auditd.conf
else
    echo "log_group = ${LOG_GROUP}" >> /etc/audit/auditd.conf
fi

# 2. Set directory permissions and ACLs on /var/log/audit
mkdir -p /var/log/audit
chmod 0750 /var/log/audit
chown root:"$LOG_GROUP" /var/log/audit
setfacl -R -m "g:${LOG_GROUP}:rX" /var/log/audit
setfacl -dR -m "g:${LOG_GROUP}:rX" /var/log/audit

# 3. Add execve syscall audit rules to log all executed commands for all users
cat <<'EOF' > /etc/audit/rules.d/99-command-logging.rules
# Log all executed commands (execve) across 64-bit and 32-bit architectures
-a always,exit -F arch=b64 -S execve -k user_commands
-a always,exit -F arch=b32 -S execve -k user_commands
EOF

chmod 0640 /etc/audit/rules.d/99-command-logging.rules

# 4. Enable auditd, compile rules, and restart service cleanly
systemctl enable auditd
augenrules --load || log_warn "Audit rules queued (reboot required if immutable mode -e 2 is active)."
service auditd restart 2>/dev/null || systemctl restart auditd

# ==============================================================================
# Completion Summary
# ==============================================================================
echo "----------------------------------------------------------------------"
log_info "CIS Level 1 Hardening, nftables, and Auditd Setup Complete!"
echo ""
echo "1. Grant a non-root user read access to all system & auditd logs:"
echo "   sudo usermod -aG ${LOG_GROUP} <username>"
echo ""
echo "2. Query logged user commands as a non-root auditor (after re-login):"
echo "   ausearch -if /var/log/audit/audit.log -k user_commands -i | tail -n 20"
echo ""
echo "3. Verify active nftables ruleset:"
echo "   sudo nft list ruleset"
echo "----------------------------------------------------------------------"
