#!/usr/bin/env bash
set -e

if [[ $(id -u) -ne 0 ]]; then
  echo "Run this script as root"
  exit 1
fi

echo "Applying SSH hardening settings..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UseDNS no
AllowTcpForwarding yes
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

systemctl reload sshd

echo "SSH hardening applied."
