#!/usr/bin/env bash
set -e

if [[ $(id -u) -ne 0 ]]; then
  echo "Run this script as root"
  exit 1
fi

apt-get update
apt-get install -y ufw fail2ban

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw --force enable

cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF

systemctl restart fail2ban

echo "Firewall and fail2ban configured."
