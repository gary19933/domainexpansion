#!/usr/bin/env bash
# setup_checker_node.sh — Provision a VPS as a domain ban checker node.
#
# Usage:
#   scp deploy/setup_checker_node.sh root@<vps-ip>:/tmp/
#   ssh root@<vps-ip> "bash /tmp/setup_checker_node.sh <country>"
#
# After running, copy the node config and scripts:
#   scp scripts/checker_node.py scripts/classify.py checker@<vps-ip>:/home/checker/
#   scp deploy/node_configs/<country>.json checker@<vps-ip>:/home/checker/config.json
#
# Then add the central VPS SSH public key:
#   ssh-copy-id -i ~/.ssh/checker_key.pub checker@<vps-ip>
#
set -euo pipefail

COUNTRY="${1:-}"
CHECKER_USER="checker"
CHECKER_HOME="/home/${CHECKER_USER}"

if [[ -z "$COUNTRY" ]]; then
  echo "Usage: $0 <country-code>"
  echo "  e.g. $0 th"
  exit 1
fi

echo "=== Setting up checker node for country=$COUNTRY ==="

# 1. Create checker user (no password, SSH key only)
if ! id "$CHECKER_USER" &>/dev/null; then
  useradd -m -s /bin/bash "$CHECKER_USER"
  echo "Created user: $CHECKER_USER"
else
  echo "User $CHECKER_USER already exists"
fi

# 2. Create directories
mkdir -p "${CHECKER_HOME}/results"
mkdir -p "${CHECKER_HOME}/lists"
chown -R "${CHECKER_USER}:${CHECKER_USER}" "${CHECKER_HOME}"

# 3. Setup SSH authorized_keys directory
mkdir -p "${CHECKER_HOME}/.ssh"
chmod 700 "${CHECKER_HOME}/.ssh"
touch "${CHECKER_HOME}/.ssh/authorized_keys"
chmod 600 "${CHECKER_HOME}/.ssh/authorized_keys"
chown -R "${CHECKER_USER}:${CHECKER_USER}" "${CHECKER_HOME}/.ssh"

# 4. Verify Python 3.10+
if command -v python3 &>/dev/null; then
  py_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  echo "Python version: $py_version"
  major=$(echo "$py_version" | cut -d. -f1)
  minor=$(echo "$py_version" | cut -d. -f2)
  if (( major < 3 || (major == 3 && minor < 10) )); then
    echo "WARNING: Python 3.10+ required, found $py_version"
    echo "Install with: apt install python3.10 (or similar)"
  fi
else
  echo "ERROR: python3 not found. Install with: apt install python3"
  exit 1
fi

# 5. Configure firewall (allow SSH only)
if command -v ufw &>/dev/null; then
  ufw allow ssh
  ufw --force enable
  echo "UFW configured: SSH only"
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --add-service=ssh
  firewall-cmd --reload
  echo "firewalld configured: SSH only"
else
  echo "NOTE: No firewall manager found. Manually ensure only SSH (port 22) is open."
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Copy scripts to the node:"
echo "     scp scripts/checker_node.py scripts/classify.py checker@<this-ip>:/home/checker/"
echo "  2. Copy the config:"
echo "     scp deploy/node_configs/${COUNTRY}.json checker@<this-ip>:/home/checker/config.json"
echo "  3. Add central VPS SSH key:"
echo "     ssh-copy-id -i ~/.ssh/checker_key.pub checker@<this-ip>"
echo "  4. Add SSH host alias to central VPS ~/.ssh/config:"
echo "     Host ${COUNTRY}-node"
echo "       HostName <this-ip>"
echo "       User checker"
echo "       IdentityFile ~/.ssh/checker_key"
echo "  5. Test:"
echo "     ssh checker@${COUNTRY}-node 'python3 /home/checker/checker_node.py --config /home/checker/config.json --list /home/checker/lists/${COUNTRY}.txt'"
