#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.local/share/floppy-key"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
CONFIG_DIR="${HOME}/.config/floppy-key"

echo "========================================================"
echo " 🗑️ FloppyKey v2 - Clean Uninstaller"
echo "========================================================"

# 1. Stop and disable systemd service
if systemctl --user is-active --quiet floppy-key.service 2>/dev/null; then
    echo "[*] Stopping floppy-key.service..."
    systemctl --user stop floppy-key.service || true
fi

if systemctl --user is-enabled --quiet floppy-key.service 2>/dev/null; then
    echo "[*] Disabling floppy-key.service..."
    systemctl --user disable floppy-key.service || true
fi

# 2. Remove systemd service unit
if [ -f "${SYSTEMD_USER_DIR}/floppy-key.service" ]; then
    echo "[*] Removing service unit..."
    rm -f "${SYSTEMD_USER_DIR}/floppy-key.service"
    systemctl --user daemon-reload
fi

# 3. Remove binary and files
echo "[*] Removing binaries and application files..."
rm -f "${BIN_DIR}/floppy-key"
rm -rf "${INSTALL_DIR}"

# 4. Remove host configuration
if [ -d "${CONFIG_DIR}" ]; then
    echo "[*] Removing host configuration (~/.config/floppy-key)..."
    rm -rf "${CONFIG_DIR}"
fi

echo ""
echo "========================================================"
echo " [✓] FloppyKey v2 has been completely uninstalled."
echo "========================================================"
