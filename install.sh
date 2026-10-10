#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/floppy-key"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"

echo "========================================================"
echo " FloppyKey v2 - Installing User Daemon & CLI"
echo "========================================================"

# 1. Ensure required directories
mkdir -p "${BIN_DIR}" "${INSTALL_DIR}" "${SYSTEMD_USER_DIR}"

# 2. Copy application files to ~/.local/share/floppy-key
echo "[*] Installing FloppyKey files to ${INSTALL_DIR}..."
rm -rf "${INSTALL_DIR}/floppy_key"
cp -r "${SCRIPT_DIR}/floppy_key" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/floppy-key" "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/floppy-key"

# 3. Create symlink in ~/.local/bin
echo "[*] Creating executable symlink at ${BIN_DIR}/floppy-key..."
ln -sf "${INSTALL_DIR}/floppy-key" "${BIN_DIR}/floppy-key"

# 4. Install systemd user service
echo "[*] Installing systemd user unit to ${SYSTEMD_USER_DIR}/floppy-key.service..."
cp "${SCRIPT_DIR}/floppy-key.service" "${SYSTEMD_USER_DIR}/"

# 5. Reload and start systemd user service
echo "[*] Reloading and starting systemd user service..."
systemctl --user daemon-reload
systemctl --user enable floppy-key.service
systemctl --user restart floppy-key.service

echo ""
echo "========================================================"
echo " [OK] Installation complete!"
echo "      CLI: ${BIN_DIR}/floppy-key"
echo "      Service: systemctl --user status floppy-key.service"
echo ""
echo " Quick Start:"
echo "   floppy-key status      # Check drive and media status"
echo "   floppy-key pair        # Pair your 3.5\" floppy disk"
echo "========================================================"
