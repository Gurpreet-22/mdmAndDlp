#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# 1. Detect LAN IP
LAN_IP="${1:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
if [[ -z "${LAN_IP}" ]]; then
    echo "Could not auto-detect LAN IP. Usage: $0 <YOUR_IP>"
    exit 1
fi
echo "[+] Detected Server LAN IP: ${LAN_IP}"

# 2. Generate TLS cert with this IP in SAN
echo "[+] Updating TLS certificates for IP: ${LAN_IP}..."
sudo python3 deploy/nginx/make_dev_tls.py --ip "${LAN_IP}"

# 3. Update Nginx single-host conf to listen on all interfaces
echo "[+] Installing updated Nginx config..."
sudo install -m 0644 deploy/nginx/ubuntuguard-single-host.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx

# 4. Rebuild installer for this IP
echo "[+] Rebuilding installer with SERVER_URL=https://${LAN_IP}:9443..."
python3 agent/packaging/build_installer.py \
  --server-url "https://${LAN_IP}:9443" \
  --server-ca /etc/ubuntuguard/dev-tls/server-ca.crt \
  --output-dir server/var/installer

echo ""
echo "============================================================"
echo "[✓] ALL DONE! Ready for other laptops."
echo "Installer is ready at: server/var/installer/ubuntuguard-agent-installer.sh"
echo "On ANY other laptop, simply:"
echo "  1. Run: sudo bash ubuntuguard-agent-installer.sh"
echo "  2. Enter token from dashboard."
echo "  3. Done!"
echo "============================================================"

