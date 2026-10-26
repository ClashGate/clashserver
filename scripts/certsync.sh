#!/usr/bin/env bash
# Copy the Caddy-managed certificate for $DOMAIN into /etc/mihomo/certs (readable by user mihomo).
# Exit 0 = cert present (copied or unchanged), 1 = not issued yet.
# --restart: restart mihomo when the certificate changed.
set -euo pipefail

ENV_FILE=/etc/clashserver/clashserver.env
CADDY_CERTS=/var/lib/caddy/.local/share/caddy/certificates
DEST=/etc/mihomo/certs
RESTART=0
[[ "${1:-}" == --restart ]] && RESTART=1

[[ -r $ENV_FILE ]] || { echo "certsync: $ENV_FILE missing" >&2; exit 1; }
# shellcheck disable=SC1090
. "$ENV_FILE"
[[ -n "${DOMAIN:-}" ]] || { echo "certsync: DOMAIN not set" >&2; exit 1; }

# Any issuer dir (acme-v02 / acme-staging-v02 / local); pick the newest.
crt=$(find "$CADDY_CERTS" -type f -path "*/$DOMAIN/$DOMAIN.crt" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-)
[[ -n "$crt" ]] || { echo "certsync: no certificate for $DOMAIN yet" >&2; exit 1; }
key="${crt%.crt}.key"
[[ -f "$key" ]] || { echo "certsync: key missing for $crt" >&2; exit 1; }

install -d -m 750 -o root -g mihomo "$DEST"
if cmp -s "$crt" "$DEST/fullchain.pem" && cmp -s "$key" "$DEST/privkey.pem"; then
  exit 0
fi
install -m 640 -o root -g mihomo "$crt" "$DEST/fullchain.pem.new"
install -m 640 -o root -g mihomo "$key" "$DEST/privkey.pem.new"
mv -f "$DEST/fullchain.pem.new" "$DEST/fullchain.pem"
mv -f "$DEST/privkey.pem.new" "$DEST/privkey.pem"
echo "certsync: updated from $crt"
if ((RESTART)) && systemctl is-active --quiet mihomo; then
  systemctl restart mihomo
fi
