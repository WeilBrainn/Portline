#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) -ne 0 ]]; then echo 'Требуются права root на VPS.'; exit 1; fi
# Never overwrite an existing gateway during a fresh-install request.
# Inspection/reuse/update are separate, user-confirmed operations.
if [[ -e /etc/portline/gateway.json || -e /etc/systemd/system/portline-gateway.service ]]; then
  echo 'Gateway already installed. В Portline выбери «Проверить Gateway», затем «Использовать существующий сервер» или обновление с резервной копией.' >&2
  exit 78
fi
printf '::phase|18|Проверяем систему VPS\n'
if ! command -v ip >/dev/null || ! command -v iptables >/dev/null; then
  if command -v dnf >/dev/null; then
    dnf -q -y install iproute iptables >/dev/null
  elif command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update >/dev/null
    apt-get -qq -y install iproute2 iptables >/dev/null
  else
    echo 'Системе необходимы iproute2 и iptables. Установи их через пакетный менеджер.'; exit 1
  fi
fi
[[ -c /dev/net/tun ]] || { echo 'Сервер не предоставляет /dev/net/tun. Проверь поддержку TUN у хостинга.'; exit 1; }
mkdir -p /etc/portline
chmod 700 /etc/portline
printf '::phase|34|Копируем серверный компонент Portline\n'
# The binary comes from the locally compiled Portline application, not from a
# mutable third-party URL. Its digest is checked after SSH transfer.
base64 -d > /usr/local/bin/portline-gateway.tmp <<'PORTLINE_GATEWAY_BINARY'
__BINARY_BODY__
PORTLINE_GATEWAY_BINARY
printf '%s  %s\n' "$NP_BIN_SHA" '/usr/local/bin/portline-gateway.tmp' | sha256sum -c - >/dev/null
chmod 755 /usr/local/bin/portline-gateway.tmp
mv -f /usr/local/bin/portline-gateway.tmp /usr/local/bin/portline-gateway
printf '::phase|55|Создаём ключи и конфигурацию TLS\n'
profile=$(/usr/local/bin/portline-gateway -mode init -config /etc/portline/gateway.json -host "$NP_ADDR" -port "$NP_PORT")
cat > /etc/systemd/system/portline-gateway.service <<'UNIT'
[Unit]
Description=Portline Tunnel Gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/portline-gateway -mode serve -config /etc/portline/gateway.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/portline
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
UNIT
printf '::phase|72|Открываем порт и запускаем службу\n'
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --add-port="${NP_PORT}/tcp" --permanent >/dev/null
  firewall-cmd --reload >/dev/null
elif command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  ufw allow "${NP_PORT}/tcp" >/dev/null
fi
systemctl daemon-reload
systemctl enable --now portline-gateway.service >/dev/null
systemctl restart portline-gateway.service
sleep 1
if ! systemctl is-active --quiet portline-gateway.service; then
  journalctl -u portline-gateway.service -n 15 --no-pager || true
  echo 'Служба Portline не запустилась. Проверь порт и поддержку TUN.'
  exit 1
fi
printf '::phase|93|Проверяем доступность службы\n'
printf '%s\n' "$profile"
printf 'Portline Tunnel готов. Для подключения используется встроенный клиент.\n'
