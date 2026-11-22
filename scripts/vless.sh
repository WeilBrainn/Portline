#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
trap 'echo "Ошибка в строке ${LINENO}. Проверь журнал выше." >&2' ERR

phase() { printf '::phase|%s|%s\n' "$1" "$2"; }
phase 14 'Проверка среды'
if [[ "$(id -u)" != '0' ]]; then echo 'Требуются root или sudo без пароля.' >&2; exit 1; fi
if ! command -v systemctl >/dev/null; then echo 'Нужна Linux-система с systemd.' >&2;exit 1;fi
if [[ ! -f /etc/os-release ]]; then echo 'Нет /etc/os-release.' >&2;exit 1;fi
source /etc/os-release
case "${ID:-}" in ubuntu|debian|almalinux|rocky|centos|rhel|fedora) ;; *) echo "Дистрибутив ${ID:-?} пока не поддерживается." >&2;exit 1;; esac
case "$(uname -m)" in x86_64|aarch64) ;; *) echo 'Требуется x86_64 или aarch64.' >&2; exit 1;; esac
if [[ ! "$NP_PORT" =~ ^[0-9]{1,5}$ ]] || (( NP_PORT < 1 || NP_PORT > 65535 )); then exit 1;fi

# Do not silently overwrite an active service on the requested port.
if command -v ss >/dev/null 2>&1;then
  if ss -lntH | awk -v p="$NP_PORT" '{n=split($4,a,":"); if (a[n]==p) found=1} END {exit !found}';then
    echo "TCP $NP_PORT уже занят. Выбери другой порт или останови существующую службу вручную." >&2;exit 1
  fi
fi

phase 27 'Установка зависимостей'
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates openssl tar unzip
elif command -v dnf >/dev/null 2>&1;then
  dnf install -y -q curl ca-certificates openssl tar unzip
else
  echo 'Не найден apt-get/dnf.' >&2;exit 1
fi
phase 43 'Проверка Xray-core'
if command -v xray >/dev/null 2>&1 && xray version >/dev/null 2>&1; then
  echo 'Xray уже установлен. Повторная загрузка не требуется.'
else
  phase 43 'Загрузка Xray-core'
  tmp_script="$(mktemp)"
  trap 'rm -f "${tmp_script:-}"' EXIT
  curl -fsSL --retry 3 https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o "$tmp_script"
  bash "$tmp_script" install
fi
command -v xray >/dev/null || { echo 'xray не установлен.' >&2; exit 1; }

# BEGIN X25519 PARSER
# Xray output variants: "Private key"/"Public key" (older),
# "PrivateKey"/"Password", "PrivateKey"/"Password (PublicKey)" (newer).
# Match full labels only, never substitute Hash32 for the public key.
parse_x25519_keys() {
  local raw="$1" line label value
  PRIVATE=''
  PUBLIC=''
  while IFS= read -r line; do
    [[ "$line" == *:* ]] || continue
    label="${line%%:*}"
    value="${line#*:}"
    [[ "$value" =~ ^[[:space:]]*([A-Za-z0-9_-]{43})[[:space:]]*$ ]] || continue
    value="${BASH_REMATCH[1]}"
    label="$(printf '%s' "$label" | tr -d '[:space:]()' | tr '[:upper:]' '[:lower:]')"
    case "$label" in
      privatekey) PRIVATE="$value" ;;
      publickey|password|passwordpublickey) PUBLIC="$value" ;;
    esac
  done <<< "$raw"
  [[ -n "$PRIVATE" && -n "$PUBLIC" ]]
}
# END X25519 PARSER

phase 65 'Создание конфигурации REALITY'
CLIENT_ID="$(xray uuid | head -n 1 | tr -d '\r')"
[[ "$CLIENT_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo 'Не удалось получить UUID.' >&2;exit 1; }
if ! KEYS="$(xray x25519)"; then
  echo 'Команда xray x25519 завершилась с ошибкой. Проверь установленный Xray.' >&2
  exit 1
fi
if ! parse_x25519_keys "$KEYS"; then
  echo 'Не удалось извлечь ключи X25519 из вывода Xray. Поддерживаются Private key/Public key, PrivateKey/Password и PrivateKey/Password (PublicKey). Значения ключей не записываются в журнал.' >&2
  exit 1
fi
unset KEYS
SHORT="$(openssl rand -hex 8)"
TARGET="${NP_SNI}:443"
conf=/usr/local/etc/xray/config.json
mkdir -p "$(dirname "$conf")"
if [[ -f "$conf" ]]; then cp -p "$conf" "${conf}.portline-backup-$(date +%Y%m%d%H%M%S)";fi
cat > "$conf" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag":"portline-vless",
    "listen":"0.0.0.0",
    "port":${NP_PORT},
    "protocol":"vless",
    "settings":{"clients":[{"id":"${CLIENT_ID}","flow":"xtls-rprx-vision"}],"decryption":"none"},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
      "show":false,"dest":"${TARGET}","xver":0,
      "serverNames":["${NP_SNI}"],"privateKey":"${PRIVATE}","shortIds":["${SHORT}"]
    }}
  }],
  "outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}]
}
JSON
chmod 640 "$conf"
chown root:xray "$conf"
xray run -test -config "$conf"
phase 82 'Настройка запуска и сетевого экрана'
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port="${NP_PORT}/tcp" >/dev/null; firewall-cmd --reload >/dev/null
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow "${NP_PORT}/tcp" >/dev/null
fi
systemctl enable xray >/dev/null
systemctl restart xray
sleep 2
if ! systemctl is-active --quiet xray; then journalctl -u xray --no-pager -n 20 >&2 || true;exit 1;fi
phase 96 'Проверка готовности'
if command -v ss >/dev/null 2>&1;then
  ss -lntH | awk -v p="$NP_PORT" '{n=split($4,a,":");if(a[n]==p)found=1}END{exit !found}' || { echo 'Xray не слушает нужный порт.' >&2;exit 1;}
fi
printf 'PORTLINE_LINK=vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&flow=xtls-rprx-vision#Portline-REALITY\n' \
  "$CLIENT_ID" "$NP_ADDR" "$NP_PORT" "$NP_SNI" "$PUBLIC" "$SHORT"
echo 'Xray активен. Для доступа извне проверь также сетевой экран панели VPS.'
