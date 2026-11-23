#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then echo 'Требуются права root или sudo без пароля.' >&2; exit 1; fi
command -v systemctl >/dev/null || { echo 'systemctl не найден; нужен VPS с systemd.' >&2; exit 1; }
[[ "${NP_GW_ACTION:-}" == inspect || "${NP_GW_ACTION:-}" == use || "${NP_GW_ACTION:-}" == update ]] || exit 2
config=/etc/portline/gateway.json
binary=/usr/local/bin/portline-gateway
unit=portline-gateway.service
if [[ ! -f "$config" ]]; then
  if [[ "$NP_GW_ACTION" == inspect ]]; then
    echo 'PORTLINE_GATEWAY|missing|-|-|-|-|-'
    exit 0
  fi
  echo 'Portline Gateway не установлен. Используй установку нового сервера.' >&2; exit 1
fi
# These fields are non-secret scalar metadata in Go's indented JSON config.
field() { sed -nE "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*(\"?[^\",}]+\"?).*/\1/p" "$config" | head -n 1 | tr -d '" '; }
port="$(field port)"; schema="$(field version)"; host="$(field host)"
[[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo 'Невозможно прочитать порт из конфигурации Gateway.' >&2; exit 1; }
[[ "$schema" =~ ^[0-9]+$ ]] || { echo 'Неизвестная версия конфигурации Gateway.' >&2; exit 1; }
[[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { echo 'Невозможно прочитать адрес Gateway.' >&2; exit 1; }
activity=inactive
if systemctl is-active --quiet "$unit"; then activity=active; fi
version=legacy
if [[ -x "$binary" ]]; then
  candidate="$("$binary" -mode version 2>/dev/null | head -n 1 || true)"
  if [[ "$candidate" =~ ^PORTLINE_VERSION=([A-Za-z0-9.+_-]+)$ ]]; then version="${BASH_REMATCH[1]}"; fi
fi
if [[ "$NP_GW_ACTION" == inspect ]]; then
  printf 'PORTLINE_GATEWAY|installed|%s|%s|%s|%s|%s\n' "$activity" "$port" "$version" "$schema" "$host"
  exit 0
fi
[[ "$schema" == 1 ]] || { echo "Неподдерживаемая конфигурация версии $schema. Нельзя импортировать/обновить автоматически." >&2; exit 1; }
[[ "$port" == "${NP_PORT:-}" && "$host" == "${NP_ADDR:-}" ]] || { echo "gateway already configured on $host:$port; selected ${NP_ADDR:-}:${NP_PORT:-}" >&2; exit 1; }
if [[ "$NP_GW_ACTION" == use ]]; then
  [[ -x "$binary" ]] || { echo 'Не найден бинарник portline-gateway.' >&2; exit 1; }
  [[ "$activity" == active ]] || { echo 'Служба Gateway не активна. Проверь systemctl status portline-gateway.service.' >&2; exit 1; }
  before_sha="$(sha256sum "$config" | awk '{print $1}')"
  if [[ "$version" == 1.4.9 || "$version" == 1.4.0 || "$version" == 1.2.0 ]]; then
    "$binary" -mode export -config "$config"
  else
    # Older Gateway implements init, which is idempotent for an existing
    # matching config. No configuration or identity is recreated.
    "$binary" -mode init -config "$config" -host "$host" -port "$port"
  fi
  after_sha="$(sha256sum "$config" | awk '{print $1}')"
  if [[ "$before_sha" != "$after_sha" ]]; then
    systemctl restart "$unit"
    systemctl is-active --quiet "$unit"
  fi
  exit 0
fi
# update: explicit client confirmation required, no implicit update on inspect.
[[ "$NP_GW_ACTION" == update ]] || exit 2
backupdir=/etc/portline/backups
mkdir -p "$backupdir"; chmod 700 "$backupdir"
backup="$backupdir/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 700 "$backup"
cp -p -- "$config" "$backup/gateway.json"
[[ ! -e "$binary" ]] || cp -p -- "$binary" "$backup/portline-gateway"
[[ ! -e "/etc/systemd/system/$unit" ]] || cp -p -- "/etc/systemd/system/$unit" "$backup/$unit"
# Decode and validate to a separate file. Never modify the running binary until checked.
tmp="$binary.new.$$"
rollback() {
  rm -f -- "$tmp"
  if [[ -f "$backup/portline-gateway" ]]; then
    cp -p -- "$backup/portline-gateway" "$binary"
    systemctl restart "$unit" >/dev/null 2>&1 || true
  fi
  echo "Ошибка обновления: прежний бинарник восстановлен. Резервная копия: $backup" >&2
}
trap rollback ERR
base64 -d > "$tmp" <<'PORTLINE_GATEWAY_UPDATE_BODY'
__BINARY_BODY__
PORTLINE_GATEWAY_UPDATE_BODY
printf '%s  %s\n' "$NP_BIN_SHA" "$tmp" | sha256sum -c - >/dev/null
chmod 755 "$tmp"
[[ "$("$tmp" -mode version)" == 'PORTLINE_VERSION=1.4.9' ]] || { echo 'Неверная версия обновления Gateway.' >&2; exit 1; }
"$tmp" -mode check -config "$config"
mv -f -- "$tmp" "$binary"
"$binary" -mode init -config "$config" -host "$host" -port "$port"
systemctl restart "$unit"
systemctl is-active --quiet "$unit"
trap - ERR
printf 'Gateway обновлён до 1.4.9. Резервная копия: %s\n' "$backup"
printf 'PORTLINE_GATEWAY|installed|active|%s|1.4.9|%s|%s\n' "$port" "$schema" "$host"
