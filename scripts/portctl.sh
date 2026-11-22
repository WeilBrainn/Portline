#!/usr/bin/env bash
set -Eeuo pipefail
# Script is streamed over an authenticated SSH session by Portline.
# Only controls a known, explicitly confirmed systemd unit; never kills PIDs.
if (( EUID != 0 )); then echo 'Требуются права root или sudo без пароля.' >&2; exit 1; fi
if ! command -v ss >/dev/null 2>&1; then echo 'На VPS нет ss (пакет iproute2/iproute). Проверка портов недоступна.' >&2; exit 1; fi
if ! command -v systemctl >/dev/null 2>&1; then echo 'Сервер не использует systemd.' >&2; exit 1; fi
[[ "${NP_PORT:-}" =~ ^[0-9]{1,5}$ ]] && (( 10#${NP_PORT} > 0 && 10#${NP_PORT} <= 65535 )) || { echo 'Недопустимый номер порта.' >&2; exit 1; }
[[ "${NP_CTL_PROTO:-}" == tcp || "${NP_CTL_PROTO:-}" == udp ]] || exit 1
[[ "${NP_CTL_ACTION:-}" == check || "${NP_CTL_ACTION:-}" == stop ]] || exit 1

# Fail closed if the requested port equals the active SSH port. This is not
# a substitute for recognizing a different SSH instance on the same host.
if [[ "${NP_PORT}" == "${NP_SSH_PORT:-22}" ]]; then
  echo 'Отказ: выбран действующий SSH-порт. Изменить его из Portline нельзя.' >&2
  exit 1
fi

# On standard `ss -H` output: Netid/State Recv-Q Send-Q Local:Port Peer:Port Process
# With TCP -lntp the local column is $4, not $5. Use field detection instead:
sockets_for() {
  local proto="$1" port="$2" data
  if [[ "$proto" == tcp ]]; then data="$(ss -H -lntp)"; else data="$(ss -H -lnup)"; fi
  awk -v needle="$port" '{for(i=4;i<=5;i++){n=split($i,a,":"); if(a[n]==needle){print $0;break}}}' <<< "$data"
}
unit_for_pid() {
  local pid="$1" candidate
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ "$pid" != 1 ]] || return 1
  [[ -r "/proc/$pid/cgroup" ]] || return 1
  candidate="$(sed -nE 's@.*/([A-Za-z0-9_.@:-]+\.service)(/.*)?$@\1@p' "/proc/$pid/cgroup" | head -n 1)"
  [[ "$candidate" =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] || return 1
  printf '%s' "$candidate"
}
allowed_to_stop() {
  case "$1" in
    xray.service|hysteria-server.service|hysteria.service|sing-box.service|nginx.service|caddy.service|apache2.service|httpd.service) return 0;;
    *) return 1;;
  esac
}

port_data="$(sockets_for "$NP_CTL_PROTO" "$NP_PORT")"
if [[ -z "$port_data" ]]; then
  if [[ "$NP_CTL_ACTION" == stop ]]; then
    echo 'Служба уже не использует этот порт. Ничего не остановлено.' >&2; exit 1
  fi
  echo "PORTLINE_PORT|free|$NP_CTL_PROTO|$NP_PORT|-|-|-|0"
else
  # Multiple processes can share the listener: a stop is allowed only when
  # *all* discoverable owners belong to one permitted systemd unit.
  mapfile -t pids < <(grep -oE 'pid=[0-9]+' <<< "$port_data" | cut -d= -f2 | sort -u || true)
  unit='' ; safe=1
  if (( ${#pids[@]} == 0 )); then safe=0; fi
  for pid in "${pids[@]}"; do
    candidate="$(unit_for_pid "$pid" || true)"
    if [[ -z "$candidate" ]]; then safe=0; continue; fi
    if [[ -n "$unit" && "$unit" != "$candidate" ]]; then safe=0; fi
    unit="$candidate"
  done
  if ! allowed_to_stop "$unit"; then safe=0; fi
  proc="$(sed -nE 's/.*users:\(\(\"([^\"]+)\".*/\1/p' <<< "$port_data" | head -n 1)"
  proc="${proc//|/_}"
  [[ "$proc" =~ ^[A-Za-z0-9_.@+-]{1,60}$ ]] || proc='неизвестен'
  pid="${pids[0]:--}"
  if (( safe )); then flag=1; else flag=0; fi
  if [[ "$NP_CTL_ACTION" == check ]]; then
    echo "PORTLINE_PORT|busy|$NP_CTL_PROTO|$NP_PORT|${unit:--}|$proc|$pid|$flag"
  else
    [[ "$flag" == 1 ]] || { echo 'Автоматическая остановка этой службы запрещена. Выбери другой порт.' >&2; exit 1; }
    [[ "$unit" == "${NP_EXPECT_UNIT:-}" ]] || { echo 'Служба на порту изменилась после проверки. Проверь порт повторно.' >&2; exit 1; }
    systemctl stop -- "$unit"
    sleep 1
    if [[ -n "$(sockets_for "$NP_CTL_PROTO" "$NP_PORT")" ]]; then
      echo 'Порт по-прежнему занят после остановки. Выбери другой порт.' >&2
      exit 1
    fi
    echo "PORTLINE_PORT|stopped|$NP_CTL_PROTO|$NP_PORT|$unit|$proc|$pid|0"
  fi
fi

if [[ "$NP_CTL_ACTION" == check ]]; then
  # Suggested alternatives are *currently* unused local sockets, not guaranteed
  # reachable through a VPS provider firewall or at installation time.
  suggestions=()
  for candidate in 8443 2053 2083 7443 9443 10443 10444 10445; do
    [[ "$candidate" == "$NP_SSH_PORT" ]] && continue
    if [[ -z "$(sockets_for "$NP_CTL_PROTO" "$candidate")" ]]; then
      suggestions+=("$candidate")
    fi
    (( ${#suggestions[@]} < 3 )) || break
  done
  printf 'PORTLINE_SUGGEST|%s\n' "$(IFS=,; echo "${suggestions[*]}")"
fi
