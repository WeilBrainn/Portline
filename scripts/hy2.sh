#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
trap 'echo "Ошибка в строке ${LINENO}. Проверь журнал выше." >&2' ERR
phase() { printf '::phase|%s|%s\n' "$1" "$2"; }
phase 14 'Проверка среды'
if [[ "$(id -u)" != '0' ]]; then echo 'Требуются root или sudo без пароля.' >&2; exit 1; fi
if ! command -v systemctl >/dev/null;then echo 'Нужен systemd.' >&2;exit 1;fi
source /etc/os-release
case "${ID:-}" in ubuntu|debian|almalinux|rocky|centos|rhel|fedora) ;; *) echo "Дистрибутив ${ID:-?} пока не поддерживается." >&2;exit 1;; esac
case "$(uname -m)" in x86_64|aarch64) ;; *) echo 'Требуется x86_64 или aarch64.' >&2;exit 1;; esac
if [[ ! "$NP_PORT" =~ ^[0-9]{1,5}$ ]] || (( NP_PORT < 1 || NP_PORT > 65535 ));then exit 1;fi
if command -v ss >/dev/null 2>&1;then
  if ss -lnuH | awk -v p="$NP_PORT" '{n=split($4,a,":");if(a[n]==p)found=1}END{exit !found}';then
    echo "UDP $NP_PORT уже занят. Выбери другой порт или останови существующую службу вручную." >&2;exit 1
  fi
fi
phase 28 'Установка зависимостей'
if command -v apt-get >/dev/null 2>&1;then
  apt-get update -qq;apt-get install -y -qq curl ca-certificates openssl tar
elif command -v dnf >/dev/null 2>&1;then
  dnf install -y -q curl ca-certificates openssl tar
else echo 'Нужен apt-get/dnf.' >&2;exit 1;fi
phase 44 'Загрузка официального Hysteria 2'
tmp_script="$(mktemp)"
trap 'rm -f "${tmp_script:-}"' EXIT
curl -fsSL --retry 3 https://get.hy2.sh/ -o "$tmp_script"
bash "$tmp_script"
command -v hysteria >/dev/null || { echo 'Hysteria не установлена.' >&2;exit 1; }
phase 63 'Сертификат и авторизация'
# Honor the service account of the official installer instead of escalating to root.
service_user="$(systemctl show -p User --value hysteria-server.service)"
service_user="${service_user:-root}"
if ! id "$service_user" >/dev/null 2>&1;then
  echo "Не обнаружен пользователь службы Hysteria: $service_user" >&2;exit 1
fi
service_group="$(id -gn "$service_user")"
mkdir -p /etc/hysteria
chown root:"$service_group" /etc/hysteria
chmod 750 /etc/hysteria
conf=/etc/hysteria/config.yaml
if [[ -f "$conf" ]];then cp -p "$conf" "${conf}.portline-backup-$(date +%Y%m%d%H%M%S)";fi
openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
  -keyout /etc/hysteria/portline.key -out /etc/hysteria/portline.crt \
  -subj '/CN=portline.local' -addext "subjectAltName=DNS:portline.local" >/dev/null 2>&1
chown root:"$service_group" /etc/hysteria/portline.key /etc/hysteria/portline.crt
chmod 640 /etc/hysteria/portline.key
chmod 644 /etc/hysteria/portline.crt
PASSWORD="$(openssl rand -hex 24)"
cat > "$conf" <<YAML
listen: :${NP_PORT}
tls:
  cert: /etc/hysteria/portline.crt
  key: /etc/hysteria/portline.key
auth:
  type: password
  password: ${PASSWORD}
masquerade:
  type: string
  string:
    content: 'Not Found'
    statusCode: 404
    headers:
      content-type: text/plain
YAML
chown root:"$service_group" "$conf"
chmod 640 "$conf"
phase 82 'Запуск сервиса и сетевого экрана'
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld;then
  firewall-cmd --permanent --add-port="${NP_PORT}/udp" >/dev/null;firewall-cmd --reload >/dev/null
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active';then
  ufw allow "${NP_PORT}/udp" >/dev/null
fi
systemctl enable hysteria-server.service >/dev/null
systemctl restart hysteria-server.service
sleep 2
if ! systemctl is-active --quiet hysteria-server.service;then journalctl -u hysteria-server --no-pager -n 20 >&2 || true;exit 1;fi
phase 96 'Проверка готовности'
if command -v ss >/dev/null 2>&1;then
  ss -lnuH | awk -v p="$NP_PORT" '{n=split($4,a,":");if(a[n]==p)found=1}END{exit !found}' || { echo 'Hysteria не слушает UDP-порт.' >&2;exit 1; }
fi
PIN="$(openssl x509 -in /etc/hysteria/portline.crt -noout -fingerprint -sha256 | cut -d= -f2)"
[[ -n "$PIN" ]] || { echo 'Не удалось получить отпечаток сертификата.' >&2;exit 1; }
printf 'PORTLINE_LINK=hysteria2://%s@%s:%s/?insecure=1&pinSHA256=%s&sni=portline.local#Portline-Hysteria2\n' \
  "$PASSWORD" "$NP_ADDR" "$NP_PORT" "$PIN"
echo 'Hysteria активна. Клиент должен поддерживать TLS pinSHA256.'
echo 'Сертификат самоподписанный и действителен 365 дней: запланируй перевыпуск.'
