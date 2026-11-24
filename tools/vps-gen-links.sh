#!/usr/bin/env bash
# gen-links.sh —— 从现有 /usr/local/etc/xray/config.json 反推 v2rayN 分享链接（不重新生成凭据）
set -euo pipefail
CONF=/usr/local/etc/xray/config.json
INFO=/root/proxy-info.txt
XRAY=/usr/local/bin/xray

PYBIN="python3"; command -v python3 >/dev/null 2>&1 || PYBIN="python2"
read_json() { $PYBIN - "$1" <<'PY'
import json,sys
k=sys.argv[1].split('.')
d=json.load(open('/usr/local/etc/xray/config.json'))
for p in k:
    if isinstance(d,list): d=d[int(p)]
    else: d=d[p]
print(d)
PY
}

UUID="$(read_json 'inbounds.0.settings.clients.0.id')"
PRIV="$(read_json 'inbounds.0.streamSettings.realitySettings.privateKey')"
SHORT="$(read_json 'inbounds.0.streamSettings.realitySettings.shortIds.0')"
SNI="$(read_json 'inbounds.0.streamSettings.realitySettings.serverNames.0')"
TROJAN_PASS="$(read_json 'inbounds.2.settings.clients.0.password')"
SS_PASS="$(read_json 'inbounds.3.settings.password')"
SS_METHOD="$(read_json 'inbounds.3.settings.method')"
IP="$(curl -s --max-time 8 https://api.ipify.org || echo '')"

PUB="$($XRAY x25519 -i "$PRIV" 2>/dev/null | awk -F': *' '/ublic/{print $2}')"
[ -n "$PUB" ] || PUB="(用 xray x25519 -i 私钥 重新算)"

SS_B64="$(printf '%s' "$SS_METHOD:$SS_PASS" | base64 -w0)"

{
  echo "==== 鲸枢 VPS 代理信息（$(date '+%F %T')）===="
  echo "服务器：$IP"
  echo
  echo "【1】VLESS + Reality（推荐）443"
  echo "vless://$UUID@$IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUB&sid=$SHORT&type=tcp"
  echo
  echo "【2】VLESS + WebSocket 8443"
  echo "vless://$UUID@$IP:8443?encryption=none&security=none&type=ws&path=%2Fwhale"
  echo
  echo "【3】Trojan 2083（自签证书，客户端需允许不安全）"
  echo "trojan://$TROJAN_PASS@$IP:2083?security=tls&sni=$IP&allowInsecure=1"
  echo
  echo "【4】Shadowsocks 8388"
  echo "ss://$SS_B64@$IP:8388"
  echo
  echo "Reality：公钥 $PUB  shortId $SHORT  sni $SNI"
  echo "UUID $UUID"
  echo "SS 密码 $SS_PASS    Trojan 密码 $TROJAN_PASS"
} | tee "$INFO"
