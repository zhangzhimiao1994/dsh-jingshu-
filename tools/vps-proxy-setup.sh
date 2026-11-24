#!/usr/bin/env bash
# vps-proxy-setup.sh —— 一键把 CentOS 7 的 VPS 配成可用代理服务（v2rayN 可直接导入）
#
# 装什么：Xray-core（一个内核同时提供四种协议入口）
#   1) VLESS + Vision + Reality   443/tcp   —— 不需要域名、不需要证书，抗探测最强
#   2) VLESS + WebSocket          8443/tcp  —— 配合 CDN / 反代时用
#   3) Trojan + 自签 TLS          2083/tcp  —— 兼容老客户端
#   4) Shadowsocks-2022 (aes-128-gcm) 8388/tcp+udp —— 手机端省电、简单
#
# 用法（在 VPS 上以 root 执行）：
#   bash vps-proxy-setup.sh
# 结果：
#   /root/proxy-info.txt  里是全部分享链接，复制到 v2rayN「服务器 → 从剪贴板导入」
#
# 注意：脚本只改 Xray 自己的配置与 systemd 单元，不动系统里其它服务。
set -euo pipefail

SSH_PORT="${SSH_PORT:-52464}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
CONF_DIR=/usr/local/etc/xray
INFO=/root/proxy-info.txt

say() { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }

[ "$(id -u)" = "0" ] || { echo "请用 root 执行"; exit 1; }

# 先保证 SSH 能进（重装镜像常缺 /run/sshd 或主机密钥）
say "确保 sshd 正常"
mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
systemctl enable --now sshd >/dev/null 2>&1 || systemctl enable --now ssh >/dev/null 2>&1 || true
if ss -lntp 2>/dev/null | grep -q ':22 '; then
  say "sshd 已在 22 监听"
else
  warn "sshd 未监听 22，请手动检查：systemctl status sshd；journalctl -u sshd -n 20"
fi

# ---------------------------------------------------------------- 1. 系统准备
say "安装基础依赖"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq curl tar openssl unzip ca-certificates >/dev/null 2>&1 || true
else
  PM="yum"; command -v dnf >/dev/null 2>&1 && PM="dnf"
  $PM -y install curl tar openssl unzip ca-certificates >/dev/null 2>&1 || true
fi

if [ -f /etc/selinux/config ]; then
  say "关闭 SELinux（Xray 监听非标准端口会被拦）"
  setenforce 0 2>/dev/null || true
  sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true
else
  say "无 SELinux（Debian 系），跳过"
fi

say "尝试开启 BBR（CentOS 7 自带内核可能不支持，不支持会跳过）"
modprobe tcp_bbr 2>/dev/null || true
cat >/etc/sysctl.d/99-proxy.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
fs.file-max=1048576
EOF
sysctl --system >/dev/null 2>&1 || true
if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
  say "BBR 已启用"
else
  warn "当前内核不支持 BBR（CentOS 7 默认 3.10）。想要提速需先升级内核（elrepo kernel-lt），脚本不动内核"
fi

say "放行端口（firewalld 在用才处理；云厂商安全组需你另开）"
if systemctl is-active firewalld >/dev/null 2>&1; then
  for p in 443/tcp 8443/tcp 2083/tcp 8388/tcp 8388/udp; do
    firewall-cmd --permanent --add-port="$p" >/dev/null 2>&1 || true
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
  say "firewalld 已放行 443 / 8443 / 2083 / 8388"
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  for p in 443/tcp 8443/tcp 2083/tcp 8388/tcp 8388/udp 22/tcp; do
    ufw allow "${p%%/*}" >/dev/null 2>&1 || true
  done
  say "ufw 已放行 22/443/8443/2083/8388"
else
  warn "没有活跃的 firewalld/ufw，跳过（若用 nftables/iptables 请自行放行 22/443/8443/2083/8388）"
fi

# ---------------------------------------------------------------- 2. 安装 Xray
say "安装 Xray-core（手动安装，适配 CentOS 7：没有 systemd-sysusers）"
XRAY_BIN=/usr/local/bin/xray
if [ ! -x "$XRAY_BIN" ]; then
  getent group xray >/dev/null || groupadd -r xray
  id -u xray >/dev/null 2>&1 || useradd -r -g xray -d /usr/local/share/xray -s /sbin/nologin xray
  mkdir -p /usr/local/share/xray /var/log/xray
  VL="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)"
  [ -n "$VL" ] || VL=v26.11.9
  say "下载 Xray $VL"
  curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/$VL/Xray-linux-64.zip" \
    || { echo "下载 Xray 失败（服务器访问不了 GitHub）"; exit 1; }
  rm -rf /tmp/xray-pkg && mkdir -p /tmp/xray-pkg
  unzip -o -q /tmp/xray.zip -d /tmp/xray-pkg
  install -m 755 /tmp/xray-pkg/xray "$XRAY_BIN"
  for f in geoip.dat geosite.dat; do
    [ -f "/tmp/xray-pkg/$f" ] && install -m 644 "/tmp/xray-pkg/$f" "/usr/local/share/xray/$f"
  done
fi
[ -x "$XRAY_BIN" ] || { echo "没找到 $XRAY_BIN"; exit 1; }
say "$XRAY_BIN version | head -1" >/dev/null 2>&1 || true
say "Xray 版本：$("$XRAY_BIN" version | head -1)"

# ---------------------------------------------------------------- 3. 生成材料
say "生成 UUID / Reality 密钥 / 密码"
UUID="$($XRAY_BIN uuid)"
KEYS="$($XRAY_BIN x25519)"
PRIV="$(echo "$KEYS" | awk -F': *' '/Private/{print $2}')"
PUB="$(echo "$KEYS" | awk -F': *' '/Public/{print $2}')"
SHORT_ID="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SS_PASS="$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | cut -c1-16)"
TROJAN_PASS="$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | cut -c1-16)"
IP="$(curl -s --max-time 8 https://api.ipify.org || curl -s --max-time 8 ifconfig.me || echo '你的服务器IP')"

say "生成自签证书（Trojan 用）"
mkdir -p "$CONF_DIR"
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout "$CONF_DIR/self.key" -out "$CONF_DIR/self.crt" \
  -subj "/CN=$IP" >/dev/null 2>&1

# ---------------------------------------------------------------- 4. 写配置
say "写入 $CONF_DIR/config.json"
cat >"$CONF_DIR/config.json" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "reality-443",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$REALITY_SNI:443",
          "serverNames": ["$REALITY_SNI"],
          "privateKey": "$PRIV",
          "shortIds": ["$SHORT_ID"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    },
    {
      "tag": "ws-8443",
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": { "clients": [{ "id": "$UUID" }], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/whale" }
      }
    },
    {
      "tag": "trojan-2083",
      "listen": "0.0.0.0",
      "port": 2083,
      "protocol": "trojan",
      "settings": { "clients": [{ "password": "$TROJAN_PASS" }] },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{ "certificateFile": "$CONF_DIR/self.crt", "keyFile": "$CONF_DIR/self.key" }]
        }
      }
    },
    {
      "tag": "ss-8388",
      "listen": "0.0.0.0",
      "port": 8388,
      "protocol": "shadowsocks",
      "settings": {
        "method": "aes-128-gcm",
        "password": "$SS_PASS",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
JSON

chown -R xray:xray "$CONF_DIR" /var/log/xray
chmod 640 "$CONF_DIR/config.json" "$CONF_DIR/self.key"

say "写入 systemd 单元"
cat >/etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray Service
After=network-online.target
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

say "重载 Xray"
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
sleep 2
if ! systemctl is-active xray >/dev/null 2>&1; then
  warn "Xray 没起来，看日志：journalctl -u xray -n 50 --no-pager"
  exit 1
fi
say "Xray 运行中"

# ---------------------------------------------------------------- 5. 输出链接
SS_B64="$(printf '%s' "aes-128-gcm:$SS_PASS" | base64 -w0)"
VLESS_REALITY="vless://$UUID@$IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$PUB&sid=$SHORT_ID&type=tcp"
VLESS_WS="vless://$UUID@$IP:8443?encryption=none&security=none&type=ws&path=%2Fwhale"
TROJAN="trojan://$TROJAN_PASS@$IP:2083?security=tls&sni=$IP&allowInsecure=1"
SS_LINK="ss://$SS_B64@$IP:8388"

{
  echo "==== 鲸枢 VPS 代理信息（$(date '+%F %T')）===="
  echo "服务器：$IP    系统：$(cat /etc/centos-release 2>/dev/null || uname -a)"
  echo
  echo "【1】VLESS + Reality（推荐，无需域名）443"
  echo "$VLESS_REALITY"
  echo
  echo "【2】VLESS + WebSocket 8443（走 CDN 时用）"
  echo "$VLESS_WS"
  echo
  echo "【3】Trojan 2083（自签证书，客户端需允许不安全）"
  echo "$TROJAN"
  echo
  echo "【4】Shadowsocks 8388（aes-128-gcm）"
  echo "$SS_LINK"
  echo
  echo "Reality 参数：公钥 $PUB / shortId $SHORT_ID / sni $REALITY_SNI"
  echo "SS 密码：$SS_PASS    Trojan 密码：$TROJAN_PASS    UUID：$UUID"
  echo
  echo "端口放行：443 8443 2083 8388(tcp+udp)；云厂商安全组要另开"
  echo "服务管理：systemctl status|restart xray    日志：journalctl -u xray -f"
} | tee "$INFO"

say "完成。链接已写入 $INFO"
say "v2rayN：复制上面任一链接 → 服务器 → 从剪贴板导入"
