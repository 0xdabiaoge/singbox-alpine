#!/bin/bash
# sing-box-alpine-final.sh
# An ultra-streamlined script for Alpine Linux, now with Docker compatibility.
# Version: 7.1 (Final Parameter Fix)
# Author: Gemini
# Features:
# - Manages sing-box process directly via PID, avoiding OpenRC dependency.
# - VLESS (TCP/REALITY), Hysteria2, TUICv5, Shadowsocks, SOCKS5.
# - Uses OFFICIAL sing-box binary from GitHub.
# - Uses self-signed certificates (no domain needed).
# - Auto-generates and manages a full Clash Meta compatible YAML config.
# - Full node management (add/delete/view with YAML sync).
# - Self-destructing uninstall.

# --- 全局变量和样式 ---
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
YAML_FILE="/usr/local/etc/sing-box/clash.yaml"
PID_FILE="/var/run/sing-box.pid"
# 新增：元数据文件，用于可靠地存储分享链接信息
META_FILE="/usr/local/etc/sing-box/metadata.json"
# 全局变量用于存储IP地址
server_ip=""

# --- Alpine/系统兼容性函数 ---

function check_and_install_deps() {
    if [ ! -f /etc/alpine-release ]; then
        echo -e "${RED}警告: 此脚本专为 Alpine Linux 设计。${NC}"
    fi
    echo "正在检查并安装所需依赖 (curl, jq, openssl)..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl procps" # procps provides `ps`
    for pkg in $required_pkgs; do
        if ! apk -e info "$pkg" >/dev/null 2>&1; then
            pkgs_to_install="$pkgs_to_install $pkg"
        fi
    done
    if [ -n "$pkgs_to_install" ]; then
        echo "正在安装缺失的依赖: $pkgs_to_install"
        apk update
        if ! apk add $pkgs_to_install; then
            echo -e "${RED}依赖安装失败，请手动执行 'apk add $pkgs_to_install' 后重试。${NC}"
            exit 1
        fi
    else
        echo "所有依赖均已满足。"
    fi
}

# --- Docker 兼容的服务管理 ---

function is_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null; then
            return 0 # Running
        fi
    fi
    return 1 # Not running
}

function manage_service() {
    local action="$1"
    case "$action" in
        start)
            if is_running; then
                echo -e "${YELLOW}sing-box 已经在运行。${NC}"
                return
            fi
            echo "正在后台启动 sing-box..."
            nohup /usr/local/bin/sing-box run -c "$CONFIG_FILE" >/dev/null 2>&1 &
            echo $! > "$PID_FILE"
            sleep 1
            if is_running; then
                echo -e "${CYAN}sing-box 启动成功。${NC}"
            else
                echo -e "${RED}sing-box 启动失败。请检查日志或手动运行: /usr/local/bin/sing-box run -c $CONFIG_FILE${NC}"
            fi
            ;;
        stop)
            if ! is_running; then
                echo -e "${YELLOW}sing-box 未在运行。${NC}"
                return
            fi
            echo "正在停止 sing-box..."
            local pid=$(cat "$PID_FILE")
            kill "$pid"
            rm -f "$PID_FILE"
            echo -e "${CYAN}sing-box 已停止。${NC}"
            ;;
        restart)
            manage_service "stop"
            sleep 1
            manage_service "start"
            ;;
        status)
            if is_running; then
                echo -e "${CYAN}sing-box 正在运行 (PID: $(cat "$PID_FILE"))。${NC}"
            else
                echo -e "${YELLOW}sing-box 未在运行。${NC}"
            fi
            ;;
    esac
}

# --- 核心辅助函数 ---

function url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}

function get_local_ip() {
    local ip_services_v4=(
        "curl -s4 --max-time 2 icanhazip.com"
        "curl -s4 --max-time 2 ipinfo.io/ip"
        "curl -s4 --max-time 2 api.ipify.org"
        "curl -s4 --max-time 2 checkip.amazonaws.com"
    )
    local ip_services_v6=(
        "curl -s6 --max-time 2 icanhazip.com"
        "curl -s6 --max-time 2 ipinfo.io/ip"
        "curl -s6 --max-time 2 api64.ipify.org"
    )
    local ip_v4=""
    local ip_v6=""

    echo "正在尝试获取公网 IPv4 地址..."
    for cmd in "${ip_services_v4[@]}"; do
        ip_v4=$($cmd)
        if [ -n "$ip_v4" ]; then
            echo -e "  - ${CYAN}成功获取 IPv4: $ip_v4${NC}"
            break
        fi
    done

    echo "正在尝试获取公网 IPv6 地址..."
    for cmd in "${ip_services_v6[@]}"; do
        ip_v6=$($cmd)
        if [ -n "$ip_v6" ]; then
            echo -e "  - ${CYAN}成功获取 IPv6: $ip_v6${NC}"
            break
        fi
    done

    if [[ -z "$ip_v4" && -z "$ip_v6" ]]; then
        echo -e "${RED}无法获取本机IP地址！${NC}"
        echo -e "${YELLOW}请检查以下几点:${NC}"
        echo -e "${YELLOW}1. 机器是否有正常的网络连接。${NC}"
        echo -e "${YELLOW}2. DNS 是否配置正确。${NC}"
        echo -e "${YELLOW}3. 防火墙是否允许出站连接。${NC}"
        exit 1
    fi
    server_ip=${ip_v4:-$ip_v6}
    echo "本机IP地址: $server_ip"
}

function install_sing_box() {
    echo "正在从官方源安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) echo -e "${RED}不支持的架构：$arch${NC}"; exit 1 ;;
    esac
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    if [ -z "$download_url" ]; then
        echo -e "${RED}无法从 GitHub API 获取 sing-box 下载链接。${NC}"
        exit 1
    fi
    echo "下载链接: $download_url"
    if ! wget -qO sing-box.tar.gz "$download_url"; then
        echo -e "${RED}下载失败!${NC}"; exit 1
    fi
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"-linux-${arch_tag}/sing-box" /usr/local/bin/
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x /usr/local/bin/sing-box
    echo "sing-box 安装成功。"
}

function initialize_config_files() {
    mkdir -p /usr/local/etc/sing-box
    if [ ! -f "$CONFIG_FILE" ] || ! jq . "$CONFIG_FILE" >/dev/null 2>&1; then
        echo '{
            "log": {"level": "info", "timestamp": true},
            "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }' > "$CONFIG_FILE"
    fi
    # 初始化元数据文件
    if [ ! -f "$META_FILE" ]; then
        echo "{}" > "$META_FILE"
    fi
    if [ ! -f "$YAML_FILE" ]; then
        echo "正在根据模板创建全新的 clash.yaml 配置文件..."
        cat > "$YAML_FILE" << 'EOF'
mixed-port: 7890
allow-lan: true
bind-address: "*"
find-process-mode: strict
mode: rule
unified-delay: false
tcp-concurrent: true
log-level: debug
ipv6: true
global-client-fingerprint: chrome
external-controller: 127.0.0.1:9090
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
tun:
  enable: false
  stack: mixed
  dns-hijack:
    - 0.0.0.0:53
  auto-detect-interface: true
  auto-route: true
  auto-redirect: true
  mtu: 1500
profile:
  store-selected: false
  store-fake-ip: true
sniffer:
  enable: true
  override-destination: false
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "+.push.apple.com"
dns:
  enable: true
  prefer-h3: false
  respect-rules: true
  listen: 0.0.0.0:53
  ipv6: true
  default-nameserver:
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
    - 1.1.1.1
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: blacklist
  fake-ip-filter:
    - "*"
    - "+.lan"
    - "+.local"
  nameserver-policy:
    "rule-set:cn_domain,private_domain":
      - https://120.53.53.53/dns-query
      - https://223.5.5.5/dns-query
    "rule-set:category-ads-all":
      - rcode://success
    "rule-set:geolocation-!cn":
      - "https://dns.cloudflare.com/dns-query"
      - "https://dns.google/dns-query"
  nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
    - https://cloudflare-dns.com/dns-query
  proxy-server-nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query

proxies:

proxy-groups:
  - name: Proxy
    type: select
    proxies:

rules:
  - RULE-SET,private_ip,DIRECT,no-resolve
  - RULE-SET,category-ads-all,REJECT
  - RULE-SET,cn_domain,DIRECT
  - RULE-SET,geolocation-!cn,Proxy
  - RULE-SET,cn_ip,DIRECT
  - MATCH,Proxy

rule-anchor:
  ip: &ip {type: http, interval: 86400, behavior: ipcidr, format: mrs}
  domain: &domain {type: http, interval: 86400, behavior: domain, format: mrs}
rule-providers:
  private_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs"
  cn_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
  geolocation-!cn:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs"
  category-ads-all:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"
  private_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs"
  cn_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
EOF
    fi
}

function generate_self_signed_cert() {
    local cert_path="/usr/local/etc/sing-box/cert.pem"
    local key_path="/usr/local/etc/sing-box/private.key"
    if [ -f "$cert_path" ] && [ -f "$key_path" ]; then
        echo "检测到已存在的自签名证书，将继续使用。"
        return
    fi
    echo "正在生成自签名证书 (CN=www.microsoft.com)..."
    openssl ecparam -genkey -name prime256v1 -out "$key_path"
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=www.microsoft.com"
    echo "自签名证书生成成功。"
}

function get_listen_port() {
    while true; do
        read -p "请输入监听端口: " listen_port
        if [[ "$listen_port" =~ ^[0-9]+$ && "$listen_port" -ge 1 && "$listen_port" -le 65535 ]]; then
            break
        else
            echo -e "${RED}请输入一个 1-65535 之间的有效端口号。${NC}"
        fi
    done
}
function get_uuid() {
    read -p "请输入 UUID (默认随机): " uuid
    uuid=${uuid:-$(sing-box generate uuid)}
}
function get_password() {
    read -p "请输入密码 (默认随机): " password
    password=${password:-$(sing-box generate rand --hex 16)}
}

# --- YAML 配置生成 ---
function append_yaml_config() {
    local node_type=$1
    local proxy_name=""
    local proxy_block=""

    case $node_type in
        "vless-tcp")
            local port=$2 uuid=$3
            proxy_name="vless-tcp-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: vless
    server: ${server_ip}
    port: ${port}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: false
EOF
)
            ;;
        "vless-reality")
            local port=$2 uuid=$3 server_name=$4 public_key=$5 short_id=$6
            proxy_name="vless-reality-vision-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: vless
    server: ${server_ip}
    port: ${port}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${server_name}
    reality-opts:
      public-key: ${public_key}
      short-id: ${short_id}
EOF
)
            ;;
        "hysteria2")
            local port=$2 password=$3
            proxy_name="hysteria2-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: hysteria2
    server: ${server_ip}
    port: ${port}
    password: ${password}
    alpn:
      - h3
    sni: www.microsoft.com
    skip-cert-verify: true
    up: "50 Mbps"
    down: "200 Mbps"
EOF
)
            ;;
        "tuic")
            local port=$2 uuid=$3 password=$4
            proxy_name="tuic-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    server: ${server_ip}
    port: ${port}
    type: tuic
    uuid: ${uuid}
    password: ${password}
    sni: www.microsoft.com
    alpn: [h3]
    udp-relay-mode: native
    skip-cert-verify: true
    congestion-controller: bbr
EOF
)
            ;;
        "shadowsocks")
            local port=$2 method=$3 password=$4
            proxy_name="ss-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: ss
    server: ${server_ip}
    port: ${port}
    cipher: ${method}
    password: ${password}
EOF
)
            ;;
        "socks")
            local port=$2 username=$3 password=$4
            proxy_name="socks-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: socks5
    server: ${server_ip}
    port: ${port}
    username: ${username}
    password: ${password}
EOF
)
            ;;
    esac
    
    awk -v block="$proxy_block" '1; /^proxies:$/ {print block}' "$YAML_FILE" > "${YAML_FILE}.tmp" && mv "${YAML_FILE}.tmp" "$YAML_FILE"

    local line_num=$(awk '/- name: Proxy/,/proxies:/ {if (/proxies:/) print NR}' "$YAML_FILE" | tail -n 1)
    if [ -n "$line_num" ]; then
        sed -i "${line_num}a\\      - ${proxy_name}" "$YAML_FILE"
    fi
}

# --- 节点搭建函数 ---

function vless_tcp_install() {
    echo "--- 正在配置 VLESS (TCP) 节点 ---"
    get_listen_port
    get_uuid
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg uuid "$uuid" \
        '{"type": "vless", "tag": "vless-tcp-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"uuid": $uuid}], "tls": {"enabled": false}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "vless-tcp" "$listen_port" "$uuid"
    echo -e "${CYAN}VLESS (TCP) 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, UUID: $uuid"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function vless_reality_install() {
    echo "--- 正在配置 VLESS (REALITY) 节点 ---"
    get_listen_port
    get_uuid
    read -p "请输入伪装域名 (默认 www.microsoft.com): " server_name
    server_name=${server_name:-"www.microsoft.com"}
    local keypair=$(sing-box generate reality-keypair)
    local private_key=$(echo "$keypair" | grep PrivateKey | awk '{print $2}')
    local public_key=$(echo "$keypair" | grep PublicKey | awk '{print $2}')
    local short_id=$(sing-box generate rand --hex 8)
    local tag="vless-reality-in-${listen_port}"
    
    # 确保生成的 config.json 合法，不包含任何自定义字段
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg uuid "$uuid" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" --arg tag "$tag" \
        '{"type": "vless", "tag": $tag, "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"uuid": $uuid, "flow": "xtls-rprx-vision"}], "tls": {"enabled": true, "server_name": $server_name, "reality": {"enabled": true, "handshake": {"server": $server_name, "server_port": 443}, "private_key": $private_key, "short_id": [$short_id]}}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    
    # 将分享链接所需参数存入元数据文件
    jq --arg tag "$tag" --arg pk "$public_key" --arg sid "$short_id" \
       '.[$tag] = {publicKey: $pk, shortId: $sid}' "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"

    append_yaml_config "vless-reality" "$listen_port" "$uuid" "$server_name" "$public_key" "$short_id"
    echo -e "${CYAN}VLESS (REALITY) 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, UUID: $uuid"
    echo "ServerName: $server_name, Short ID: $short_id, Public Key: $public_key"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function hysteria2_install() {
    echo "--- 正在配置 Hysteria2 (自签证书) 节点 ---"
    generate_self_signed_cert
    get_listen_port
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg password "$password" \
        '{"type": "hysteria2", "tag": "hy2-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"password": $password}], "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "/usr/local/etc/sing-box/cert.pem", "key_path": "/usr/local/etc/sing-box/private.key"}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "hysteria2" "$listen_port" "$password"
    echo -e "${CYAN}Hysteria2 节点添加成功!${NC}"
    echo -e "${YELLOW}请注意：此节点使用自签名证书，客户端需开启“跳过证书验证”。${NC}"
    echo "地址: $server_ip, 端口: $listen_port, 密码: $password"
    echo "SNI: www.microsoft.com"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function tuic_install() {
    echo "--- 正在配置 TUICv5 (自签证书) 节点 ---"
    generate_self_signed_cert
    get_listen_port
    get_uuid
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg uuid "$uuid" --arg password "$password" \
        '{"type": "tuic", "tag": "tuic-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"uuid": $uuid, "password": $password}], "congestion_control": "bbr", "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "/usr/local/etc/sing-box/cert.pem", "key_path": "/usr/local/etc/sing-box/private.key"}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "tuic" "$listen_port" "$uuid" "$password"
    echo -e "${CYAN}TUICv5 节点添加成功!${NC}"
    echo -e "${YELLOW}请注意：此节点使用自签名证书，客户端需开启“跳过证书验证”。${NC}"
    echo "地址: $server_ip, 端口: $listen_port, UUID: $uuid, 密码: $password"
    echo "SNI: www.microsoft.com"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function shadowsocks_install() {
    echo "--- 正在配置 Shadowsocks (aes-256-gcm加密) 节点 ---"
    get_listen_port
    local ss_method="aes-256-gcm"
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg ss_method "$ss_method" --arg password "$password" \
        '{"type": "shadowsocks", "tag": "ss-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "method": $ss_method, "password": $password}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "shadowsocks" "$listen_port" "$ss_method" "$password"
    echo -e "${CYAN}Shadowsocks 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, 加密方式: $ss_method, 密码: $password"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function socks_install() {
    echo "--- 正在配置 SOCKS5 节点 ---"
    get_listen_port
    read -p "请输入用户名 (默认随机): " username
    username=${username:-$(sing-box generate rand --hex 8)}
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg username "$username" --arg password "$password" \
        '{"type": "socks", "tag": "socks-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"username": $username, "password": $password}]}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "socks" "$listen_port" "$username" "$password"
    echo -e "${CYAN}SOCKS5 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, 用户名: $username, 密码: $password"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

# --- 管理功能 ---

function view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${YELLOW}当前没有任何已配置的节点。${NC}"
        return
    fi
    
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE")
    echo "--- 当前节点信息 (共 $node_count 个) ---"

    for i in $(seq 0 $((node_count - 1))); do
        local node=$(jq ".inbounds[$i]" "$CONFIG_FILE")
        local type=$(echo "$node" | jq -r '.type')
        local tag=$(echo "$node" | jq -r '.tag')
        local port=$(echo "$node" | jq -r '.listen_port')
        
        echo "-------------------------------------"
        echo -e " ${CYAN}节点 $((i+1)): ${tag}${NC}"
        
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local security="none"
                if [[ $(echo "$node" | jq -r '.tls.enabled') == "true" ]]; then
                    if [[ $(echo "$node" | jq -r '.tls.reality.enabled') == "true" ]]; then
                        security="reality"
                    else
                        security="tls"
                    fi
                fi

                if [[ "$security" == "reality" ]]; then
                    local server_name=$(echo "$node" | jq -r '.tls.server_name')
                    local flow=$(echo "$node" | jq -r '.users[0].flow')
                    
                    local meta_info=$(jq -r --arg tag "$tag" '.[$tag]' "$META_FILE")
                    if [[ -z "$meta_info" || "$meta_info" == "null" ]]; then
                        echo "  (错误: 无法在元数据文件中找到节点 '$tag' 的信息)"
                        continue
                    fi
                    local public_key=$(echo "$meta_info" | jq -r '.publicKey')
                    local short_id=$(echo "$meta_info" | jq -r '.shortId')

                    # 最终修复：使用 v2rayN 兼容的 pbk 和 sid 参数名, 并添加 encryption=none
                    url="vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${server_name}&fp=chrome&flow=${flow}&pbk=${public_key}&sid=${short_id}#$(url_encode "$tag")"
                else # Plain TCP VLESS
                    url="vless://${uuid}@${server_ip}:${port}?encryption=none&security=none&type=tcp#$(url_encode "$tag")"
                fi
                ;;
            "hysteria2")
                local password=$(echo "$node" | jq -r '.users[0].password')
                url="hysteria2://${password}@${server_ip}:${port}?sni=www.microsoft.com&insecure=1#$(url_encode "$tag")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local password=$(echo "$node" | jq -r '.users[0].password')
                url="tuic://${uuid}:${password}@${server_ip}:${port}?sni=www.microsoft.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(url_encode "$tag")"
                ;;
            "shadowsocks")
                local method=$(echo "$node" | jq -r '.method')
                local password=$(echo "$node" | jq -r '.password')
                local b64_part=$(echo -n "${method}:${password}" | base64 | tr -d '\n')
                url="ss://${b64_part}@${server_ip}:${port}#$(url_encode "$tag")"
                ;;
            "socks")
                local username=$(echo "$node" | jq -r '.users[0].username')
                local password=$(echo "$node" | jq -r '.users[0].password')
                echo "  类型: SOCKS5"
                echo "  地址: $server_ip"
                echo "  端口: $port"
                echo "  用户: $username"
                echo "  密码: $password"
                echo "  (SOCKS5 协议无标准分享链接格式)"
                ;;
            *)
                echo "  (不支持为类型 '$type' 生成链接)"
                ;;
        esac

        if [ -n "$url" ]; then
            echo -e "  ${YELLOW}分享链接:${NC}"
            echo -e "  ${url}"
        fi
    done
    echo "-------------------------------------"
}

function manage_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${YELLOW}当前没有任何已配置的节点。${NC}"
        return
    fi
    echo "--- 节点管理 (删除) ---"
    jq -r '.inbounds[] | "\(.tag) (\(.type)) @ \(.listen_port)"' "$CONFIG_FILE" | cat -n
    echo "------------------"
    read -p "请输入要删除的节点编号 (输入 0 返回): " node_num
    if [[ ! "$node_num" =~ ^[0-9]+$ ]]; then echo -e "${RED}无效输入。${NC}"; return; fi
    if [ "$node_num" -eq 0 ]; then return; fi
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$node_num" -gt "$node_count" ]; then echo -e "${RED}编号超出范围。${NC}"; return; fi

    local index_to_delete=$((node_num - 1))
    local tag_to_delete=$(jq -r ".inbounds[${index_to_delete}].tag" "$CONFIG_FILE")
    
    # 从主配置删除
    jq "del(.inbounds[${index_to_delete}])" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    echo "节点已从 sing-box 配置中删除。"

    # 从元数据文件删除
    if jq -e --arg tag "$tag_to_delete" '.[$tag]' "$META_FILE" > /dev/null; then
        jq --arg tag "$tag_to_delete" 'del(.[$tag])' "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"
        echo "节点已从元数据文件中删除。"
    fi

    # 从 YAML 删除
    if [ -f "$YAML_FILE" ] && [ -n "$tag_to_delete" ]; then
        local port_to_delete=$(echo "$tag_to_delete" | awk -F'-' '{print $NF}')
        local type_prefix=$(echo "$tag_to_delete" | sed -E 's/(-in-).+//')
        local proxy_name_to_delete=""
        
        case "$type_prefix" in
            "vless-tcp") proxy_name_to_delete="vless-tcp-${port_to_delete}" ;;
            "vless-reality") proxy_name_to_delete="vless-reality-vision-${port_to_delete}" ;;
            "hy2") proxy_name_to_delete="hysteria2-${port_to_delete}" ;;
            "tuic") proxy_name_to_delete="tuic-${port_to_delete}" ;;
            "ss") proxy_name_to_delete="ss-${port_to_delete}" ;;
            "socks") proxy_name_to_delete="socks-${port_to_delete}" ;;
        esac

        if [ -n "$proxy_name_to_delete" ]; then
            awk -v name="$proxy_name_to_delete" '
                BEGIN { in_block=0 }
                $0 ~ "- name: " name { in_block=1; next }
                !in_block { print }
                in_block && ($0 ~ /^- name:/ || $0 ~ /^proxy-groups:/) { in_block=0; print }
            ' "$YAML_FILE" | sed '/^$/d' > tmp.yaml && mv tmp.yaml "$YAML_FILE"

            sed -i "/- ${proxy_name_to_delete}/d" "$YAML_FILE"
            echo "节点已从 Clash YAML 配置中删除。"
        fi
    fi
    
    echo -e "${CYAN}节点删除成功！正在重启服务...${NC}"
    manage_service "restart"
}

function uninstall_script() {
    local script_path=$(readlink -f "$0")
    read -p "确定要卸载 sing-box 并删除所有相关文件和此脚本吗? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "卸载已取消。"
        return
    fi
    echo "正在停止服务..."
    manage_service "stop"
    echo "正在删除文件..."
    rm -rf /usr/local/bin/sing-box /usr/local/etc/sing-box "$PID_FILE"
    echo "清理完成。"
    rm -f "$script_path"
    echo "脚本 '$script_path' 已自毁。"
    echo "再见！"
    exit 0
}


# --- 主菜单 ---
function ensure_installation() {
    if [ ! -f /usr/local/bin/sing-box ]; then
        echo "sing-box 主程序未找到，将开始安装..."
        install_sing_box
    fi
}

function main_menu() {
    clear
    echo "sing-box Alpine 安装脚本"
    echo "=========================================="
    echo "--- 安装选项 ---"
    echo -e " ${CYAN}1)${NC} VLESS (TCP)"
    echo -e " ${CYAN}2)${NC} VLESS (REALITY)"
    echo -e " ${CYAN}3)${NC} Hysteria2 (自签证书)"
    echo -e " ${CYAN}4)${NC} TUICv5 (自签证书)"
    echo -e " ${CYAN}5)${NC} Shadowsocks (aes-256-gcm加密)"
    echo -e " ${CYAN}6)${NC} SOCKS5"
    echo "--- 管理选项 ---"
    echo -e " ${YELLOW}7)${NC} 查看节点分享链接"
    echo -e " ${YELLOW}8)${NC} 管理节点 (删除)"
    echo -e " ${YELLOW}9)${NC} 重启 sing-box 服务"
    echo -e " ${YELLOW}10)${NC} 卸载 sing-box"
    echo -e " ${YELLOW}0)${NC} 退出脚本"
    echo "=========================================="
    read -p "请输入选项 [0-10]: " choice

    local is_install_action=false
    case $choice in
        1) vless_tcp_install; is_install_action=true ;;
        2) vless_reality_install; is_install_action=true ;;
        3) hysteria2_install; is_install_action=true ;;
        4) tuic_install; is_install_action=true ;;
        5) shadowsocks_install; is_install_action=true ;;
        6) socks_install; is_install_action=true ;;
        7) view_nodes ;;
        8) manage_nodes ;;
        9) manage_service "restart" ;;
        10) uninstall_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效输入，请重试。${NC}" ;;
    esac

    if [ "$is_install_action" = true ]; then
        echo "正在重启 sing-box 使配置生效..."
        manage_service "restart"
        sleep 1
        manage_service "status"
    fi
}

# --- 脚本入口 ---

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：本脚本需要以 root 权限运行！${NC}"
    exit 1
fi

# --- 初始化操作 (只执行一次) ---
check_and_install_deps
ensure_installation
initialize_config_files
get_local_ip

# --- 主循环 ---
while true; do
    main_menu
    # 退出或卸载的选项会在其函数内部通过 exit 终止脚本，不会执行到这里
    echo
    read -p "按任意键返回主菜单..."
done
