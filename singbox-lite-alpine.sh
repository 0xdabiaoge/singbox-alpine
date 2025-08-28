#!/bin/bash

# --- 全局变量和样式 ---
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
YAML_FILE="/usr/local/etc/sing-box/clash.yaml"
PID_FILE="/var/run/sing-box.pid"
META_FILE="/usr/local/etc/sing-box/metadata.json"
server_ip=""

# --- 系统与依赖函数 ---

function check_and_install_deps() {
    if [ ! -f /etc/alpine-release ]; then
        echo -e "${YELLOW}警告: 此脚本专为 Alpine Linux 设计, 但仍会尝试运行。${NC}"
    fi
    echo "正在检查并安装所需依赖 ..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl procps" # procps provides `ps`
    for pkg in $required_pkgs; do
        if ! apk -e info "$pkg" >/dev/null 2>&1; then
            pkgs_to_install="$pkgs_to_install $pkg"
        fi
    done
    if [ -n "$pkgs_to_install" ]; then
        echo "正在安装缺失的依赖: $pkgs_to_install"
        if ! apk update || ! apk add --no-cache $pkgs_to_install; then
            echo -e "${RED}依赖安装失败，请手动执行 'apk add $pkgs_to_install' 后重试。${NC}"
            exit 1
        fi
    else
        echo "所有依赖均已满足。"
    fi
}

# --- 服务管理 (PID) ---

function is_running() {
    if [ -f "$PID_FILE" ] && [ -n "$(cat "$PID_FILE")" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
        return 0 # 正在运行
    fi
    return 1 # 未运行
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
            mkdir -p /var/run
            nohup /usr/local/bin/sing-box run -c "$CONFIG_FILE" >/dev/null 2>&1 &
            echo $! > "$PID_FILE"
            sleep 1
            if is_running; then
                echo -e "${CYAN}sing-box 启动成功 (PID: $(cat "$PID_FILE"))。${NC}"
            else
                echo -e "${RED}sing-box 启动失败。请检查配置文件或手动运行进行调试:${NC}"
                echo "/usr/local/bin/sing-box run -c $CONFIG_FILE"
            fi
            ;;
        stop)
            if ! is_running; then
                echo -e "${YELLOW}sing-box 未在运行。${NC}"
                return
            fi
            echo "正在停止 sing-box (PID: $(cat "$PID_FILE"))..."
            kill "$(cat "$PID_FILE")"
            rm -f "$PID_FILE"
            sleep 1
            echo -e "${CYAN}sing-box 已停止。${NC}"
            ;;
        restart)
            manage_service "stop"
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
    server_ip=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip)
    if [ -z "$server_ip" ]; then
        echo "未能获取 IPv4 地址, 正在尝试 IPv6..."
        server_ip=$(curl -s6 --max-time 2 icanhazip.com || curl -s6 --max-time 2 ipinfo.io/ip)
    fi

    if [ -z "$server_ip" ]; then
        echo -e "${RED}无法获取本机的公网 IP 地址！请检查网络连接。${NC}"
        exit 1
    fi
    echo "本机公网 IP 地址: $server_ip"
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
    mv "$temp_dir/sing-box-"*"/sing-box" /usr/local/bin/
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x /usr/local/bin/sing-box
    echo "sing-box 安装成功。"
}

function initialize_config_files() {
    mkdir -p /usr/local/etc/sing-box
    if [ ! -s "$CONFIG_FILE" ] || ! jq -e . "$CONFIG_FILE" >/dev/null 2>&1; then
        echo '{"log":{"level":"info","timestamp":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONFIG_FILE"
    fi
    if [ ! -s "$META_FILE" ]; then
        echo "{}" > "$META_FILE"
    fi
    if [ ! -s "$YAML_FILE" ]; then
        echo "正在创建全新的 clash.yaml 配置文件..."
        cat > "$YAML_FILE" << 'EOF'
mixed-port: 7890
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: true
external-controller: 127.0.0.1:9090
proxies:
proxy-groups:
  - name: Proxy
    type: select
    proxies:
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
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
    echo "正在为 www.microsoft.com 生成自签名证书..."
    openssl ecparam -genkey -name prime256v1 -out "$key_path"
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=www.microsoft.com"
    echo "自签名证书生成成功。"
}

# --- YAML 配置生成 ---
function append_yaml_config() {
    local node_type=$1
    shift
    local proxy_name=""
    local proxy_block=""
    local display_ip="$server_ip"
    if [[ "$server_ip" == *":"* ]]; then
        display_ip="[$server_ip]"
    fi

    case $node_type in
        "vless-reality")
            local port=$1 uuid=$2 server_name=$3 public_key=$4 short_id=$5
            proxy_name="vless-reality-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: vless
    server: ${display_ip}
    port: ${port}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${server_name}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${public_key}
      short-id: ${short_id}
EOF
)
            ;;
        "hysteria2")
            local port=$1 password=$2 obfs_password=$3 up_speed=$4 down_speed=$5
            proxy_name="hysteria2-${port}"
            local obfs_block=""
            if [ -n "$obfs_password" ]; then
                obfs_block=$(cat <<EOF
    obfs: salamander
    obfs-password: ${obfs_password}
EOF
)
            fi
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: hysteria2
    server: ${display_ip}
    port: ${port}
    password: ${password}
${obfs_block}
    alpn:
      - h3
    sni: www.microsoft.com
    skip-cert-verify: true
    up: "${up_speed}"
    down: "${down_speed}"
EOF
)
            ;;
        "tuic")
            local port=$1 uuid=$2 password=$3
            proxy_name="tuic-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: tuic
    server: ${display_ip}
    port: ${port}
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
            local port=$1 method=$2 password=$3
            proxy_name="ss-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: ss
    server: ${display_ip}
    port: ${port}
    cipher: ${method}
    password: ${password}
EOF
)
            ;;
        "socks")
            local port=$1 username=$2 password=$3
            proxy_name="socks-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: socks5
    server: ${display_ip}
    port: ${port}
    username: ${username}
    password: ${password}
EOF
)
            ;;
    esac
    
    # 使用 awk 在 proxies: 下方插入节点配置
    awk -v block="$proxy_block" '1; /^proxies:$/ {print block}' "$YAML_FILE" > "${YAML_FILE}.tmp" && mv "${YAML_FILE}.tmp" "$YAML_FILE"
    # 使用 sed 在 Proxy 组中添加新的节点名
    sed -i "/- name: Proxy/,/proxies:/s/proxies:/proxies:\n    - ${proxy_name}/" "$YAML_FILE"
    echo "Clash YAML 配置文件已更新。"
}

# --- 节点搭建函数 ---

function vless_reality_install() {
    echo "--- 正在配置 VLESS (REALITY) 节点 ---"
    read -p "请输入监听端口: " listen_port
    read -p "请输入 UUID (默认随机): " uuid; uuid=${uuid:-$(sing-box generate uuid)}
    read -p "请输入伪装域名 (默认 www.microsoft.com): " server_name; server_name=${server_name:-"www.microsoft.com"}
    
    local keypair=$(sing-box generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(sing-box generate rand --hex 8)
    local tag="vless-reality-in-${listen_port}"

    local new_inbound=$(jq -n \
        --arg tag "$tag" --arg listen_port "$listen_port" --arg uuid "$uuid" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" \
        '{"type":"vless","tag":$tag,"listen":"::","listen_port":($listen_port|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$server_name,"reality":{"enabled":true,"handshake":{"server":$server_name,"server_port":443},"private_key":$private_key,"short_id":[$short_id]}}}')
    
    jq --argjson inbound "$new_inbound" '.inbounds += [$inbound]' "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    jq --arg tag "$tag" --arg pk "$public_key" --arg sid "$short_id" '. + {($tag): {"publicKey": $pk, "shortId": $sid}}' "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"
    append_yaml_config "vless-reality" "$listen_port" "$uuid" "$server_name" "$public_key" "$short_id"
    
    echo -e "${CYAN}VLESS (REALITY) 节点添加成功!${NC}"
}

function hysteria2_install() {
    echo "--- 正在配置 Hysteria2 (自签证书) 节点 ---"
    generate_self_signed_cert
    read -p "请输入监听端口: " listen_port
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    read -p "请输入上传速度 (默认 50 Mbps): " up_speed; up_speed=${up_speed:-"50 Mbps"}
    read -p "请输入下载速度 (默认 200 Mbps): " down_speed; down_speed=${down_speed:-"200 Mbps"}

    local obfs_password=""
    read -p "是否开启 QUIC 流量混淆? (y/N): " enable_obfs
    if [[ "$enable_obfs" == "y" || "$enable_obfs" == "Y" ]]; then
        read -p "请输入混淆密码 (默认随机): " obfs_password; obfs_password=${obfs_password:-$(sing-box generate rand --hex 16)}
    fi

    local tag="hy2-in-${listen_port}"

    local new_inbound_object=$(jq -n \
        --arg tag "$tag" --arg listen_port "$listen_port" --arg password "$password" --arg obfs_pass "$obfs_password" \
        '
        {
            "type": "hysteria2", "tag": $tag, "listen": "::", "listen_port": ($listen_port | tonumber),
            "users": [{"password": $password}],
            "tls": {
                "enabled": true, "alpn": ["h3"],
                "certificate_path": "/usr/local/etc/sing-box/cert.pem",
                "key_path": "/usr/local/etc/sing-box/private.key"
            }
        } | if $obfs_pass != "" and $obfs_pass != null then .obfs = {"type": "salamander", "password": $obfs_pass} else . end
        '
    )
    
    jq --argjson inbound "$new_inbound_object" '.inbounds += [$inbound]' "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    
    local meta_data_object=$(jq -n \
        --arg up "$up_speed" --arg down "$down_speed" --arg obfs_pass "$obfs_password" \
        '{ "up": $up, "down": $down } | if $obfs_pass != "" and $obfs_pass != null then .obfsPassword = $obfs_pass else . end'
    )
    jq --arg tag "$tag" --argjson data "$meta_data_object" '. + {($tag): $data}' "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"
    append_yaml_config "hysteria2" "$listen_port" "$password" "$obfs_password" "$up_speed" "$down_speed"

    echo -e "${CYAN}Hysteria2 节点添加成功!${NC}"
}

function tuic_install() {
    echo "--- 正在配置 TUICv5 (自签证书) 节点 ---"
    generate_self_signed_cert
    read -p "请输入监听端口: " listen_port
    read -p "请输入 UUID (默认随机): " uuid; uuid=${uuid:-$(sing-box generate uuid)}
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    local tag="tuic-in-${listen_port}"

    local new_inbound=$(jq -n \
        --arg tag "$tag" --arg listen_port "$listen_port" --arg uuid "$uuid" --arg password "$password" \
        '{"type":"tuic","tag":$tag,"listen":"::","listen_port":($listen_port|tonumber),"users":[{"uuid":$uuid,"password":$password}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/usr/local/etc/sing-box/cert.pem","key_path":"/usr/local/etc/sing-box/private.key"}}')

    jq --argjson inbound "$new_inbound" '.inbounds += [$inbound]' "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "tuic" "$listen_port" "$uuid" "$password"
    echo -e "${CYAN}TUICv5 节点添加成功!${NC}"
}

function shadowsocks_install() {
    echo "--- 正在配置 Shadowsocks (aes-256-gcm) 节点 ---"
    read -p "请输入监听端口: " listen_port
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    local tag="ss-in-${listen_port}"
    local ss_method="aes-256-gcm"

    local new_inbound=$(jq -n \
        --arg tag "$tag" --arg listen_port "$listen_port" --arg method "$ss_method" --arg password "$password" \
        '{"type":"shadowsocks","tag":$tag,"listen":"::","listen_port":($listen_port|tonumber),"method":$method,"password":$password}')

    jq --argjson inbound "$new_inbound" '.inbounds += [$inbound]' "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "shadowsocks" "$listen_port" "$ss_method" "$password"
    echo -e "${CYAN}Shadowsocks 节点添加成功!${NC}"
}

function socks_install() {
    echo "--- 正在配置 SOCKS5 节点 ---"
    read -p "请输入监听端口: " listen_port
    read -p "请输入用户名 (默认随机): " username; username=${username:-$(sing-box generate rand --hex 8)}
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    local tag="socks-in-${listen_port}"

    local new_inbound=$(jq -n \
        --arg tag "$tag" --arg listen_port "$listen_port" --arg username "$username" --arg password "$password" \
        '{"type":"socks","tag":$tag,"listen":"::","listen_port":($listen_port|tonumber),"users":[{"username":$username,"password":$password}]}')

    jq --argjson inbound "$new_inbound" '.inbounds += [$inbound]' "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "socks" "$listen_port" "$username" "$password"
    echo -e "${CYAN}SOCKS5 节点添加成功!${NC}"
}

# --- 管理功能 ---

function view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${YELLOW}当前没有任何已配置的节点。${NC}"
        return
    fi
    
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE")
    echo "--- 当前节点信息 (共 $node_count 个) ---"

    jq -r '.inbounds[].tag' "$CONFIG_FILE" | while read -r tag; do
        local node=$(jq --arg tag "$tag" '.inbounds[] | select(.tag == $tag)' "$CONFIG_FILE")
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        
        local display_ip="$server_ip"
        if [[ "$server_ip" == *":"* ]]; then
            display_ip="[$server_ip]"
        fi

        echo "-------------------------------------"
        echo -e " ${CYAN}节点: ${tag}${NC}"
        
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local server_name=$(echo "$node" | jq -r '.tls.server_name')
                local flow=$(echo "$node" | jq -r '.users[0].flow')
                local meta_info=$(jq -r --arg tag "$tag" '.[$tag]' "$META_FILE")
                local public_key=$(echo "$meta_info" | jq -r '.publicKey')
                local short_id=$(echo "$meta_info" | jq -r '.shortId')
                url="vless://${uuid}@${display_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${server_name}&fp=chrome&flow=${flow}&pbk=${public_key}&sid=${short_id}#$(url_encode "$tag")"
                ;;
            "hysteria2")
                local password=$(echo "$node" | jq -r '.users[0].password')
                local meta_info=$(jq -r --arg tag "$tag" '.[$tag]' "$META_FILE")
                local obfs_password=$(echo "$meta_info" | jq -r '.obfsPassword')
                local obfs_param=""
                if [[ -n "$obfs_password" && "$obfs_password" != "null" ]]; then
                    obfs_param="&obfs=salamander&obfs-password=${obfs_password}"
                fi
                url="hysteria2://${password}@${display_ip}:${port}?sni=www.microsoft.com&insecure=1${obfs_param}#$(url_encode "$tag")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local password=$(echo "$node" | jq -r '.users[0].password')
                url="tuic://${uuid}:${password}@${display_ip}:${port}?sni=www.microsoft.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(url_encode "$tag")"
                ;;
            "shadowsocks")
                local method=$(echo "$node" | jq -r '.method')
                local password=$(echo "$node" | jq -r '.password')
                local b64_part=$(echo -n "${method}:${password}" | base64 | tr -d '\n')
                url="ss://${b64_part}@${display_ip}:${port}#$(url_encode "$tag")"
                ;;
            "socks")
                local username=$(echo "$node" | jq -r '.users[0].username')
                local password=$(echo "$node" | jq -r '.users[0].password')
                echo "  类型: SOCKS5, 地址: $server_ip, 端口: $port"
                echo "  用户: $username, 密码: $password"
                ;;
        esac

        if [ -n "$url" ]; then
            echo -e "  ${YELLOW}分享链接:${NC} ${url}"
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
    if [[ ! "$node_num" =~ ^[0-9]+$ ]] || [ "$node_num" -eq 0 ]; then return; fi
    
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$node_num" -gt "$node_count" ]; then echo -e "${RED}编号超出范围。${NC}"; return; fi

    local index_to_delete=$((node_num - 1))
    local tag_to_delete=$(jq -r ".inbounds[${index_to_delete}].tag" "$CONFIG_FILE")
    local port_to_delete=$(jq -r ".inbounds[${index_to_delete}].listen_port" "$CONFIG_FILE")
    local type_to_delete=$(jq -r ".inbounds[${index_to_delete}].type" "$CONFIG_FILE")
    
    # 从主配置和元数据删除
    jq "del(.inbounds[${index_to_delete}])" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    jq "del(.\"$tag_to_delete\")" "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"
    
    # 从 YAML 删除
    local proxy_name_to_delete
    case "$type_to_delete" in
        "vless") proxy_name_to_delete="vless-reality-${port_to_delete}" ;;
        "hysteria2") proxy_name_to_delete="hysteria2-${port_to_delete}" ;;
        "tuic") proxy_name_to_delete="tuic-${port_to_delete}" ;;
        "shadowsocks") proxy_name_to_delete="ss-${port_to_delete}" ;;
        "socks") proxy_name_to_delete="socks-${port_to_delete}" ;;
    esac

    if [ -n "$proxy_name_to_delete" ]; then
        # 从 proxies 列表删除
        awk -v name="$proxy_name_to_delete" '
            BEGIN {p=1} 
            $0 ~ "- name: " name {p=0; next} 
            !p && NF==0 {p=1; next} 
            p' "$YAML_FILE" > "${YAML_FILE}.tmp" && mv "${YAML_FILE}.tmp" "$YAML_FILE"
        # 从 proxy-groups 列表删除
        sed -i "/- ${proxy_name_to_delete}/d" "$YAML_FILE"
    fi

    echo -e "${CYAN}节点 ${tag_to_delete} 已删除！正在重启服务...${NC}"
    manage_service "restart"
}

function uninstall_script() {
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
    rm -f "$0"
    echo "脚本已自毁。再见！"
    exit 0
}

# --- 主菜单 ---
function main_menu() {
    clear
    echo "sing-box Alpine 安装脚本 "
    echo "=========================================="
    echo "--- 安装选项 ---"
    echo -e " ${CYAN}1)${NC} VLESS (REALITY)"
    echo -e " ${CYAN}2)${NC} Hysteria2 "
    echo -e " ${CYAN}3)${NC} TUICv5 "
    echo -e " ${CYAN}4)${NC} Shadowsocks (aes-256-gcm)"
    echo -e " ${CYAN}5)${NC} SOCKS5"
    echo "--- 管理选项 ---"
    echo -e " ${YELLOW}6)${NC} 查看节点分享链接"
    echo -e " ${YELLOW}7)${NC} 管理节点 (删除节点)"
    echo -e " ${YELLOW}8)${NC} 重启 sing-box 服务"
    echo -e " ${YELLOW}9)${NC} 卸载 sing-box"
    echo -e " ${YELLOW}0)${NC} 退出脚本"
    echo "=========================================="
    read -p "请输入选项 [0-9]: " choice

    local needs_restart=false
    case $choice in
        1) vless_reality_install; needs_restart=true ;;
        2) hysteria2_install; needs_restart=true ;;
        3) tuic_install; needs_restart=true ;;
        4) shadowsocks_install; needs_restart=true ;;
        5) socks_install; needs_restart=true ;;
        6) view_nodes ;;
        7) manage_nodes ;;
        8) manage_service "restart" ;;
        9) uninstall_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效输入，请重试。${NC}" ;;
    esac

    if [ "$needs_restart" = true ]; then
        echo "配置已更新，正在重启 sing-box..."
        manage_service "restart"
    fi
}

# --- 脚本入口 ---

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：本脚本需要以 root 权限运行！${NC}"
    exit 1
fi

if [ ! -f /usr/local/bin/sing-box ]; then
    check_and_install_deps
    install_sing_box
    initialize_config_files
    get_local_ip
else
    get_local_ip
fi

while true; do
    main_menu
    echo
    read -n 1 -s -r -p "按任意键返回主菜单..."
done
