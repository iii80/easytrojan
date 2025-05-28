
#!/bin/sh

# EasyTrojan Alpine Edition - Alpine Linux 3.x Only

set -e

trojan_passwd=$1
caddy_domain=$2
address_ip=$(curl -s ipv4.ip.sb)
nip_domain="${address_ip}.sslip.io"
trojan_link="trojan://$trojan_passwd@$address_ip:443?security=tls&sni=$nip_domain&alpn=h2%2Chttp%2F1.1&fp=chrome&type=tcp#easytrojan-$address_ip"
base64_link=$(echo -n "$trojan_link" | base64 | tr -d '\n')

# 检查系统是否为 Alpine 3.x
if ! grep -qi 'alpine' /etc/os-release || ! grep -q '^VERSION_ID="3\.' /etc/os-release; then
    echo "Error: Only Alpine Linux 3.x is supported"
    exit 1
fi

# 检查必要参数
[ -z "$trojan_passwd" ] && { echo "Error: You must enter a trojan's password to run this script"; exit 1; }

# 检查是否为 root
[ "$(id -u)" != "0" ] && { echo "Error: You must be root to run this script"; exit 1; }

# 检查 80 和 443 端口是否被占用
check_port=$(netstat -tuln | grep -E ':80|:443')
[ -n "$check_port" ] && { echo "Error: Port 80 or 443 is already in use"; exit 1; }

# 安装依赖
apk add --no-cache curl bash grep sed net-tools iproute2 coreutils

# 检查域名解析
if [ -n "$caddy_domain" ]; then
    domain_ip=$(ping -c 1 "$caddy_domain" | sed -n '1{s/.*(\(.*\)).*/\1/;p}')
    [ "$domain_ip" != "$address_ip" ] && { echo "Error: Could not resolve hostname"; exit 1; }
    nip_domain=$caddy_domain
fi

# 下载并安装 Caddy
arch=$(uname -m)
case "$arch" in
    x86_64)   caddy_url=https://raw.githubusercontent.com/eastmaple/easytrojan/caddy/caddy_trojan_linux_amd64.tar.gz ;;
    aarch64)  caddy_url=https://raw.githubusercontent.com/eastmaple/easytrojan/caddy/caddy_trojan_linux_arm64.tar.gz ;;
    *)        echo "Error: Unsupported architecture $arch"; exit 1 ;;
esac

curl -L "$caddy_url" | tar -zx -C /usr/local/bin caddy
chmod +x /usr/local/bin/caddy

# 创建 caddy 用户
addgroup -S caddy
adduser -S -G caddy -s /sbin/nologin caddy

# 创建配置目录
mkdir -p /etc/caddy/trojan
chown -R caddy:caddy /etc/caddy
chmod 700 /etc/caddy

# 生成 Caddyfile
cat > /etc/caddy/Caddyfile <<EOF
{
    order trojan before respond
    https_port 443
    servers :443 {
        listener_wrappers {
            trojan
        }
        protocols h2 h1
    }
    servers :80 {
        protocols h1
    }
    trojan {
        caddy
        no_proxy
    }
}
:443, $nip_domain {
    tls $address_ip@tbcache.com {
        ciphers TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    }
    log {
        level ERROR
    }
    trojan {
        websocket
    }
    respond "Service Unavailable" 503 {
        close
    }
}
:80 {
    redir https://{host}{uri} permanent
}
EOF

# 添加 OpenRC 服务
cat > /etc/init.d/caddy <<'EOF'
#!/sbin/openrc-run

description="Caddy Web Server with Trojan plugin"
command=/usr/local/bin/caddy
command_args="run --environ --config /etc/caddy/Caddyfile"
pidfile=/run/caddy.pid
command_background=true

depend() {
    need net
    use dns
}
EOF

chmod +x /etc/init.d/caddy
rc-update add caddy default
rc-service caddy restart

# 向 Caddy 添加 Trojan 用户
curl -X POST -H "Content-Type: application/json" -d "{"password": "$trojan_passwd"}" http://localhost:2019/trojan/users/add
echo "$trojan_passwd" >> /etc/caddy/trojan/passwd.txt
sort /etc/caddy/trojan/passwd.txt | uniq > /etc/caddy/trojan/passwd.tmp
mv -f /etc/caddy/trojan/passwd.tmp /etc/caddy/trojan/passwd.txt

# 检查证书是否申请成功
echo "Obtaining and Installing an SSL Certificate..."
count=0
sslfail=0
until [ -d /etc/caddy/certificates ]; do
  count=$((count + 1))
  sleep 3
  [ "$count" -gt 20 ] && sslfail=1 && break
done

[ "$sslfail" = 1 ] && { echo "Certificate application failed, please check your server firewall and network settings"; exit 1; }

# 输出配置
clear
echo "You have successfully installed EasyTrojan for Alpine Linux 3.x"
echo "Trojan Address:" | tee /etc/caddy/trojan.link
echo "$nip_domain | Port: 443 | Password: $trojan_passwd | Alpn: h2,http/1.1" | tee -a /etc/caddy/trojan.link
echo "Trojan Link:" | tee -a /etc/caddy/trojan.link
echo "$trojan_link" | tee -a /etc/caddy/trojan.link
echo "Base64 Trojan Link (for QR or sharing):" | tee -a /etc/caddy/trojan.link
echo "https://autoxtls.github.io/base64.html#$base64_link" | tee -a /etc/caddy/trojan.link
