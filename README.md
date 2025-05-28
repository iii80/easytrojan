![language](https://img.shields.io/badge/language-Shell_&_Go-brightgreen.svg)
![release](https://img.shields.io/badge/release-v3.0_20231108-blue.svg)
# EasyTrojan v3.0 #

#### 世界上最简单的Trojan部署脚本，仅需一行命令即可搭建一台代理服务器 ####

- 该项目会自动提供trojan服务所需的免费域名与证书，无需购买、解析等繁琐操作

- 支持RHEL 7、8、9 (CentOS、RedHat、AlmaLinux、RockyLinux)、Debian 9、10、11、12、Ubuntu 16、18、20、22

- 该项目仅限研究用途，用户应根据所在管辖区的当地法律评估自己的法规遵从义务

---

#### 首次安装 ####
请将结尾的password更换为自己的密码，例如 bash easytrojan.sh 123456，安装成功后会返回trojan的连接参数
```
curl https://raw.githubusercontent.com/autoxtls/easytrojan/main/easytrojan.sh -o easytrojan.sh && chmod +x easytrojan.sh && bash easytrojan.sh password
```

#### 放行端口 ####
如果服务器开启了防火墙，应放行TCP80与443端口，如在云厂商的web管理页面有防火墙应同时放行TCP80与443端口
```
# RHEL 7、8、9 (CentOS、RedHat、AlmaLinux、RockyLinux) 放行端口命令
firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp && firewall-cmd --reload && iptables -F

# Debian 9、10、11、12、Ubuntu 16、18、20、22 放行端口命令
sudo ufw allow proto tcp from any to any port 80,443 && sudo iptables -F
```
> 验证端口是否放行 (示例IP应修改为trojan服务器的IP)
>
> 通过浏览器访问脚本提供的免费域名，例如1.3.5.7.nip.io </br>
> 如果自动跳转至https，页面显示Service Unavailable，说明端口已放行

#### 密码管理 ####
请将结尾的password更换为自己的密码，仅限字母、数字、下划线，非多密码管理用途无需使用
```
# 下载trojan密码管理脚本
curl https://raw.githubusercontent.com/autoxtls/easytrojan/main/mytrojan.sh -o mytrojan.sh && chmod +x mytrojan.sh

# 创建密码
bash mytrojan.sh add password

# 一次创建多个密码示例
bash mytrojan.sh add password1 password2 ...

# 删除密码
bash mytrojan.sh del password

# 一次删除多个密码示例
bash mytrojan.sh del password1 password2 ...

# 流量查询
bash mytrojan.sh status password1 password2 ...

# 流量归零
bash mytrojan.sh rotate
*流量统计归零后会自动在/etc/caddy/trojan/data目录下生成历史记录

# 密码列表
bash mytrojan.sh list
```

#### 重新安装 ####
```
systemctl stop caddy.service && curl https://raw.githubusercontent.com/autoxtls/easytrojan/main/easytrojan.sh -o easytrojan.sh && chmod +x easytrojan.sh && bash easytrojan.sh password
```

#### 完全卸载 ####
```
systemctl stop caddy.service && systemctl disable caddy.service && rm -rf /etc/caddy /usr/local/bin/caddy /etc/systemd/system/caddy.service
```

---

#### 脚本说明 ####
- 注意事项

```
必须使用root用户部署

请勿修改配置文件参数
```

- 免费域名

```
通过tbcache.com提供的免费域名解析服务获取
例如：
ip518200520.mobgslb.tbcache.com
```

- 指定域名

仅建议在免费域名被阻断时使用
```
在密码后加入域名即可指定域名重新安装，密码与域名之间应使用空格分隔，执行命令如下：
systemctl stop caddy.service && curl https://raw.githubusercontent.com/autoxtls/easytrojan/main/easytrojan.sh -o easytrojan.sh && chmod +x easytrojan.sh && bash easytrojan.sh password yourdomain

*当指定域名后，如需切换回免费域名，必须完全卸载脚本，重新执行首次安装命令
```

- 更换端口

仅建议在443端口被阻断时临时使用
```
# 将443端口更换为8443端口示例
sed -i "s/443/8443/g" /etc/caddy/Caddyfile && systemctl restart caddy.service

*更换端口后应开启对应端口的防火墙
*当测试临时端口超过48小时未阻断后，应尽快更换IP并重新安装，使用默认的443端口
```

- 免费证书

```
通过Caddy的HTTPS模块实现，会自动申请letsencrypt或zerossl的免费证书

*关闭防火墙后执行重新安装命令，能大概率解决证书申请失败的问题

# RHEL 7、8、9 (CentOS、RedHat、AlmaLinux、RockyLinux)
systemctl stop firewalld.service && systemctl disable firewalld.service

# Debian 9、10、11、Ubuntu 16、18、20、22
sudo ufw disable
```

- 连接参数

IP为1.3.5.7 密码为123456的服务器示例
```
地址：ip***.mobgslb.tbcache.com  #根据服务器IP生成（即免费域名）
端口：443
密码：123456          #安装时设置的密码
ALPN: h2/http1.1
```

- 服务伪装

```
非密码正确的trojan客户端访问返回503状态，将trojan伪装成过载的Web服务
```

---

#### 鸣谢项目 ####
[EasyTrojan](https://github.com/eastmaple/easytrojan) </br>
[CaddyServer](https://github.com/caddyserver/caddy) </br>
[CaddyTrojan](https://github.com/imgk/caddy-trojan)
