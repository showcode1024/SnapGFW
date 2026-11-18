# natgfw — KVM + LXC / runman-agent 专用 NAT DPI 防火墙与定制面板

`natgfw` 是一款用 Go 从头自研（**不依赖 OpenGFW、不修改 `runman-agent`**）的轻量化 NAT 宿主机深度包检测（DPI）防火墙与 Web 控制面板，专为切小鸡（特别是 `narwhal-cloud/runman-agent-rs` 环境下的 `rmbr0` + `rv*`/`rw*` 系统容器）设计。

---

## 核心特性

1. **精准接入 NAT `FORWARD` 链（不影响宿主机，完美支持 IPv4 / IPv6 / 独立 IP 隧道）**
   * 独立维护 `table inet natgfw`（挂载 `forward` 链 `priority filter + 10`），完全不修改 `runman-agent` 的 `inet runman` 与 `bridge runman`，每 30 秒自愈互不冲突。
   * 宿主机自身 `INPUT` / `OUTPUT` 与 SSH、面板管理流量完全不入队列，杜绝误锁宿主机。
   * 只读读取 `/var/lib/runman-agent/` 中的实例列表与 `portforwards.json`，自动将容器内网 IP 关联到实例 UUID、主机名和宿主机映射端口。
   * 4 队列编码方向（`200..203`），严格区分**外部入站（外部 → 容器）**与**容器出站（容器 → 外部）**。

2. **全协议手动可控 + 一键预设策略模板**
   * **可自由独立配置全部 15 类协议/检测器**（启停 / 动作`拦截|仅告警|放行` / 方向`入站|出站|双向` / 豁免端口 / 豁免实例 / 自定义域名）：
     * 全加密 TCP 代理：`Shadowsocks`、`Shadowsocks 2022 (TCP)`、原生 `VMess-TCP`（且封堵伪造 `GET`/`TLS` 前缀绕过）
     * 全加密 UDP 流量（可选开关，排除 DNS/QUIC/WG/OVPN/STUN/DTLS/NTP 后的高熵 UDP 检测）
     * 明文代理：`SOCKS4/4a/5`、`HTTP CONNECT` / 绝对 URI 正向代理
     * 明文 WebSocket：支持 `两阶段高熵检测`（按 RFC 6455 去掩码后判定，放行正常业务 WS、仅拦截套壳加密 VMess-WS）、`全封`、`仅告警`
     * `TLS SNI`（支持多 TLS Record 分片重组）与 `QUIC SNI`（RFC 9001 v1/v2 Initial 解密 + CRYPTO 重组，支持 Hysteria2 / TUIC / HTTP3）
     * `TLS 异常`：Fake TLS/HTTP Obfs、ECH/ESNI、无 SNI 的纯 IP TLS
     * `OpenVPN (TCP/UDP)`：校验双向 HardReset 与 8 字节 Session ID 回显，不误伤正常 DNS
     * `WireGuard (UDP)`：仅检查容器转发流量，不影响宿主机 `rw*` 隧道
     * `Trojan 启发式`、`SSH`、`HTTP 明文`、`DNS`、`BitTorrent / DHT P2P`
   * **一键策略预设库**：内置 `anti_blacklist`（防招黑）、`strict_block`（严格全封）、`audit_only`（纯审计观察）、`anti_abuse`（防滥用加固），导入后仍可随时单条微调与导出 JSON 跨机同步。

3. **L4 端口规则与防滥用限速（纯 `nftables` 内核执行）**
   * 自由添加任意 TCP/UDP/ICMP 端口或端口段规则，支持按租户 IP、宿主机映射端口（`ct original proto-dst`）、目标/源端口、CIDR 或 GeoIP 国家匹配。
   * 单实例并发连接上限（`ct count`）、新建速率限流、UDP PPS 限流，以及多次 L7 违规自动内核 `@quarantine` 临时隔离 + Telegram/Webhook 告警。

4. **低内存与高可用设计**
   * 流式按需解码 `geosite.dat` / `geoip.dat`（仅保留规则用到的分类为后缀 Trie 树），缺失文件时自动启用内置核心 CN 域名兜底。
   * 合规连接首包判定后立即下发 `ct mark` 走内核直通，用户态仅保留有界前缀缓冲与 LRU 流表；带 `queue ... bypass` 崩溃不阻断业务。

---

## 构建 Linux 二进制

在有 Go 1.24+ 环境的任意机器上交叉编译：

```bash
# 编译 Linux AMD64 静态二进制
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o natgfw-linux-amd64 ./cmd/natgfw

# 编译 Linux ARM64 静态二进制
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o natgfw-linux-arm64 ./cmd/natgfw
```

运行全量单元测试：

```bash
go test ./...
```

---

## 部署到 KVM 宿主机

### 一键快速安装（推荐）

在 KVM 宿主机（Debian / Ubuntu）以 `root` 用户执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/showcode1024/natgfw/main/install.sh) --disable-rfw --with-geo
```

如需面板仅监听本机并通过 SSH 隧道安全访问：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/showcode1024/natgfw/main/install.sh) --listen 127.0.0.1:9090 --disable-rfw --with-geo
```

### 使用本地编译产物安装

```bash
bash install.sh --from-bin ./natgfw-linux-amd64 --disable-rfw --with-geo
```

安装完成后会打印面板地址（默认 `http://<IP>:9090`）与初始随机密码（用户名 `admin`）。

---

## 常用运维命令

```bash
# 查看运行状态与实时日志
systemctl status natgfw
journalctl -u natgfw -f

# 查看内核 nftables 规则与命中计数
nft list table inet natgfw

# 重置面板密码
echo '你的新密码' | natgfw set-password

# 导出 / 导入策略模板
natgfw export-policy > my-policy.json
natgfw import-policy my-policy.json && systemctl reload natgfw

# 彻底卸载
bash <(curl -fsSL https://raw.githubusercontent.com/showcode1024/natgfw/main/install.sh) --uninstall --purge
```
