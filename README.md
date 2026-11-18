# SnapGFW — KVM + LXC / runman-agent 专用轻量 NAT DPI 防火墙

`SnapGFW` 是一款用 Go 从头自研（**不依赖 OpenGFW、不修改 `runman-agent`**）的轻量化 NAT 宿主机深度包检测（DPI）防火墙与极简 Web 控制面板，专为 `narwhal-cloud/runman-agent-rs` 环境下的 `rmbr0` + `rv*`/`rw*` 系统容器设计。

---

## 核心特性

1. **初始零拦截 + 唯一「防滥用」推荐策略可选导入**
   * 首次启动默认策略完全为空（全部 16 类协议与 L4 端口规则默认关闭，直接内核直通、零误杀）。
   * 面板内置 **防滥用 (`anti_abuse`)** 统一推荐策略一键导入：合并防招黑与防滥用能力（入站阻断 SS / SS-2022 / VMess-TCP、SOCKS、HTTP 代理、高熵 WS、OpenVPN 与国内 SNI 伪装，出站拦截 Stratum 挖矿 / 矿池、BT/P2P，封禁 SMTP 发信与常见矿池端口并启用连接限速）；放行海外正常 HTTPS / Reality。
   * 导入推荐策略后仍可逐条启用/停用、修改动作（拦截 / 仅记录 / 放行）、方向、例外端口与例外租户 IP。

2. **极度克制的日志与内存占用 + 面板在线更新**
   * **RAM 严格封顶**：内存日志环默认仅保留最新 `200` 条事件（`--low-mem` 模式为 `100` 条），合流首次识别即下发 `ct mark` 走内核直通。
   * **ROM 严格封顶**：审计文件 `audit.jsonl` 单文件上限 `2 MiB`、最多保留 `1` 份轮转备份，磁盘总占用严格 `≤ 4 MiB`（`--low-mem` 为 `≤ 2 MiB`）；突发同类拦截在 3 秒窗口内仅计总数不刷盘。
   * **面板自更新**：可在「系统 → 版本更新」检查并执行 SHA-256 校验更新（更新重启期间保持现有内核 `nftables` 防护不断流）。

3. **精准接入 NAT `FORWARD` 链（不影响宿主机与 `runman-agent`）**
   * 独立维护 `table inet snapgfw`（`forward` 链 `priority filter + 10`），只读读取 `/var/lib/runman-agent/` 映射实例与端口转发。
   * 全空默认策略下自动跳过用户态 `NFQUEUE` 排队，零额外 CPU 开销。

---

## 构建 Linux 二进制

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o snapgfw-linux-amd64 ./cmd/snapgfw
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o snapgfw-linux-arm64 ./cmd/snapgfw
go test ./...
```

---

## 部署到 KVM 宿主机

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/showcode1024/SnapGFW/main/install.sh) --disable-rfw --with-geo
```

面板仅监听本机（通过 SSH 隧道访问）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/showcode1024/SnapGFW/main/install.sh) --listen 127.0.0.1:9090 --disable-rfw --with-geo
```

使用本地编译产物：

```bash
bash install.sh --from-bin ./snapgfw-linux-amd64 --disable-rfw --with-geo
```

---

## 常用运维命令

```bash
systemctl status snapgfw
nft list table inet snapgfw
echo '你的新密码' | snapgfw set-password
snapgfw export-policy > my-policy.json
snapgfw import-policy my-policy.json && systemctl reload snapgfw
bash <(curl -fsSL https://raw.githubusercontent.com/showcode1024/SnapGFW/main/install.sh) --uninstall --purge
```
