# 安装与运维

## 支持范围

- Ubuntu/Debian；
- `x86_64`（发布名 `amd64`）与 `arm64`；
- systemd；
- 原生单机、原生多机和 Docker 只读观察模式。

其他发行版可以从源码构建，但尚不属于安装器承诺的测试范围。

原生 Agent 的临时封禁 Playbook 固定调用发行版提供的 `/usr/sbin/nft`。安装器发现缺少该文件时会通过 APT 安装 `nftables`；包修复依赖系统已有的 APT/DPKG。SSH 加固只在主机原本安装了 `openssh-server`、存在 `/usr/sbin/sshd` 时可用，妙盾不会为了启用该 Playbook 擅自安装或启动 SSH 服务。

## 安装前准备

- 保留可用备份和带外控制台；
- 确认管理员不会只依赖即将修改的唯一 SSH 会话；
- 确认系统时间同步；
- 单机模式不需要开放端口，默认用 SSH Tunnel 访问；
- 多机 Controller 通常只对外开放 HTTPS `443`，Agent 不需要入站端口；
- 决定可信的 AI 上游；未决定时先不配置，不影响规则扫描。

## 推荐：审阅后安装

```bash
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://github.com/witkitlab/witshield/releases/latest/download/install.sh
less install.sh
sudo bash install.sh --mode standalone --require-signature
```

签名校验现在始终强制执行；`--require-signature` 仅为兼容旧命令保留。本机没有 `/usr/local/bin/cosign` 或 `/usr/bin/cosign` 时，安装器会临时下载固定版本的 Cosign，并用脚本内分别为 amd64、arm64 固定的 SHA-256 校验后才执行。仓库同时启用 GitHub Immutable Releases，已公开 Release 的资产和关联 tag 不可替换。

上面的“先看脚本”流程仍把首次信任交给人工审阅。需要可验证的引导链时，先下载同一 Release 的脚本、校验表和签名 bundle，再执行：

```bash
release=https://github.com/witkitlab/witshield/releases/latest/download
curl --proto '=https' --tlsv1.2 -fsSLO "$release/install.sh"
curl --proto '=https' --tlsv1.2 -fsSLO "$release/SHA256SUMS"
curl --proto '=https' --tlsv1.2 -fsSLO "$release/SHA256SUMS.bundle"
cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp \
    '^https://github.com/witkitlab/witshield/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
grep '  install.sh$' SHA256SUMS | sha256sum --check -
less install.sh
sudo bash install.sh --mode standalone --require-signature
```

网页生成的“一行命令”是便利入口：它改用不可变正式 Release 的 `install.sh`，脚本再强制校验二进制归档和 Sigstore 身份，但管道本身无法在执行前验证安装脚本。高保证环境应使用上面的分步流程。

### 安装模式

```bash
# Controller + 本机 Agent
sudo bash install.sh --mode standalone

# 仅多机 Controller
sudo bash install.sh --mode controller

# 新设备：推荐把控制台生成的一次性 token 写入 root-only 文件
sudo install -o root -g root -m 0600 /dev/null /etc/witshield-enrollment.token
sudoedit /etc/witshield-enrollment.token
sudo bash install.sh --mode agent \
  --controller-url https://shield.example.com \
  --enrollment-token-file /etc/witshield-enrollment.token
sudo rm -f -- /etc/witshield-enrollment.token
```

Agent 把 token 复制到只有 `witshield-agent` 可读的临时文件，注册成功后用独立设备凭据替代并删除临时文件。

## 网页“一行命令”接入

控制台会生成 15 分钟过期、只能消费一次的设备 token。为了实现网页内的一行安装，可使用：

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/witkitlab/witshield/releases/latest/download/install.sh \
  | sudo env \
      WITSHIELD_CONTROLLER_URL='https://shield.example.com' \
      WITSHIELD_ENROLLMENT_TOKEN='<15分钟、单次使用的token>' \
      bash -s -- --mode agent
```

这条命令为了易用性把短期 token 放进 shell 命令历史，并在安装期间短暂出现在进程参数/环境观察面。安装器会立即从自身环境删除它，不传给下载和 systemd 子进程，只写入 `0600` 临时文件；Controller 消费一次后即失效。对历史留存严格的环境请使用上一节的 token-file 方法。

`--hub URL` 是 `--controller-url URL` 的兼容别名；`--token` 被明确拒绝，避免把秘密长期放在普通命令参数里。

## 首次初始化

Controller 默认监听 `127.0.0.1:8080`。远程操作时先建立 Tunnel：

```bash
ssh -L 8080:127.0.0.1:8080 admin@server
```

打开 `http://127.0.0.1:8080`。首次安装生成 256-bit bootstrap token 并写入 `/var/lib/witshield/bootstrap.token`（`0600`）。读取一次完成管理员创建：

```bash
sudo cat /var/lib/witshield/bootstrap.token
```

管理员密码至少 12 个字符。初始化成功后删除 token 文件并重启：

```bash
sudo rm -f -- /var/lib/witshield/bootstrap.token
sudo systemctl restart witshield-controller
```

不要把 bootstrap token 复用为设备 enrollment token。单机安装器内部会创建另一枚 15 分钟、单次使用的随机设备 token，让本机 Agent 自动注册；Controller 和 Agent 各自读取后删除明文副本。

## 日常检查

```bash
systemctl status witshield-controller witshield-helper witshield-agent
journalctl -u witshield-controller -u witshield-helper -u witshield-agent --since today
curl --fail http://127.0.0.1:8080/healthz
```

日志分享前检查 IP、用户名、路径、Finding 证据和上游错误。正常日志不应出现 API Key、会话 Cookie、bootstrap/enrollment token 或设备身份凭据。

原生 Agent 默认通过固定的 `/usr/bin/journalctl` 增量读取 `ssh`/`sshd` 认证失败并持久化 cursor；只有带受信 unit 字段的 journald 事件可以进入自动防御判定。journald 不可用时回退 `/var/log/auth.log`，但平面文本无法证明写入进程身份，因此只显示为非可信观察/告警，绝不自动封禁。回退读取器把偏移绑定到文件 device/inode，并在轮转后增加本地 generation；超过 256 KiB 的异常单行会以每轮最多 4 MiB 的进度丢弃到下一个换行，同时留下“未验证、不可触发动作”的安全观察，不会永久卡住后续日志。控制台通过管理员只读接口 `GET /api/v1/security-events` 分页查看这类事件（`limit` 为 1–100，可按 `deviceId`、`type` 过滤并使用 `cursor` 翻页）。安装器只在系统已有 `systemd-journal`/`adm` 组时授予相应只读组，不安装 rsyslog。若策略页面提示事件源不可用，先检查组权限、journal unit 名称与 `WITSHIELD_AUTH_LOG`，不要为修复可见性而让 Agent 以 root 运行。

当单台设备的 SSH 来源关联窗口达到 2,000 条安全上限时，Controller 会保留当前正在更新的来源、按优先级淘汰较旧窗口，并写入 `defense_correlation_capacity_degraded` 严重事件。该事件是容量健康信号，不是攻击证据，也绝不会直接授权自动动作；管理员应检查异常高基数来源与 Agent/Controller 资源使用情况。

通知事件先写入 Controller SQLite outbox，再由 Webhook、SMTP 两个独立 worker 发送。失败使用有界退避，进程重启后继续；修改渠道配置会取消旧配置下尚未发送的项，避免把历史敏感事件误投到新端点。终态投递记录保留 30 天。报告按设备最多保留最近 100 份，同时受每设备 20 MiB 报告内容预算约束，因此大型报告可能更早淘汰；安全事件按设备最多 2,000 条且最长 7 天。这些上限用于防止单个失陷设备耗尽控制台磁盘。

Agent 请求体最多 4 MiB，并同时受三层资源预算约束：单来源 600 次/分钟（IPv6 按 `/64` 聚合）、认证后单设备 120 次/分钟且全局 20,000 次/分钟，以及按请求体和条目数计费的单设备 2,500、全局 20,000 工作单位/分钟。全局请求预算在写入防重放 nonce 之前扣除，因此多设备不能绕过 Controller 总量边界。注册 challenge 与最终注册分别按来源限制为 120 次/10 分钟；两步预算彼此隔离。Controller 最多并行处理 8 个 Agent 写入和 16 个命令长轮询。正常 Agent 远低于这些上限；持续收到 `429` 应先排查重复进程、异常队列或失陷凭据，而不是扩大上限。

尚未开始的特权命令 10 分钟后失效；已经进入 Helper 但 2 小时没有可信签名结果的动作会变为“需人工核验”，不会重试或伪装成失败。设备撤销也会把已开始但无结果的动作标为这一状态。管理员应通过带外终端、Helper 审计和下一次扫描确认真实主机状态。完成命令按设备保留有界详情和摘要墓碑；极旧、已经没有可安全核验上下文的队列回执会收到明确的 `command_result_expired` 终态，Agent 仅对这个精确协议结果丢弃队列项。

动作创建时返回的单次审批 nonce 也只有 10 分钟有效期；这是“管理员确认草稿”的期限，与批准后 Agent 领取但尚未进入 Helper 的命令执行期限是两个独立阶段。nonce 过期后应重新创建动作并复核预览，不要复用旧值。

Docker observer 的报告会列出 `checkErrors` 与覆盖率；Web 界面会显示覆盖不完整，并把安全分标为非全量评估。不能用 observer 的高分代替原生主机检查。

### 扫描计划

Controller 是周期扫描的唯一调度权威。新设备首次注册时会按 Agent 提供的初始周期创建 schedule（默认 24 小时），Agent 启动时另做一次即时扫描；此后不会再运行独立的本地周期计时器。日常调整应在控制台的计划任务中完成，修改 `/etc/witshield/agent.env` 的 `WITSHIELD_SCAN_INTERVAL` 不会覆盖已注册设备的 schedule。升级前已有且尚无 schedule 的设备会一次性补一个默认 24 小时计划；管理员随后禁用或删除的计划不会在重启时被自动补回。

## 通知与自动遏制

管理员在 Web 控制台的**设置 → 安全通知**中配置 Webhook 或 SMTP，保存后点击“测试已保存配置”。通知覆盖扫描完成、SSH 防御事件和动作失败。Webhook 密钥与 SMTP 密码只写不回显，使用 Controller 主密钥加密保存；备份与恢复时必须同时保护数据库和主密钥。

Webhook 使用 `X-WitShield-Timestamp` 和 `X-WitShield-Signature: v1=<hex>`。签名内容是 `timestamp + "." + 原始 JSON body` 的 HMAC-SHA256。接收端应使用常量时间比较、限制时间戳偏差并按事件 ID 去重。Webhook 不跟随重定向。SMTP 465 使用隐式 TLS；其他公网 SMTP 必须提供 STARTTLS，不能通过关闭证书校验绕过失败。

在策略页启用 SSH 自动遏制前，必须至少填写一个非回环管理员 IP/CIDR allowlist，并设置失败阈值、统计窗口、封禁 TTL 和每小时上限。系统不会自动推断 NAT、跳板机或动态出口；错误 allowlist 仍可能造成失联，因此生产启用前要验证带外控制台，并按需为 Helper 配置 `--admin-ip`/`--protected-prefix` 的第二层本机保护。

临时封禁的真实到期由主机内核的 nftables TTL 执行，不依赖 Controller 在线。Controller 与 Agent 没有共享可信时钟，主机也可能在最终授权后休眠，因此 Controller 只把“命令开始时间 + TTL”作为**最早可能到期、确定仍应去重的窗口**；窗口过去后若没有新的主机证据，记录转为“需核验”而不会谎称已经解除，也不会用迟到的结果重新开始 TTL。相同 IP 的后续封禁会在单个 nftables 原子事务中刷新，并携带动作代际；旧动作的迟到回滚不能删除新一代封禁。

设备级紧急停止会阻止新的自动决策，并原子取消尚未进入 Helper 的已排队策略动作；Agent 在特权执行前还会再次向 Controller 取得最终授权，处理停止开关与队列领取之间的竞态。它不会谎报已经开始执行的动作已取消，也不会立即移除已经生效的临时封禁：后者继续按 TTL 自动解除，或由管理员从动作记录发起回滚。

SSH 配置加固执行后不会立即显示为最终成功。Helper 会保留原配置并启动本机持久化回滚计时器，动作进入“等待安全确认”；管理员应从第二个会话验证密钥登录后再确认。未在窗口内确认会触发 Helper 自动恢复。Controller 显示“已取消/已触发安全回滚”不是回滚成功回执，网络异常时仍需通过带外控制台与审计复核实际配置。

## 多机反向代理

以下 Caddy 示例只展示最小 TLS 入口；域名和访问策略需要自行调整：

```caddyfile
shield.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080 {
        # 不信任客户端自带的转发身份；把上游看到的来源固定为本次
        # TCP peer，并明确外部请求经过 HTTPS。
        header_up -Forwarded
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto https
        transport http {
            read_timeout 5m
            write_timeout 5m
        }
    }
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
    }
}
```

只应让反向代理访问 loopback Controller。启用该拓扑后，在 `/etc/witshield/controller.env` 中加入：

```text
WITSHIELD_TRUSTED_PROXIES=127.0.0.1/32,::1/128
```

然后执行 `sudo systemctl restart witshield-controller`。只在代理确实通过 loopback 直连时信任这两个前缀；不要信任所有地址或整个内网。代理必须删除/覆盖客户端提交的 `Forwarded`、`X-Forwarded-For` 和 `X-Forwarded-Proto`，否则攻击者可能伪造登录限流来源或 HTTPS 状态。若要用防火墙限制来源，还要考虑 Agent 出口地址变化；不要把 IP allowlist 当成设备认证替代品。

## 升级

先阅读发布说明并备份，然后重跑安装器指定版本：

```bash
sudo bash install.sh --mode standalone --version vX.Y.Z --require-signature
```

安装器保留已有环境文件和数据目录，只替换二进制、systemd unit 与 Web 资产。Agent 已有设备身份时不会要求或生成新的 enrollment token。安装与卸载共享全局锁并拒绝并发执行；签名和归档验证通过后、任何系统变更发生前，目标版本先写入 `/usr/share/witshield/VERSION.pending`。全部服务验证成功后才原子提交为 `VERSION`；中途失败留下的 pending 版本也会成为反降级下限，防止部分升级或数据库迁移后被旧版覆盖。普通卸载会保留该下限及用户数据，只有明确 `--purge` 才清除。确需回退时，必须先恢复匹配版本的数据备份并显式增加 `--allow-downgrade`，不能只覆盖二进制。升级后检查：

```bash
systemctl is-active witshield-controller witshield-helper witshield-agent
curl --fail http://127.0.0.1:8080/healthz
journalctl -u witshield-controller -u witshield-helper -u witshield-agent -n 100 --no-pager
```

不要自动降级数据库。需要回退时先停止服务，按发布说明恢复匹配版本的二进制和数据库备份。

## 备份与恢复

备份对象至少包括：

- `/var/lib/witshield/`：Controller 数据库、审计和默认主密钥；
- `/var/lib/witshield-agent/`：设备身份、状态和回滚材料；
- `/var/lib/witshield-helper/`：特权 Playbook 的 SSH 回滚日志；
- `/etc/witshield/`：运行配置（可能包含短期初始化材料）。

在应用一致性无法保证的版本，停止服务后再复制：

```bash
sudo systemctl stop witshield-agent witshield-helper witshield-controller
# 使用组织批准的加密备份工具；不要把备份提交到 Git。
sudo systemctl start witshield-controller witshield-helper witshield-agent
```

Controller 主密钥和数据库最好存入不同的访问控制域。恢复到另一台机器后，验证文件所有者、`0600/0700` 权限、系统时间、TLS 域名和设备连接。

## 故障排查

### Agent 无法注册

检查 Controller URL、TLS、系统时间和 token 是否过期/已使用。不要把 token 发进公开日志。生成新 token 前先确认控制台没有已经注册成功但暂时离线的同名设备。

### 更新后 Web 为空白

确认 `/usr/share/witshield/web/index.html` 存在且 Controller 能读取，`WITSHIELD_WEB_DIR` 指向该目录；检查浏览器 Network 中是否有静态文件 404。不要通过关闭浏览器安全策略解决。

### AI 接口连通但请求失败

模型列表成功不等于 Responses/Messages 协议兼容。当前客户端使用非流式请求；分别检查 protocol、Base URL、模型、TLS CA、非流式 JSON 响应结构、网关超时和上游错误。规则报告仍应可用。

### 防御动作可能导致失联

立即打开对应设备的紧急停止：尚未开始的策略动作会被取消，已经生效的临时封禁等待 TTL 自动解除或从动作记录手工回滚。若无法通过网络恢复，使用带外控制台检查防火墙与妙盾审计。不要在不清楚现场的情况下批量清空所有安全规则。

## 卸载

默认卸载保留配置、身份、审计和回滚数据：

```bash
sudo witshield-uninstall
```

只有明确不再需要任何数据时才永久清除：

```bash
sudo witshield-uninstall --purge
```

清除动作不可恢复，会再次确认。执行后脚本会说明删除了什么以及是否保留数据。
