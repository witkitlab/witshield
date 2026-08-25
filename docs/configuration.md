# 配置参考

妙盾的普通运行参数可由 CLI 参数或环境变量设置；敏感值优先通过权限为 `0600` 的文件或认证后的 UI/API 写入。CLI 参数优先于环境变量，环境变量优先于默认值。

## Controller

```text
witshield-controller [options]
```

| CLI | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--listen` | `WITSHIELD_LISTEN` | `127.0.0.1:8080` | HTTP 监听地址；公开使用应由 TLS 反代保护 |
| `--data-dir` | `WITSHIELD_DATA_DIR` | Linux 为 `/var/lib/witshield` | SQLite、状态和默认主密钥目录 |
| `--web-dir` | `WITSHIELD_WEB_DIR` | `/usr/share/witshield/web` | Web 静态资源目录 |
| `--trusted-proxies` | `WITSHIELD_TRUSTED_PROXIES` | 空 | 允许提供转发头的反向代理 IP/CIDR，逗号分隔；仅配置真实直连代理 |
| `--bootstrap-token` | `WITSHIELD_BOOTSTRAP_TOKEN` | 空 | 首位管理员初始化令牌 |
| `--bootstrap-token-file` | `WITSHIELD_BOOTSTRAP_TOKEN_FILE` | 空 | 首选：从本机受限文件读取初始化令牌 |
| `--initial-enrollment-token-file` | `WITSHIELD_INITIAL_ENROLLMENT_TOKEN_FILE` | 空 | 单机首次启动时预置一次性设备 token |
| `--master-key-file` | `WITSHIELD_MASTER_KEY_FILE` | `<data-dir>/master.key` | 加密 AI 与通知渠道凭据的主密钥文件 |

安装包使用 `/etc/witshield/controller.env` 保存非交互式 systemd 环境。该文件必须由 root 拥有且权限为 `0600`。

### 初始化管理员

空数据库时：

1. `GET /api/v1/status` 返回 `needsBootstrap`；
2. `POST /api/v1/admin/bootstrap` 提交用户名、至少 12 个字符的密码和 bootstrap token；
3. 创建唯一管理员和会话；
4. 此后使用 `POST /api/v1/auth/login` 登录。

首次创建管理员必须配置 bootstrap token，请求必须精确匹配；未配置时初始化端点返回不可用，即使请求来自 loopback 也不会免 token。原生安装默认使用 `/var/lib/witshield/bootstrap.token`（`0600`）而不是环境变量；初始化完成后删除该文件并重启 Controller。数据库已初始化时该端点仍拒绝重复创建管理员。

主密钥首次使用时生成并以 `0600` 保存。不要把它写入 `.env`、Compose 或数据库。备份时将主密钥与数据库分开保存；丢失主密钥会导致加密的 AI Key、Webhook 密钥和 SMTP 密码无法恢复。

## Agent

```text
witshield-agent [options]
```

| CLI | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--controller-url` | `WITSHIELD_CONTROLLER_URL` | — | Controller 的绝对 HTTP(S) URL |
| `--enrollment-token` | `WITSHIELD_ENROLLMENT_TOKEN` | — | 首次设备注册令牌 |
| `--enrollment-token-file` | `WITSHIELD_ENROLLMENT_TOKEN_FILE` | — | 首选：首次设备注册令牌文件 |
| `--consume-enrollment-token` | `WITSHIELD_CONSUME_ENROLLMENT_TOKEN` | `false` | 原生安装专用：长期设备凭据安全落盘后删除非 `/run/secrets/` token 文件 |
| `--name` | `WITSHIELD_DEVICE_NAME` | 主机名 | 控制台显示的设备名 |
| `--data-dir` | `WITSHIELD_DATA_DIR` | Linux 为 `/var/lib/witshield-agent` | 设备身份、扫描和恢复状态 |
| `--interval` | `WITSHIELD_SCAN_INTERVAL` | `24h` | **首次注册时**建议 Controller 创建的初始扫描周期，如 `24h`、`168h`；注册完成后以 Controller 中的 schedule 为准 |
| `--auth-log` | `WITSHIELD_AUTH_LOG` | 原生为 `/var/log/auth.log` | 可选：显式 SSH 认证日志绝对路径 |
| `--journalctl` | `WITSHIELD_JOURNALCTL` | `/usr/bin/journalctl` | 固定的 journald 读取器；原生模式优先保存 cursor 增量读取；失败时 auth.log 回退仅用于可见性/告警，不授权自动处置 |
| `--host-root` | `WITSHIELD_HOST_ROOT` | `/` | Docker observer 的只读宿主机挂载根 |
| `--observer-only` | `WITSHIELD_OBSERVER_ONLY` | `false` | 禁止全部特权动作，只执行可见范围内的扫描 |

systemd 安装使用 `/etc/witshield/agent.env`，指向 `/var/lib/witshield-agent/enrollment.token`；服务带 `--consume-enrollment-token`，首次注册成功后删除该文件。Agent 保存独立设备身份并停止依赖 enrollment token。不要在 URL 查询参数或普通进程参数中传递令牌。

### 扫描调度权威

Agent 每次进程启动会做一次即时扫描，用于尽快恢复可见性。除此之外，周期扫描只由 Controller 的 schedule 下发；Agent 不再运行第二套本地周期计时器。`WITSHIELD_SCAN_INTERVAL` 只在设备首次注册时创建初始 schedule，注册提示允许 15 分钟至 365 天；之后修改 Agent 环境变量不会改动已注册设备的周期。已注册设备在控制台/API 中新建或修改 schedule 的范围为 15 分钟至 30 天，当前 UI 提供每日与每周两个常用值。

## 特权 Helper

联网的 Agent 以 `witshield-agent` 普通用户运行。所有 root 修复通过本机 Helper 的强类型 Playbook 接口完成：

| 参数/环境 | 默认/安装值 | 说明 |
|---|---|---|
| `--helper-socket` / `WITSHIELD_HELPER_SOCKET` | `/run/witshield/helper.sock` | Agent 连接的 Unix Socket |
| `--helper-token-file` / `WITSHIELD_HELPER_TOKEN_FILE` | `/etc/witshield/helper.token` | root/helper-group `0640` 的 256-bit 本机令牌 |

Helper 运行参数由 systemd unit 固定为：

```text
--socket /run/witshield/helper.sock
--token-file /etc/witshield/helper.token
--group witshield-helper
--journal-dir /var/lib/witshield-helper/ssh-rollbacks
--receipt-dir /var/lib/witshield-helper/receipts
```

Helper 还支持重复的 `--protected-prefix CIDR` 和 `--admin-ip IP`，用于在本地执行层拒绝封禁保护网段或管理源；`--state-key-file` 默认是 `/var/lib/witshield-helper/state.key`，用于签名回滚状态。额外保护项应通过受审的 systemd drop-in 固定配置，修改后运行 `systemctl daemon-reload` 并重启 Helper。Controller 侧的防御策略 allowlist 仍需同时配置，不能只依靠一层保护。

只有 `witshield-agent` 加入 `witshield-helper` 组；Controller 使用独立的 `witshield-controller` 用户，不能读取 Helper token 或连接 Socket。Helper 校验 Unix peer credential 与 token，并且不接受任意命令行、可执行路径或 shell 片段。

Helper 的 Playbook 只使用审计过的固定系统路径（包括 APT/DPKG、`/usr/sbin/nft`、`/usr/sbin/sshd` 和 `systemctl`）。其中 `nftables` 是原生 Agent 的运行依赖；SSH 加固在没有现成 `sshd` 的主机上返回不可用，不会自动安装 SSH 服务。

## AI 设置

AI 凭据不使用环境变量，避免出现在 Compose、进程环境和常见诊断输出中。管理员登录后通过 UI 或 `PUT /api/v1/ai/settings` 配置。

字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `protocol` | enum | `openai_responses`、`openai_chat`、`anthropic_messages` |
| `baseUrl` | URL | 用户信任的 API 根地址 |
| `model` | string | 上游模型名 |
| `apiKey` | string，可选 | 仅写；省略表示保留现有值 |
| `clearApiKey` | boolean，可选 | 显式设为 `true` 才删除已有 Key |
| `customHeaders` | object，可选 | 额外请求头；敏感值与设置一起加密 |

示例（不要把真实 Key 保存进脚本或仓库）：

```json
{
  "protocol": "openai_responses",
  "baseUrl": "https://api.example.com/v1",
  "model": "example-security-model",
  "apiKey": "<通过安全输入提供>",
  "customHeaders": {}
}
```

读取设置时不会返回明文 API Key，并对其他敏感请求头进行移除或掩码。若想保留现有 Key，更新其他字段时不要发送 `apiKey`；空字符串不等同于清除。

更多协议语义见 [AI 提供方](ai-providers.md)。

## 反向代理最低要求

- TLS 1.2+，浏览器始终使用 HTTPS；
- 精确代理 Controller，不把任意用户输入拼入上游；
- 允许 Agent 的命令长轮询，并设置合理的读取/写入/空闲超时；
- 设置请求体、响应头和连接数上限；
- 只传递经过清洗的 `X-Forwarded-For`/`Forwarded`，Controller 只信任明确配置的代理；
- `/agent/v1/sync` 等 Agent API 不得被缓存；
- 初始化完成前先限制来源，且使用 bootstrap token；
- Cookie 保持 `HttpOnly`、`Secure`、`SameSite=Strict`。

不要仅靠隐藏域名保护 Controller。

`WITSHIELD_TRUSTED_PROXIES` 是安全边界：只有 TCP peer 命中该列表时，Controller 才使用 `X-Forwarded-For` 判断登录限流来源、使用 `X-Forwarded-Proto: https` 设置 Secure Cookie。不要填写 `0.0.0.0/0`、`::/0` 或宽泛内网段。若 Caddy 与 Controller 同机并通过 loopback 通信，精确值应为 `127.0.0.1/32,::1/128`，同时要求代理覆盖而非透传客户端提供的转发头。

## 文件权限

```text
/etc/witshield/                     root:witshield-helper 0750（含 Agent 时）
/etc/witshield/controller.env       root:root 0600
/etc/witshield/agent.env            root:root 0600
/etc/witshield/helper.token         root:witshield-helper 0640
/var/lib/witshield/                 witshield-controller:witshield-controller 0700
/var/lib/witshield/bootstrap.token  witshield-controller:witshield-controller 0600（仅初始化）
/var/lib/witshield/master.key       witshield-controller:witshield-controller 0600
/var/lib/witshield-agent/           witshield-agent:witshield-agent 0700
/var/lib/witshield-agent/enrollment.token witshield-agent:witshield-agent 0600（仅注册期间）
/var/lib/witshield-helper/          root:root 0700
```

不要把 `/etc/witshield` 或 `/var/lib/witshield*` 直接打进公开故障包。导出诊断前检查数据库、主密钥、API 设置、设备令牌、IP 和日志原文。

所有 secret 路径都拒绝符号链接和非普通文件。原生路径必须不向 group/other 开放（通常 `0600` 或 `0400`）；清理后的绝对路径位于 `/run/secrets/` 时，可接受容器运行时常见的只读 `0400`/`0440`/`0444`，程序只读取且不尝试删除。不要用这一容器例外放宽原生磁盘文件。
