# 妙计巡御 · AI Agent 服务器管家

> **妙计巡御（WitShield AI）**：主动巡检风险，在你授权后修复，并在攻击发生时按策略自动响应。

[产品官网](https://witshield.witkitlab.com) · [English](README.en.md) · [架构](docs/architecture.md) · [安全模型](docs/threat-model.md) · [配置参考](docs/configuration.md)

> [!IMPORTANT]
> 项目目前处于早期开发阶段。自动处置默认关闭；在生产服务器启用修复前，请先阅读[安全模型](docs/threat-model.md)，并验证备份和回滚路径。

## 巡御解决什么问题

传统服务器安全工具擅长发现风险，却常把用户留在一串告警和命令面前。巡御把工作流连成一个可审计的闭环：

1. 按天或按周检查账号、SSH、敏感权限、端口、防火墙、软件包更新与 Docker Socket 风险，并持续监测账号、关键配置、计划任务、systemd 服务与容器配置变化；
2. 把扫描发现和运行时信号归一化、关联为有生命周期的安全事件，保留证据与时间线；
3. 用户开启对应能力后，常驻 AI 安全工程师会使用固定的只读调查工具主动分析事件，并输出严格结构化的结论与响应计划；
4. 响应计划中的每一步仍需重新通过 Controller 强类型校验和一次性批准，再由 Agent/Helper 预检、执行、验证和回滚；
5. 只有用户明确预授权、由确定性规则触发的低风险场景才可自动遏制，并受 TTL、频率上限、保护白名单与紧急停止约束。

AI 不是安全边界：规则、策略、审批和执行器共同决定一个动作能否发生。模型输出不能绕过策略，也不能直接获得一个不受限制的 root Shell。

## 两种部署模式

| 模式 | 适用场景 | 组成 | 数据位置 |
|---|---|---|---|
| 单机 | 管理一台服务器、离线环境 | Controller 与 Agent 安装在同一台机器 | 本机 SQLite |
| 多机 | 一位管理员管理多台服务器 | 一套自建 Controller + 各服务器上的 Agent | Controller 与各 Agent 本地 |

Agent 主动连接 Controller，多机部署不需要为每个 Agent 开放入站管理端口。首版定位为**单管理员、多设备**；团队、RBAC 与公共 SaaS 不在当前范围内。

## 快速开始

首发支持 Ubuntu/Debian 的 `x86_64` 与 `arm64`。推荐先下载并审阅安装脚本，再执行：

```bash
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://github.com/witkitlab/witshield/releases/latest/download/install.sh
less install.sh
sudo bash install.sh --mode standalone
```

安装器从 GitHub 不可变 Release 下载对应架构的发布包，校验 `SHA256SUMS` 后还会强制验证发布工作流的 Sigstore 签名；本机没有 Cosign 时，会临时下载经过内置 SHA-256 固定的验证器。已安装版本会记录在本机，安装器默认拒绝降级。

安装完成后，默认仅监听 `127.0.0.1:8080`：

```bash
ssh -L 8080:127.0.0.1:8080 your-server
# 浏览器打开 http://127.0.0.1:8080
```

可用模式：

```bash
# 单机原生模式：Controller + Agent
sudo bash install.sh --mode standalone

# 多机的中心控制台
sudo bash install.sh --mode controller

# 接入已有控制台的服务器 Agent；安装器会在 TTY 中隐藏输入一次性令牌
sudo bash install.sh --mode agent \
  --controller-url https://shield.example.com
```

详细参数、反向代理和升级方法见[运维手册](docs/operations.md)。

## Docker 只读观察模式

Docker 适合快速体验和只读体检，不承载修复或自动防御。示例配置明确做到：

- 不使用 `--privileged`；
- 不挂载 `/var/run/docker.sock`；
- 宿主机信息仅按白名单只读挂载；
- 丢弃全部 Linux capabilities，启用只读根文件系统和 `no-new-privileges`。

```bash
install -d -m 0700 docker/.secrets
umask 077
openssl rand -hex 32 > docker/.secrets/bootstrap.token
printf 'not-enrolled-yet\n' > docker/.secrets/enrollment.token
chmod 0444 docker/.secrets/bootstrap.token docker/.secrets/enrollment.token
docker compose -f docker-compose.observer.yml up -d controller
```

创建管理员、注册观察 Agent 以及消费 token 的完整步骤见 [Docker 观察模式说明](docs/docker-observer.md)。需要修复与自动防御能力时请使用原生 systemd 安装。

观察容器看不到未挂载的数据。报告会列出未完成检查，界面会明确标记“覆盖不完整”，安全分也不会被当作全量主机评分；“不可见”不等于“没有风险”。

基础 Compose 只要求 `/etc/passwd` 和 IPv4 TCP 表；没有 OpenSSH Server 或 IPv6 TCP 表也能启动。存在这些可选数据源时，再按说明叠加单文件只读覆盖，不会为了方便挂载整个 `/etc`、`/proc` 或宿主根目录。

## 使用自己的 AI API

巡御不内置 WitKitLab 密钥，也不要求经过公共代理。用户可配置：

- OpenAI Responses / Chat Completions 兼容接口；
- Anthropic Messages 兼容接口；
- 自定义 Base URL、API Key、模型名与连接测试。

未配置 AI 时，规则扫描、持续信号、事件关联、证据、风险等级和人工修复工作流仍可使用。配置后，可按设备和能力分别开启“AI 协助”或“增强自动化”；后台 worker 只会读取白名单化、限量、脱敏后的设备态势、事件信号、当前 Finding、近期动作与策略边界。模型不能调用 Agent、Helper 或 shell。密钥由本机主密钥加密后写入 SQLite，主密钥文件权限为 `0600`，UI 与日志不会回显完整密钥。参见 [AI 提供方配置](docs/ai-providers.md)和[常驻 AI 安全工程师](docs/security-engineer.md)。

## 安全通知

管理员可在 Web 控制台的**设置 → 安全通知**中配置带 HMAC-SHA256 签名的 Webhook 或自有 SMTP，保存后可直接发送测试通知。扫描完成、自动防御触发和动作失败会先进入 SQLite 持久通知队列；Webhook 与 SMTP 由相互独立的 worker 限次重试，一个故障渠道不会拖住另一个。Webhook 签名密钥与 SMTP 密码由本机主密钥加密，读取接口、错误和 UI 都不回显明文或带凭据的端点路径。

## 调度、确认与紧急停止

Controller 是周期扫描的唯一调度权威：Agent 启动时先做一次即时扫描，之后只响应 Controller schedule。Agent 的 `--interval`/`WITSHIELD_SCAN_INTERVAL` 只决定首次注册时创建的初始周期，已注册设备应在控制台修改计划，避免两套计时器产生重复任务。

动作获批不等于已经修改服务器。Agent 在进入 root Helper 前还要取得最终授权，Helper 执行预检、变更和验证。SSH 加固完成变更后会先进入“等待安全确认”：管理员从第二个会话验证新连接可用并确认后才算成功；超时则由 Helper 的本机持久化计时器触发恢复。Controller 的“已触发安全回滚”状态不冒充回滚成功回执，异常时应查看设备与审计。

设备级紧急停止会阻止新自动决策，并取消尚未进入 Helper 的策略队列；已经开始的动作不会被假装取消，已经生效的临时封禁按内核 TTL 到期或由管理员手工回滚。

## 安全原则

- 默认本地优先、最少出站、管理端口仅监听 loopback；
- 联网 Agent 与 Controller 都以独立普通用户运行；root Helper 只接受本机认证的强类型 Playbook；
- 默认不自动修复；每个动作绑定固定类型和设备并逐次批准，自动授权只来自该设备显式开启的策略；
- 自动动作必须可逆、带 TTL、频率限制、白名单和紧急停止；
- 不提供反向攻击（hack back）、外部扫描或攻击能力；
- 所有计划、批准、执行、验证和回滚都进入审计日志；
- 特权动作结果还必须由设备的持久 Ed25519 身份签名；仅拿到 bearer 设备令牌不能伪造修复成功；
- 每个 GitHub Release 同时提供安装归档、SBOM、全资产 SHA-256 校验和、Sigstore bundle 与构建 provenance；这些供应链证明是与安装归档并列的 Release 资产，不嵌入归档内部。

自动防御的边界是保护用户明确授权的本机资产，例如暂时封禁正在暴力尝试 SSH 的来源 IP。它不会攻击来源主机，也不会自动执行永久删除、重装系统或破坏性命令。

启用 SSH 自动遏制前，策略必须至少配置一个**非回环的管理员 IP/CIDR allowlist**；系统不会猜测 NAT、跳板机或动态管理出口。还应保留带外控制台，并在 Helper 的本机保护参数中配置关键管理来源。

## 项目状态与路线

- [x] 单机资产盘点、定时扫描、报告与 AI 解读
- [x] 单管理员多设备控制台与主动注册
- [x] 修复计划、逐次批准、验证和回滚
- [x] 自动防御策略框架、紧急停止与审计
- [x] 实验性 SSH 暴力尝试临时封禁
- [x] 通用 Signal → Incident → Investigation → ResponsePlan 事件闭环
- [x] 账号/权限、关键文件、计划任务、systemd 服务和容器配置的持续变化信号
- [x] 按能力授权的后台 AI 只读调查与结构化响应计划
- [x] Ubuntu/Debian x86_64/arm64 原生包与 Docker 观察模式

以上是当前源码实现状态；“已实现”不等于“已在所有生产拓扑验证”。正式版本仍以对应 tag 的 CI、签名制品、发布说明和干净主机烟测结果为准。

## 开发与贡献

```bash
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
```

贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题不要公开提交 Issue，请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可证

[Apache License 2.0](LICENSE)。
