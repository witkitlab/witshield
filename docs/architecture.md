# 架构

本文描述巡御的目标架构、安全边界和两种部署拓扑。具体版本已经实现的能力以发布说明和测试为准。

## 设计目标

1. **本地优先**：单机不依赖 WitKitLab 服务，规则扫描在没有 AI 或外网时仍可运行。
2. **证据先于模型**：确定性的采集与规则产生 Finding/Signal，Controller 先把它们关联成 Incident；AI 只用固定只读工具调查并生成结构化建议。
3. **决策与权限分离**：模型、Web UI、Controller 都不能直接获得一个不受限的 root Shell。
4. **人机共同控制**：默认逐次确认；自动处置只用于用户预授权、低破坏、可逆的动作。
5. **失败可恢复**：修改前检查与留存状态，修改后重新验证，失败时进入明确的回滚或人工接管状态。
6. **同一内核、两种模式**：单机和多机复用协议、数据模型、策略与审计机制。

## 组件

```text
┌──────────────────────── 管理域 ────────────────────────┐
│  Browser/CLI ──> Controller API ──> SQLite + audit     │
│                         │          Signal → Incident    │
│                         ├──> AI provider (optional)     │
│                         │    read-only investigation   │
│                         │    + typed response proposal │
└─────────────────────────┼───────────────────────────────┘
                          │ authenticated HTTPS long-poll + reports
┌─────────────────────────▼── 设备域 ─────────────────────┐
│ Agent                                                     │
│  collectors → deterministic rules → findings              │
│                              │                             │
│                       policy/approval                      │
│                              ▼                             │
│     unprivileged Agent ──Unix socket──> root Helper         │
│                          fixed read-only process sensor     │
│                          + typed action executor            │
│          precheck → snapshot → apply → verify → rollback   │
│                              │                             │
│                         local audit                        │
└────────────────────────────────────────────────────────────┘
```

### Controller

- 提供本地 Web UI 与版本化 `/api/v1` API；
- 管理单一管理员会话、设备、Finding、策略、审批与审计；
- 保存加密后的 AI 凭据与 Controller 数据；
- 接受 Agent 主动建立的连接，不主动扫描设备端口；
- 默认监听 `127.0.0.1:8080`，公开访问必须在受信反向代理之后启用 TLS。

### Agent

- 检查特权账号、SSH 配置、敏感文件权限、监听端口、防火墙、待更新软件包与 Docker Socket 权限；
- 维护账号/组、登录信任、SSH/PAM、计划任务、启动持久化、动态链接器、内核策略、systemd 和 Docker daemon 配置的本地摘要基线；不上传文件正文；
- 以最小化网络监听基线发现新暴露端口；原生模式通过 Helper 的固定只读接口从 procfs 识别特权临时路径进程与已删除可执行文件，不给 Agent 额外系统权限，也不采集命令行、环境变量或进程输出；
- 执行确定性规则并给结果生成稳定指纹；
- 启动时执行一次扫描，之后只执行 Controller 调度器下发的扫描命令，把结果和状态发送到 Controller；Controller 是周期调度的唯一权威；
- 只把 Controller 请求映射到 Helper 已编译的强类型 Playbook，不接受任意命令、可执行路径或 shell；
- 保存设备身份、最近任务和恢复所需状态。

### 事件关联与 AI 调查层

- 支持用户指定的 OpenAI/Anthropic 兼容接口；
- 扫描 Finding 和签名运行时事件先转换成统一 Signal，并按设备、类型和稳定目标关联为 Incident；新证据会重新打开处于监测中的事件；
- Controller 后台 worker 只处理用户在对应 PolicyGrant 中显式开启的能力；普通协助忽略低风险噪声，增强模式才会调查低风险事件，失败后至少退避 15 分钟；
- AI 只能读取八组 Controller 侧工具结果：设备态势、事件信号、当前 Finding、近期动作、策略边界、最近巡检态势、事件时间线和同类事件。工具没有参数自由度，不访问主机 shell；每种信号使用独立证据白名单，上下文有字段截断和 128 KiB 总上限；
- 模型必须返回严格 JSON。响应步骤只能引用已注册动作类型，并在保存及准备执行时两次通过 Controller schema 校验；模型不能创建已批准动作，也不能取得 approval nonce；
- 接口失败、超时或输出无效时，规则报告保持可用。

### 结构化执行器

动作由固定类型和严格 schema 标识，例如临时封禁 IP，而不是一段模型任意生成的 shell。每种动作应拥有：

- 参数校验和目标白名单；
- 支持平台与依赖检查；
- 影响预览和失联风险检查；
- 幂等执行与超时；
- 独立验证器；
- 可持久化的回滚材料；
- 审批级别与是否允许自动执行的上限。

原生 Agent 以 `witshield-agent` 普通用户运行，可按安装时存在的系统组获得只读日志权限。独立的 `witshield-helper` 以 root 运行，但只监听本机 Unix Socket，校验 peer credential 和 256-bit 本机 token，并仅接受编译进二进制的强类型 Playbook。Controller 使用独立用户且不在 Helper 访问组，因此 Controller RCE 不能直接调用 Helper。

Helper 仍是高价值边界：它不连接 AI/Controller，也不接受任意 shell、可执行路径或远程插件。唯一的只读观察请求没有参数自由度，只返回两类有上限的可疑进程元数据；它与会产生副作用的 Action 协议分开。`apt` Playbook 需要下载包时，其固定子进程可能访问系统软件源。软件包变更会在 APT 持有前端锁后读取 version 3 计划，按 `包名:架构` 锁定完整事务，只允许管理员显式授权且已经安装的包做严格单调升级；任何未列出的依赖变化、新增/删除包、同版本重装、架构或 Multi-Arch 切换以及陈旧回滚都会在 `dpkg` 前拒绝。APT 的自动/手动安装标记保持不变。每次动作调用的 actor、类型、参数摘要与结果都应生成审计回执。

## 部署拓扑

### 单机模式

Controller 与 Agent 同机运行，Agent 连接 loopback Controller。Controller 使用 `/var/lib/witshield`，Agent 使用 `/var/lib/witshield-agent`，二者的配置和权限独立。

```text
localhost:8080 ← Browser through SSH tunnel
      ▲
 Controller ← Agent → local host
```

适合一台服务器、开发或希望保持本地优先的用户。未配置外部集成时，规则扫描和人工修复流程不需要业务出站；管理员启用 AI、Webhook/SMTP 时 Controller 会连接相应端点，软件包升级 Playbook 也可能通过系统包管理器访问已配置的软件源。

### 多机模式

一台受控管理服务器运行 Controller，各设备 Agent 通过 HTTPS 心跳、报告上传和命令长轮询主动连接它。

```text
                 ┌── Agent A
Admin → Controller├── Agent B
                 └── Agent C
```

- Agent 不需要开放入站端口；
- 初始 enrollment token 应短期、一次性并限制用途；
- 注册后换取独立设备身份，后续请求不继续复用 enrollment token；
- Controller 被攻陷不等价于任意 root Shell，但攻击者可能调用设备允许的强类型 Playbook；应把 Controller 入侵视为高危事件，立即停用 Agent/Helper、撤销设备凭据并检查动作审计；
- 反向代理必须允许约 25 秒的命令长轮询、设置高于客户端整体期限的合理超时，并限制请求大小。

## 数据与密钥

| 数据 | 建议位置 | 保护方式 |
|---|---|---|
| Controller SQLite | `/var/lib/witshield/` | `witshield-controller` 独占，目录 `0700` |
| Agent 状态 | `/var/lib/witshield-agent/` | `witshield-agent` 独占，目录 `0700` |
| Controller 主密钥 | `/var/lib/witshield/master.key` | Controller `0600`，不进入数据库或备份日志 |
| Helper token/socket | `/etc/witshield/helper.token`、`/run/witshield/helper.sock` | `root:witshield-helper`，仅 Agent 加入访问组 |
| Helper 回滚日志 | `/var/lib/witshield-helper/` | root 独占，目录 `0700` |
| 服务环境文件 | `/etc/witshield/*.env` | `0600`，不得提交仓库 |
| AI API Key | 加密凭据库 | 仅在调用时解密，UI/日志掩码 |
| 审计记录 | Controller 与设备本地 | 追加式事件、稳定 ID、时间与结果 |
| 动作快照 | Agent 状态目录 | 最小保留、权限隔离、按策略清理 |

备份 Controller 时必须同时安全备份主密钥，否则加密凭据不可恢复；主密钥与数据库应分开保存。

## 关键状态机

### Finding

```text
open → resolved
  └──→ ignored
```

重新扫描后由稳定指纹合并，不因 AI 文案变化而创建重复 Finding。

### Incident / Investigation / ResponsePlan

```text
Signal ──关联──> Incident(open) ──PolicyGrant──> investigating
                         │                         │
                         │                         ├─ 无可执行建议 → monitoring
                         │                         ├─ 有响应计划 ─→ awaiting_approval
                         │                         └─ 失败 ───────→ open（退避后可重试）
                         │
                         ├─ 新相关 Signal 到达 monitoring → open
                         ├─ 管理员忽略 → dismissed
                         └─ 管理员确认解决 → resolved

ResponsePlan(proposed) → 单步重新校验/生成一次性动作 → approved/executing
                       → Action 可信回执 → completed/failed
```

Incident 是长期事件档案，不等于一条告警。调查记录保存触发来源、模型、结论、置信度和实际使用的只读工具；响应计划保存理由、风险、强类型步骤及绑定的 Action ID。旧版 Finding、Action 和 SSH DefensePolicy API 继续保留，迁移只新增投影表并把已有 SSH 策略映射为对应能力授权。

### Action

```text
draft → approved → executing ───────────────→ succeeded
                     └──────────────────────→ failed
                     └─ 结果超时 / 设备撤销 → indeterminate（人工核验）
                     └─ SSH 已修改 ─────────→ awaiting_confirmation
                                               ├─ 用户确认 → confirming → succeeded
                                               ├─ 手工回滚 ─────────────→ rolling_back
                                               └─ 安全窗口过期 ─────────→ cancelled

succeeded / failed（存在回滚材料） ──────────→ rolling_back → rolled_back
                                                           └→ failed
```

批准 nonce、状态转换和命令结果由服务端原子校验；Agent 在进入 Helper 前还要从 Controller 取得最终执行授权，Helper 再验证动作类型与参数。所有 execute/rollback/confirm 命令都必须先持久记录 `started_at`，动作结果需由注册时固定的设备 Ed25519 身份签名，并绑定设备、命令、结果、回滚状态、审计回执与错误文本。重复消息和并发批准必须保持幂等。命令在进入 Helper 前 10 分钟过期时，后台维护任务即使在设备离线时也会更新对应动作；跨过执行边界后 2 小时仍没有可信结果则进入 `indeterminate`，后续不会自动重试。设备级紧急停止抢先生效时，尚未进入 Helper 的**策略自动动作**会变为 `cancelled`，不会越权取消人工批准的其他动作。

从早期、尚无 `completion_digest` 的数据库升级时，Controller 会对旧成功回执重建完整摘要。旧失败记录并未保存 rollback 字段，因此只能在原始 result、audit 和有效错误完全一致时把重放作为无副作用的终态确认；它会刻意忽略无法证明的 rollback，且不会回填摘要、改写状态或重复通知。新格式记录仍绑定并校验所有签名结果字段。

Agent API 对来源与设备凭据设置有界请求速率，并对报告、事件、结果按请求体和条目数计算工作预算；SQLite 写入与命令长轮询也有独立并发闸门。报告、安全事件、当前 Finding 投影、未完成动作、请求 nonce 与完成命令墓碑均按设备或全局设置固定数量/字节上限；短期注册 challenge 同时受身份、注册令牌、来源与全局边界约束。高成本历史压缩只在启动和每 6 小时运行，常规维护不做全表排名。上述限制不是身份验证的替代，而是避免一个已失陷设备拖垮单连接 SQLite 控制台。

SSH 加固是额外的失联保护流程：Helper 在修改前持久化原配置并启动本机耐重启的回滚计时器；只有用户在安全窗口内确认新连接可用、Agent 执行确认命令成功后，动作才成为 `succeeded`。窗口过期时 Controller 的 `cancelled` 表示 Helper 安全回滚已被触发，不等同于 Controller 已收到“回滚成功”回执；应通过设备状态和审计复核。首版没有单独的 `verified` 状态，Helper 执行回执和后续扫描共同用于确认效果。

## 分级授权与自动防御

每台设备按能力分别拥有 PolicyGrant：`observe` 只记录；`assist` 自动只读调查但执行前询问；`auto_low_risk` 允许该能力下已注册的确定性低风险规则自动执行；`enhanced` 额外调查低风险信号。任何模式都不会把 AI 变成任意命令执行器。

自动防御是一组预注册 Playbook，逐项包含：

- 触发信号和最小证据阈值；
- 目标与保护白名单；
- 按设备的每小时创建上限、同一来源的待执行/生效去重、作用时间 TTL；
- 自动解除或回滚方法；
- 设备级紧急停止；
- 设备离线时动作留在 Controller 队列且受命令有效期约束；临时封禁的解除由内核 TTL 执行，不依赖 Controller 在线。
- Controller 不根据迟到的结果重启封禁 TTL，也不假设 Controller/Agent 时钟同步：它只在 `started_at + TTL` 的确定窗口内抑制同源重复动作，窗口过后把远端状态标为 `indeterminate` 并允许新动作以单次 nftables 事务原子刷新。同一 IP 的 element 带动作代际，Helper 在回滚前核验代际，因而旧回滚无法删除后来刷新出的封禁。

SSH 暴力尝试临时封禁是首个实验场景：只临时阻断来源地址，不永久修改账号，不反向访问来源主机，并保护私网/loopback 和用户明确配置的管理员 IP/CIDR allowlist；系统不自动猜测当前管理员来源。

打开设备级紧急停止会在同一数据库事务中停用后续自动决策，并取消该设备尚未跨过 Agent 最终授权门的已排队策略动作。已经进入 Helper 执行的动作不会被伪装成“已取消”；已经生效的临时封禁按 TTL 自动解除，也可从动作记录手工回滚。

## 扩展点

- `Collector`：只读采集器；
- `Rule`：确定性 Finding 生成器；
- `Notifier`：邮件、Webhook 等通知；
- `AIProvider`：兼容接口适配器；
- `Action`：固定类型的执行/验证/回滚实现；
- `SignalSource`：Falco、CrowdSec 或系统日志信号。

扩展应在进程内使用强类型接口或运行在受限子进程中；不把未经签名的远程插件直接加载到特权 Agent。
