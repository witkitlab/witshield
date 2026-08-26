# Docker 观察模式的安全边界

巡御的 Docker 镜像只用于**只读观察**，不是原生 Agent 的等价替代。完整说明与命令见 [`docker/README.md`](../docker/README.md)。

## 为什么不提供 privileged 模式

一个同时解析不可信服务器数据、连接网络和调用 AI 的容器，如果获得 `--privileged` 或 Docker Socket，实际上能取得宿主机 root 控制权。`/var/run/docker.sock:ro` 也不构成只读 API：文件系统挂载标记不能阻止客户端通过 Socket 调用创建容器、挂载根目录等写操作。

因此官方 Compose：

- 不挂载 Docker Socket；
- 不使用 `privileged` 或 `cap_add`；
- 不提供宿主机根目录写挂载；
- 不启用 host network；
- 丢弃所有 capabilities，根文件系统只读；
- 管理端口只映射到 `127.0.0.1`；
- 基础模式仅挂载 `/etc/passwd` 和 IPv4 TCP 表；SSH 与 IPv6 通过存在性检查后显式叠加单文件只读覆盖。

Compose 默认只把控制台映射到 `127.0.0.1:8080`。如本机端口冲突，可在启动前设置 `WITSHIELD_PORT`（例如 `WITSHIELD_PORT=18080`）；绑定地址仍固定为 loopback，不会因改端口而公开到局域网或公网。

## 能力差异

| 能力 | 原生 systemd | Docker 观察模式 |
|---|---:|---:|
| 内置基线检查与报告 | 运行全部检查；普通用户权限不足项会显式不可用 | 受挂载数据范围限制；默认仅账号与 IPv4 TCP 数据可见 |
| AI 解读 | 支持 | 支持 |
| 修改软件包/配置 | 支持审批工作流 | 不支持 |
| SSH 加固所需的服务重载 | 支持审批与安全确认 | 不支持 |
| 防火墙临时封禁 | 按策略支持 | 不支持 |
| 自动防御 | 实验性、默认关闭 | 不支持 |

当数据不可见时，报告的 `checkErrors`/覆盖率会记录未完成项，Web 界面明确显示覆盖不完整，安全分不作为全量主机评分。不能把“没有权限观察”解释为“没有风险”。

基础 Compose 不要求 `sshd_config` 或 `tcp6` 存在，普通 Linux Docker 主机缺少这些可选文件时仍可启动。需要更多覆盖时，按 [`docker/README.md`](../docker/README.md) 的存在性检查叠加 `docker-compose.observer.ssh.yml` 和/或 `docker-compose.observer.ipv6.yml`。缺少 IPv6 数据时会保留已观察到的 IPv4 证据，同时把端口覆盖标为不完整；不会把“IPv4 已检查”冒充成“全部 TCP 已检查”。

## 镜像供应链

- 生产使用 `ghcr.io/witkitlab/witshield@sha256:...` 固定 digest；
- 对照 Release 的 `SHA256SUMS`、SBOM、Sigstore bundle 和 provenance；
- 镜像不包含 API Key、注册 token 或默认管理员密码；
- 镜像运行时不下载可执行插件或更新自身；
- 升级前备份命名卷，并阅读迁移说明。
