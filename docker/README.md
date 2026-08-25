# Docker 只读观察模式

该 Compose 配置用于体验有限范围的只读盘点、规则报告和 AI 解读。它不会获得修复或自动防御权限，也不是原生 Agent 的全量主机扫描替代品。

从源码构建时默认使用 Go 官方模块代理并回退到直连。中国大陆网络下如果访问超时，可以显式覆盖构建参数；依赖仍必须通过 `go.sum` 校验：

```bash
docker build --build-arg GOPROXY=https://goproxy.cn,direct -t witshield:local .
```

## 启动

1. 固定发布镜像（生产环境推荐固定 digest）：

   ```bash
   export WITSHIELD_IMAGE='ghcr.io/witkitlab/witshield@sha256:<release-digest>'
   ```

2. 生成只用于首次管理员初始化的高熵 token 文件，并启动 Controller：

   ```bash
   install -d -m 0700 docker/.secrets
   umask 077
   openssl rand -hex 32 > docker/.secrets/bootstrap.token
   # Agent profile尚未启动，但 Compose 需要第二个秘密源存在。
   printf 'not-enrolled-yet\n' > docker/.secrets/enrollment.token
   chmod 0444 docker/.secrets/bootstrap.token docker/.secrets/enrollment.token
   docker compose -f docker-compose.observer.yml up -d controller
   ```

   默认监听本机 `127.0.0.1:8080`。若端口冲突，可在同一 shell 先执行 `export WITSHIELD_PORT=18080`。浏览器入口在容器内使用独立的 `admin-listener:8081`，绑定仅 Controller 加入的 `egress` 网络接口；Agent API 继续使用内部 `controller:8080`，因此伪造 `Host` 不能获得本地管理会话。Compose 只把独立入口发布到宿主 loopback。不要把端口改为 `0.0.0.0`，也不要让 Agent 加入 `egress` 网络；公开访问应改用受信 TLS 反向代理。

3. 浏览器访问 `http://127.0.0.1:${WITSHIELD_PORT:-8080}` 对应的实际端口，输入以下值创建管理员：

   ```bash
   cat docker/.secrets/bootstrap.token
   ```

   初始化后原 token 已不能再次使用。用明显的非秘密占位内容覆盖源文件，避免明文继续保留：

   ```bash
   chmod 0600 docker/.secrets/bootstrap.token
   printf 'disabled-after-bootstrap\n' > docker/.secrets/bootstrap.token
   chmod 0444 docker/.secrets/bootstrap.token
   docker compose -f docker-compose.observer.yml up -d --force-recreate controller
   ```

4. 选择只读数据源。基础配置只要求普通 Linux Docker 主机都应存在的 `/etc/passwd` 与 IPv4 TCP 表，因此未安装 OpenSSH Server、内核未启用 IPv6 时也不会因为缺少可选文件而启动失败。若宿主机存在对应文件，可以显式叠加 SSH/IPv6 覆盖：

   ```bash
   WITSHIELD_OBSERVER_FILES=(-f docker-compose.observer.yml)
   test -r /etc/ssh/sshd_config && \
     WITSHIELD_OBSERVER_FILES+=(-f docker-compose.observer.ssh.yml)
   test -r /proc/1/net/tcp6 && \
     WITSHIELD_OBSERVER_FILES+=(-f docker-compose.observer.ipv6.yml)
   ```

   这些命令使用 Bash 数组。可选文件只在来源确实可读时才加入；配置仍以单文件只读方式挂载，不扩大到整个 `/etc`、`/proc/1/net` 或宿主根目录。

5. 在控制台生成一个 15 分钟、单次使用的设备注册 token，临时传给 Agent：

   ```bash
   umask 077
   chmod 0600 docker/.secrets/enrollment.token
   printf '%s\n' '<控制台只显示一次的 token>' > docker/.secrets/enrollment.token
   chmod 0444 docker/.secrets/enrollment.token
   docker compose "${WITSHIELD_OBSERVER_FILES[@]}" --profile observer up -d agent
   ```

6. 看到设备在线后，清除 token 并重建 Agent。后续使用数据卷中的独立设备身份：

   ```bash
   chmod 0600 docker/.secrets/enrollment.token
   printf 'consumed-enrollment-token\n' > docker/.secrets/enrollment.token
   chmod 0444 docker/.secrets/enrollment.token
   docker compose "${WITSHIELD_OBSERVER_FILES[@]}" --profile observer up -d --force-recreate agent
   ```

Compose 把源文件只读挂载到 `/run/secrets/`，token 不进入环境、命令参数或镜像。源文件仍在宿主机：目录必须保持 `0700`，源文件设为 `0444` 是为了让非 root 容器用户可读且无人可从容器内改写；宿主机其他用户因无法穿越 `0700` 目录，仍无法读取。修改内容时短暂改为 `0600`，写完立即恢复 `0444`，并在消费后覆盖。设备 token 还会在 15 分钟后过期且只能消费一次。API Key 在登录后写入加密设置。

`WITSHIELD_SCAN_INTERVAL` 只作为 Agent 首次注册时创建 Controller schedule 的初始周期；Agent 启动时做一次即时扫描，后续周期任务由 Controller 唯一下发。设备注册完成后请在控制台修改扫描计划，重建容器或改变该环境变量不会覆盖既有 schedule。

## 约束检查

在仓库根目录运行发布流程使用的完整验证器；它会渲染基础、SSH、IPv6 和全部增强四种组合，并精确校验网络、挂载白名单、只读标记和沙箱参数：

```bash
scripts/verify-observer-compose.sh
```

只想人工查看基础配置时可以运行：

```bash
docker compose -f docker-compose.observer.yml --profile observer config > /tmp/witshield-compose.rendered.yml
grep -E 'privileged:|docker\.sock|cap_add:' /tmp/witshield-compose.rendered.yml
```

预期无输出。配置使用：

- `read_only: true`；
- `cap_drop: [ALL]`；
- `no-new-privileges`；
- 仅 loopback 端口映射；
- Agent 仅加入内部 `control` 网络；Controller 的 `egress` 网络同时承载管理员配置的 AI 出站与 Agent 不可达的本地浏览器监听器；
- 有限 CPU、内存和 PID；
- `json-file` 日志按 10 MiB × 3 个文件轮转；
- 明确的宿主机只读白名单挂载；可选覆盖仍是单文件挂载。

不要自行添加 `/var/run/docker.sock`、`--privileged`、宿主机根目录写挂载或 `network_mode: host`。这些做法会破坏观察模式的安全边界。

## 能看见什么

基础配置只能读取宿主机 `/etc/passwd` 和宿主 PID 1 网络命名空间的 `/proc/1/net/tcp`，用于发现额外 UID 0 账号和可见的 IPv4 TCP 监听端口。可选覆盖只会再加入：

- `docker-compose.observer.ssh.yml`：`/etc/ssh/sshd_config`；若主配置使用 `Include`，单文件不能代表有效配置，检查仍会明确标为不可用；
- `docker-compose.observer.ipv6.yml`：`/proc/1/net/tcp6`。

缺少 IPv6 表时，已经看见的 IPv4 证据仍会保留，但端口检查会计入覆盖不完整。容器看不到密码哈希、未挂载的日志、其他进程信息、软件包数据库、宿主机 `/sys` 或 Docker API，因此报告会列出对应未完成检查，Web 界面标记覆盖不完整，安全分不作为全量主机评分，而不是误报为安全。

Compose 以非 root、零 capabilities 运行。部分启用了 `hidepid` 或特殊 LSM 策略的主机可能进一步限制 `/proc`；这是预期的安全降级。

宿主机白名单挂载使用 `create_host_path: false`，避免 Docker 以 root 身份创建不存在的来源路径。可选覆盖如果被手工加入但来源随后消失，Compose 会明确失败；移除对应 `-f` 参数即可恢复基础观察，相关检查会显示“数据不可用”。

## 停止与删除

```bash
docker compose -f docker-compose.observer.yml --profile observer down
```

该命令保留数据卷。永久删除控制台、设备身份、设置和审计数据需要明确执行：

```bash
docker compose -f docker-compose.observer.yml --profile observer down --volumes
```

删除卷不可恢复，请先确认不再需要审计、报告或加密设置。
