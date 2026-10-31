# 命令行体检发布演练

这份清单用于在发布前检查 `witshield check` 和交互式修复。只在自己有权限操作、可随时销毁的干净虚拟机上演练。每个修复场景开始前恢复快照，避免前一个场景改变后一个场景的前提。

## 结果怎么记

勾选代表执行者已经实际观察到预期结果。未执行写 `NOT RUN`，执行后写 `PASS` 或 `FAIL`，并记录版本、架构、耗时和脱敏后的证据。模拟 runner、单元测试、Docker 只读体检都不能代替真实 SSH 重连和虚拟机修复演练。

初始登记日期为 2026-10-31。本文件交付时，下表所有整机项目均为 `NOT RUN`，不代表任何平台已经验收通过。执行后把填写完整的记录贴到发布 PR；发现失败先停止发布并保留现场。

| 环境 | 非 root / root 体检 | SSH 四种恢复路径及无公钥 | shadow | APT 正常 / 锁冲突 / 包集合 | 证据链接、执行者、日期 |
| --- | --- | --- | --- | --- | --- |
| Ubuntu 22.04 x86_64 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | 待提供干净虚拟机 |
| Ubuntu 24.04 x86_64 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | 待提供干净虚拟机 |
| Debian 12 x86_64 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | 待提供干净虚拟机 |
| 至少一台上述系统的 arm64 虚拟机，填写发行版 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | 待提供原生 ARM64 虚拟机 |

| 跨环境项目 | 状态 | 证据链接、执行者、日期 |
| --- | --- | --- |
| 测试版本的 GitHub Release host smoke 完整矩阵 | NOT RUN | 待发布和运行 GitHub Actions |
| DeepSeek 解读 | NOT RUN | 可选；需获授权的真实 API Key |
| 国内云服务器 Gitee 首次下载、验证和体检 | NOT RUN | 待国内测试机和已同步镜像 |
| 国内 Gitee 篡改制品拒绝执行 | NOT RUN | 待隔离的镜像夹具 |

## 开始前

- [ ] 记录 Release tag、提交 SHA、镜像或云镜像版本、`uname -m`、`/etc/os-release`、测试时间和虚拟机编号。公开记录使用 `demo-vps` 等名称，移除真实地址、用户名、公钥正文、凭据和日志中的来源 IP。
- [ ] 创建快照，实际验证云厂商 VNC 或串口控制台可以登录。保持原 SSH 会话 A，并准备从自己电脑新开 SSH 会话 B。控制台应独立于 SSH；只留两个 SSH 窗口不能代替带外恢复。
- [ ] 使用专用 sudo 测试账号。私钥只放在自己的电脑，用密钥新建一次连接，确认账号、端口和 `authorized_keys` 权限正确。准备仅用于本次演练的账号密码，并通过交互提示输入。
- [ ] 确认没有运行中的完整版 `witshield-helper.service`，没有生产业务和其他包管理操作；记录现有服务、监听端口及已安装包列表，方便检查只读体检有没有额外安装或启动内容。
- [ ] 从本次 Release 取得独立 CLI。按 [发布文档](releasing.md#独立验证) 验证 `SHA256SUMS.bundle`，证书身份必须是本次 tag 的 `witkitlab/witshield/.github/workflows/release.yml`，OIDC issuer 必须是 `https://token.actions.githubusercontent.com`。再检查独立程序对应的唯一 SHA-256 项，缺失、重复、签名或哈希不符都停止。
- [ ] 核对资产名使用去掉 `v` 的版本号，例如 `witshield_0.4.0_linux_amd64` 或 `witshield_0.4.0_linux_arm64`。用最新版 GitHub CLI 对程序执行 `gh attestation verify`，限制 `--repo witkitlab/witshield`、`--signer-workflow witkitlab/witshield/.github/workflows/release.yml` 和 `--source-ref refs/tags/v0.4.0`，将例子中的 tag 换成本次版本。
- [ ] 把已验证程序放在测试目录中，设置执行权限，并执行 `witshield version` 核对版本。后文的 `witshield` 均指这个程序；如果没有加入 PATH，使用绝对路径，sudo 时也使用同一个路径。

这份清单不会要求关闭校验或修改安装器的升级、降级和回滚逻辑。首次体检使用独立 CLI，无需安装完整版。

## 只读体检

- [ ] 普通用户运行 `witshield check --json`，单独保存 stdout、stderr 和退出码。stdout 是一个 JSON 对象，含 `score`、`grade`、`summary`、`findings`、`sshFailures`；`score` 为 0–100 的整数，`findings` 为数组，含中文解释和是否可修复的信息。
- [ ] `summary` 有检查数、已完成数和覆盖率。读取受限时说明检查未完成，不能把缺数据算成没有风险。SSH 日志不可读时，`sshFailures.available` 为 false，`total`、`uniqueIPs` 为 null，不能写成 0；可读且确实没有失败事件时才允许为 0。
- [ ] 运行 `witshield check --no-color` 和 `sudo witshield check --no-color`。输出包含「安全分」，非 root 检查缺数据时说明 sudo 可获得更完整的结果；输出不含 ANSI 颜色控制字符。
- [ ] 根据报告核对退出码：分数 ≥ 60 为 0，低于 60 为 1，参数或运行错误为 2。不能因正常的低安全分将体检记录为运行失败。
- [ ] 对比体检前后的 SSH 配置、shadow 元数据、包列表、监听端口和服务。没有安装服务、安装额外软件包或修改安全配置。在没有遗留 SSH 回滚日志的干净机器上，普通体检不应创建修复状态。
- [ ] 不提供 AI 配置运行普通体检，确认无需 API Key。可用独立的流量记录观察 CLI 本身没有外联；下载脚本、签名验证以及显式的 `--ai` 需要网络，应分别记录。

`.github/workflows/release-host-smoke.yml` 在 Ubuntu 22.04/24.04 amd64 和 Ubuntu 24.04 arm64 原生 runner 上执行签名、校验和、provenance 验证，再跑非 root JSON 与 sudo 文本体检。它不执行 CLI 修复。现有完整版安装演练和 Debian 12 amd64/arm64 systemd 容器矩阵继续保留；它们不能证明下面的真实 SSH 登录恢复已经通过。

## SSH 修复

四种路径各自从同一快照开始，使用系统自带的真实 `sshd` 和 `ssh.service` 或 `sshd.service`。不得用假 systemctl、回显脚本或容器中的模拟重载作为真实主机结果。对其他修复项逐项回答 `n`，不要用 `yes` 或管道自动确认。

每轮开始先做以下准备。

- [ ] 从带外控制台设置仅用于演练的密码登录基线，包含正确的 `Include` 和 `Match` 配置。`sudo /usr/sbin/sshd -t` 通过；记录配置文件及 drop-in 的摘要和元数据。用 `sshd -T` 核对实际参数，存在 Match 时使用实际测试用户、主机和来源地址的 `-C` 条件核对。
- [ ] 从自己的电脑分别新建一次密钥登录和密码登录。使用 `-o ControlMaster=no -o ControlPath=none` 禁用连接复用；密码测试还设置 `-o PubkeyAuthentication=no -o PreferredAuthentications=password -o KbdInteractiveAuthentication=no`，确保没有偷偷回退到密钥或已有连接。
- [ ] 保持会话 A 和带外控制台，确认没有上次演练留下的待确认回滚日志。记录开始时间、SSH 服务名以及密码认证基线。配置备份和私钥不贴到 PR。

### 确认新登录

- [ ] 在会话 A 运行 `sudo witshield check --fix`，只批准关闭 SSH 密码登录。看到配置预检、修改、验证及等待新登录的提示。
- [ ] 等待期间从自己的电脑新开会话 B，用密钥建立新连接并执行简单命令确认会话可用。不能用会话 A 仍未断开作为证据。
- [ ] 回到 A 输入 `yes`，确认收到已完成提示。用 `sshd -T` 核对 `passwordauthentication no`；新建密码连接应被拒绝，新建密钥连接仍成功。
- [ ] 超过原确认截止时间，再次验证密钥连接可用、密码连接被拒绝，回滚没有在已确认后触发。重新运行体检确认该发现已消失。

### 不确认，等待超时

- [ ] 恢复基线后运行 `sudo witshield check --fix`，批准 SSH 修改，记录默认 180 秒等待窗口和提示中的截止时间。
- [ ] 保持交互终端和输入流打开，既不输入也不关闭窗口，等待自动恢复。EOF 或输入 `n` 属于另外的路径，不能算超时测试。
- [ ] 记录实际等待时间，确认提示「已恢复原来的 SSH 配置」。核对配置摘要、属主和权限回到基线，`sshd -t` 通过。
- [ ] 从外部新建密码连接和密钥连接，均按基线成功。再执行只读体检，确认没有遗留待恢复状态。

### 等待确认时按 Ctrl-C

- [ ] 恢复基线后再次批准 SSH 修复。在明确出现新登录确认提示后按一次 Ctrl-C，记录按键到恢复提示的耗时。
- [ ] 确认立即开始恢复，没有一直等到 180 秒超时；允许真实服务重载所需时间。提示包含「已恢复原来的 SSH 配置」，若失败必须明确显示需要人工接管，不能记为 PASS。
- [ ] 核对配置摘要、权限和 `sshd -t`，从外部新建密码连接及密钥连接确认基线已恢复。记录进程退出码和实际服务状态。

### 等待确认时 kill -9，下一次启动恢复

- [ ] 恢复基线后再次批准 SSH 修复，等待新登录确认提示。用另一个会话核对该次 CLI 的 PID、可执行文件路径和参数，仅向这个进程发送 `sudo kill -9 <PID>`；不要使用 `pkill` 或匹配所有 witshield 进程。
- [ ] 从控制台确认 `/var/lib/witshield-cli/ssh-rollbacks` 中保留了该次恢复记录，不删除或改写日志。记录发生时是否已经由系统恢复；如果等待太久让自动恢复先完成，应重做本轮，不能据此宣称验证了启动恢复。
- [ ] 在恢复截止前立即以 root 运行只读的 `sudo witshield check --no-color`，不带修复参数。确认扫描前打印恢复说明、恢复配置并重载真实 SSH 服务。另恢复快照重做一次，用 `sudo witshield version` 验证其他 root 子命令也先恢复。
- [ ] 核对配置摘要、属主权限和 `sshd -t`，从外部新建密码及密钥连接确认基线可用。再次执行 root 命令不应重复改动已恢复配置；记录恢复日志状态。

普通用户没有恢复系统配置的权限，不能用非 root 启动代替这一项。kill -9 后进程自身不可能处理信号，本项验证的是持久日志和下一次 root 启动恢复。

### 没有 authorized_keys

- [ ] 单独克隆一台可通过带外控制台登录的测试机。在控制台备份并暂时移走本轮候选账号的 `authorized_keys`，至少检查 root 和执行 sudo 的测试用户；确认没有其他被实现识别的密钥位置。不要在唯一的远程入口上做这一步。
- [ ] 确保密码登录基线正常且扫描能发现密码认证开启。运行 `sudo witshield check --fix`，确认 SSH 修复在修改前就被拒绝，提示未找到公钥并说明先配置密钥。其他修复均回答 `n`。
- [ ] 对比配置摘要及权限，确认没有修改 SSH，没有创建这次操作的待确认恢复记录，密码新连接仍可用。恢复公钥后重新新建密钥连接。

## shadow 权限

- [ ] 从干净快照启动，记录 `sudo stat -c '%a %U %G' /etc/shadow`。不要打印或复制 shadow 正文。
- [ ] 仅在测试机执行 `sudo chmod 0644 /etc/shadow`，运行体检，确认报告权限过宽。
- [ ] 运行 `sudo witshield check --fix`，只批准 shadow 修复。确认需要主动输入 `y`，修复后 `stat` 为 `640 root shadow`；没有 shadow 组的系统应是实现支持的 `600 root root`。
- [ ] 再次体检确认该发现消失。记录没有改动其他路径、没有创建服务或额外账号；随后销毁测试机或恢复快照，避免保留弱权限样本。

## 软件包升级

准备一台含可升级软件包、使用受信任 APT 源的快照。不要为了制造更新问题把生产机降级；如使用本地测试源，只能放在独立演练网络中。没有待更新包时写 `NOT RUN`，不能用「未做任何修改」代替正常升级成功。

### 正常升级与包集合边界

- [ ] 先在测试准备阶段刷新 APT 元数据，保存 `apt-get -s upgrade` 的计划。升级前后分别将 `dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'` 的结果排序保存；公开证据只保留测试包名及版本。
- [ ] 运行 `sudo witshield check --fix`，只批准软件包升级。记录预览中的显式包列表（最多 64 个），再确认执行。
- [ ] 升级后核对每个已授权包的版本及 `dpkg --audit`。没有新增或删除包，没有升级预览列表以外的依赖，没有同版本重装，也没有顺便安装推荐包。除包的正常维护脚本外，CLI 没有安装服务或开启新端口。
- [ ] 另用独立快照构造必须新增包、删除包或改变未授权依赖的受控升级计划，确认在 dpkg 修改前拒绝。对比完整包清单，确认没有额外安装；无法准备这一前提时单独记 `NOT RUN`，不要记作 PASS。

### APT 锁冲突安全失败

- [ ] 恢复有待更新包的快照。用独立会话持有真实的 APT/dpkg POSIX 锁，记录持锁 PID、锁文件、起止时间。可使用测试机已有的 Python `fcntl.lockf` 持有 `/var/lib/dpkg/lock-frontend`，保持该进程和文件描述符打开；`flock` 不是同一种锁，不能代替这项验证。
- [ ] 在锁仍被持有时运行 `sudo witshield check --fix`，只批准升级。确认报告无法获得包管理锁、升级未完成，且没有虚报成功。预览已经因锁冲突失败也应如实记录发生阶段。
- [ ] 对比包版本和包集合，确认没有部分升级、新装或删除，不删除系统锁文件、不杀死正在工作的 apt/dpkg，不自动改为无锁执行。
- [ ] 结束自己的持锁进程，确认它确实退出，再运行 `dpkg --audit`。重新演练正常升级；若无法恢复或状态不明确，停止测试并恢复快照，不用新的包管理命令掩盖现场。

## 可选 DeepSeek 解读

只有获得允许使用的 API Key 和付费额度后才执行。没有授权凭据写 `NOT RUN（缺少授权 Key）`；使用本地假响应只证明协议或失败路径，不能记为 DeepSeek 已跑通。

- [ ] 使用不含真实服务器信息的测试机，确认报告内容适合发送给所选模型服务。以普通用户设置以下变量，Key 通过隐藏输入读取，不写进脚本、命令参数或终端录屏。

```bash
export WITSHIELD_AI_BASE_URL=https://api.deepseek.com/v1
export WITSHIELD_AI_MODEL=deepseek-chat
export WITSHIELD_AI_PROTOCOL=openai_chat
read -rs -p 'DeepSeek API Key: ' WITSHIELD_AI_API_KEY
printf '\n'
export WITSHIELD_AI_API_KEY
witshield check --ai --no-color
unset WITSHIELD_AI_API_KEY
```

- [ ] 记录实际请求耗时和响应成功状态，终端出现中文 AI 解读。检查发送内容不包含私钥、shadow 正文或 SSH 来源 IP；模型只得到该版本允许发送的报告摘要和统计。
- [ ] 确认没有自动发起修复、修改配置或安装包；模型请求失败时原始体检报告仍然可读，日志没有泄漏 API Key。清理凭据后普通体检仍可使用。

## 国内 Gitee 从零体验

在国内云厂商的全新实例上执行，记录地区和运营商即可，不公开真实地址。先核对本次 Release 镜像任务的结果和资产清单；没有同步成功就记录失败，不能把 GitHub 的结果填在 Gitee 栏。

- [ ] 没有缓存的 CLI、Cosign 或 Sigstore 信任数据，记录 CPU 架构和预装依赖。分别记录脚本下载、程序下载、SHA-256 验证、Sigstore 验证、体检、端到端耗时，以及每阶段失败和重试次数。
- [ ] 下载并阅读本次脚本，再固定版本运行。以下例子使用计划版本 `v0.4.0`，演练时替换为实际已发布的 tag。不要用修复参数。

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  -o check.sh https://gitee.com/witkitlab/witshield/releases/download/v0.4.0/check.sh
less check.sh
time bash check.sh --version v0.4.0 --mirror gitee --no-color
```

- [ ] 确认程序、SHA256SUMS、bundle 和固定版本 Cosign 从预期镜像取得；Cosign 的固定哈希与 GitHub 发布工作流的证书身份仍被验证。下载附件是否要求登录、是否限流、是否出现挑战页，都需要记录；下载到 HTML 不能算成功。
- [ ] 再执行一次 `--mirror gitee` 的默认 latest 路径，核对解析得到的严格 `vX.Y.Z` 版本与镜像最新正式版一致。记录冷启动和重复执行的耗时差异。
- [ ] 签名校验超过 30 秒或需要的信任服务不可达时记录具体阶段，不跳过校验。如采用发布的离线信任根方案，按该版实现验证其校验和及信任引导，单独记录结果并经审阅。
- [ ] 在独立的本地 HTTP 镜像夹具中复制本次资产，只改程序的一个字节，保留原校验和与 bundle，使用实现允许的测试下载地址运行。确认哈希不匹配时拒绝执行，且没有输出体检报告。再单独破坏 bundle，确认签名失败也不执行。不要改写公开 Gitee Release。
- [ ] 对比开始前后的包列表、服务、端口和配置，确认下载校验脚本没有顺带安装软件包、服务或修改安全配置，结束后临时程序被清理。记录成功体检的退出码，区分低分 1 与运行失败 2。

发布 PR 至少附上各系统结果表、四条 SSH 路径的真实重连证据、包清单差异、签名及 provenance 验证结果、国内分阶段耗时和未执行原因。未完成项目继续保留 `NOT RUN`，不得用计划内容补成通过记录。
