# 终端演示素材

[`check.gif`](check.gif) 用于中英文 README；[`web/public/check-demo.gif`](../../web/public/check-demo.gif) 是逐字节相同的官网副本。

## 来源与边界

当前 GIF 是 **Pillow 对真实虚拟机 stdout / PTY 的节奏重排重播**，不是 VHS 实时录屏。素材来自获授权的隔离 Debian 12.15 amd64 QEMU TCG 完整虚拟机，运行真实 Linux `6.1.0-54-cloud-amd64` 内核、PID 1 `systemd` 和 `ssh.service`；systemd 版本为 `252.39-1~deb12u2`。SSH 经宿主侧回环端口转发建立到 guest 的全新 TCP 连接，没有使用 `systemctl` 适配器。主机名已统一为 `demo-vps`。

录制使用的是较早的 **dfa093f 构建（包含 be7c87e CLI 硬化）**，并非最终 v0.4.0 签名发布制品。程序的 `version` 输出仍含 `commit unknown, built unknown`；实际构建提交采用 `go version -m` 内嵌的 `vcs.revision`，其 `vcs.modified=false`。构建来源如下。

| 项目 | 记录 |
| --- | --- |
| 实际构建提交 | `dfa093f35f7d569071ef83fa58907c3b0597e956` |
| 其中的 CLI 硬化提交 | `be7c87e45ce075dd26375e71b1f300582708a744` |
| 程序 SHA-256 | `c6175de872ee349ac970d95e0e5ea0d4a6adf602ca4d222ffca5cca33757ff55` |
| 版本输出 | `witshield v0.4.0-dev (commit unknown, built unknown)` |

演示中的实际变化为关闭 SSH 密码认证，以及把 `/etc/shadow` 权限从 `0644` 修为 `root:shadow 0640`。修复前，密码认证探测明确以 `password` 方法成功、退出码为 0；同一探测关闭公钥认证、键盘交互认证和连接复用。确认修改时，录制器先建立另一条全新密钥 SSH 连接，成功后才提交 `yes`。修复后新密钥连接仍成功，密码认证专用探测被拒绝、退出码为 255。密钥探测使用 `BatchMode=yes`、`IdentitiesOnly=yes`、指定测试密钥以及 `ControlMaster=no` / `ControlPath=none`；录制后另一次独立复验明确观察到 `publickey` 认证成功，该复验在 capture 中单独标明为 post-capture，没有冒充录制中的时间点。

旧 dfa093f 构建的成功行写着“SSH 已改为只允许密钥登录”，capture 和画面保留实录原文，并另加范围注释。本次变更仅关闭 `PasswordAuthentication`，不涵盖键盘交互等其他 SSH 认证机制。当前集成代码已采用“密码认证已关闭”的准确表述；本次素材没有把较新程序的文字补进旧录制。

报告分数从 **58 变为 87**，问题从 **5 个变为 3 个**。两次均只完成 **7/8 项检查，覆盖率 87%**；guest 没有 `ufw` / `nft`，防火墙检查未完成。root 密钥直接登录、内核指针地址暴露和开放端口仍需评估。SSH 登录失败计数原样保留为前后 **9 次和 10 次**，来自这台隔离 guest 的认证探测，不能据此推断公网攻击规模。87 分不代表完整安全审计或“已经安全”。

[`capture.json`](capture.json) 只采用标记为 PASS 的 `valid-capture-debian12-amd64` 导出，保存去标识后的完整前后报告、真实 PTY 分块与相对时间戳、实际输入事件、探测方法和结果。没有混入失败或无效的录制。源导出已使用 `demo-vps` 并把 IP 字面量替换为 `[IP]`；未导出凭据、密钥正文、known_hosts、SSH 指纹或私有测试执行器代码。`sourceSHA256` 记录输入源文件的 SHA-256，`binarySHA256` 记录程序摘要，均不是 SSH 指纹。

交互录制器记录的实际耗时为 **6.235 秒**，以 `fix.metadata.json` 为准；概览元数据较低精度的 **6.23 秒** 也在 capture 中原样保留。GIF 按预览、二次登录确认、权限修复和重新体检分镜停留，总时长 **25.5 秒**。报告有节选，长行按画幅重新换行，完整原文与原始相对时间可在 capture 中核对。顶部“调用说明”和底部“录制动作”“录制验证”都是画面注释，不是 CLI 输出或 shell 回显。实际命令由 SSH exec 启动，录制器还包装了 PID 跟踪；完整 argv 位于 `source.commands`。终端中的 `y` / `yes` 只取自真实 guest PTY 收到的回显，没有合成打字或补写输入。本次确认窗口为 60 秒，产品默认仍为 180 秒。

## 重建当前 GIF

需要 Python 3、Pillow，以及系统字体 `NotoSansCJK-Regular.ttc`。渲染器选用 TTC 内的 `Noto Sans Mono CJK SC`（索引 7）显示终端；所有帧共享固定调色板。

在仓库根目录运行：

```bash
python3 docs/demo/render.py --preview-dir /tmp/witshield-demo-preview
```

脚本检查报告分数、检查数和问题数与元数据一致，核对 PTY 拼接内容及时间戳，并要求密码成功基线、新建密钥连接和修复后密码拒绝的证据。它同时生成 README 和官网 GIF，检查尺寸为 `1440×900`、时长在 25 秒到 30 秒以内、文件小于 3 MiB，并验证两份副本完全一致；最后打印实际文件大小、帧数、时长和 SHA-256。预览 PNG 仅写入指定的临时目录。渲染只读取已去标识的 capture，不连接服务器或执行修复。

本次使用 Pillow `12.3.0` 生成并重新解码验收，结果为 **51 帧、25,500 毫秒、361,985 字节**，尺寸 **1440×900**；两份 GIF 的字节完全相同。SHA-256 为 `791d6020de7d1ca93fd28a5c9bd1843bebc64d1d144c4995af961a5081d8bd66`。已目视检查体检、预览、SSH 等待确认、shadow 预览、完成和复查六个关键画面。

## 用 VHS 重新实时录制

[`check.tape`](check.tape) 是供后续虚拟机重新录制的 VHS 脚本，**没有用于生成当前 GIF，也尚未由 VHS 执行验证**。先在可销毁的 Ubuntu/Debian 虚拟机准备相应问题、安装 CLI，缓存 sudo 认证，并保留独立备份和带外控制台。不得在生产机器运行，也不要为了演示降低现有服务器的权限。

脚本会批准 SSH 和 shadow 两项变更，只适用于恰好出现这两项可修复问题的演示机；若出现包升级、不同提示或步骤顺序，先调整脚本。修改 SSH 后的 8 秒停留期间，需要从另一个终端建立全新密钥连接；失败时立即中断，不能继续提交 `yes`。运行前再次核对输入时机，录制后逐帧审查。不同虚拟机的分数、问题和运行时间以实测为准，不能为了复现 58→87 修改报告。

```bash
WITSHIELD_DEMO_DISPOSABLE=yes vhs docs/demo/check.tape
```

重新录制会覆盖 `docs/demo/check.gif`，需另行同步官网副本、控制体积与时长，并记录新证据。当前素材只证明这台 Debian 12 amd64 QEMU guest 的本次确认修复场景，不能代替其他发行版和架构、SSH 恢复分支、APT、AI 或国内下载矩阵；发布演练仍以[手工清单](../testing-check-cli.md)为准。
