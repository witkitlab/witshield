# 参与贡献

感谢参与妙盾。安全 Agent 的“小改动”也可能影响服务器可用性，因此贡献需要清晰边界、可重复测试和失败路径。

## 开始之前

- 功能或架构变更先创建 Issue，说明威胁、权限、失败模式和兼容性；
- 安全漏洞走 [SECURITY.md](SECURITY.md)，不要公开提交；
- 不要提交 API Key、令牌、真实服务器日志、数据库、证书或 `.env`；
- 不要加入 hack-back、凭据利用、外部未授权扫描等能力；
- 修复与自动动作必须是结构化动作，不能把模型文本直接拼成 shell。

## 本地开发

需要 Go `1.26.7` 或更新的兼容安全补丁版本。若修改前端，还需要仓库前端配置声明的 Node.js 版本。

```bash
git clone https://github.com/witkitlab/witshield.git
cd witshield
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
```

建议启用：

```bash
go test -race ./cmd/... ./internal/...
go test -coverprofile=coverage.out ./cmd/... ./internal/...
```

如果修改 shell：

```bash
shellcheck scripts/*.sh
bash -n scripts/*.sh
```

如果修改 Web：

```bash
cd web
npm ci
npm run lint
npm run typecheck
npm test
npm run build:embedded
```

## 设计约束

### 采集与检测

- 采集器默认只读，并声明读取的数据范围；
- Finding 必须包含规则 ID、证据、影响对象、严重性和稳定指纹；
- 规则结果应可在没有 AI 的情况下复现；
- 报告中不得默认收集密钥正文、完整环境变量或无关文件内容。

### 修复与自动防御

动作应实现 `precheck → preview → authorize → apply → verify → rollback`，并明确：

- 最小权限与支持的系统；
- 幂等性；
- 超时、并发和频率限制；
- 可恢复状态与回滚条件；
- 哪些失败需要停止而不是继续；
- 对管理员连接、网络与关键服务的影响。

禁止让模型生成的任意 shell 直接进入特权执行路径。实验性的自动动作必须默认关闭、可撤销、带 TTL、白名单和明确作用域的紧急停止；当前实现的作用域是单设备。

### 协议与兼容性

- Agent 只主动连接 Controller；
- 网络消息需要稳定版本号、大小上限、重放保护与严格验证；
- 数据库变更必须可迁移并测试旧版本升级；
- 公共 API 和配置项的行为变更需要更新 `docs/`。

## Pull Request 检查表

- [ ] PR 只解决一个清晰问题，描述了用户影响；
- [ ] 新行为有单元/集成测试，也覆盖失败和取消路径；
- [ ] 权限、数据流、日志和回滚影响已评估；
- [ ] 无新增秘密、测试私钥或真实用户数据；
- [ ] 文档、配置示例和变更记录已更新；
- [ ] `go test -race ./cmd/... ./internal/...`、`go vet ./cmd/... ./internal/...` 与相关前端测试通过；
- [ ] 对抗性检查过提示注入、参数注入、路径穿越、SSRF、重放和并发竞态；
- [ ] 改动没有扩大默认网络暴露或自动处置范围。

## 提交与许可证

提交信息建议使用简短祈使句，例如 `agent: reject expired enrollment token`。向本仓库提交贡献，即表示你有权提交，并同意该贡献按 [Apache-2.0](LICENSE) 发布。
