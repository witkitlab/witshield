# 发布与供应链

本仓库的正式发布由 `.github/workflows/release.yml` 完成，不在维护者电脑上手工拼包。

## 发布内容

标签 `vX.Y.Z` 对应：

- `witshield_X.Y.Z_linux_amd64.tar.gz`；
- `witshield_X.Y.Z_linux_arm64.tar.gz`；
- 与该版本源码一致的 `install.sh`；
- 每个包内的 Controller、普通用户 Agent、root Helper 三个二进制、Web 静态资源、systemd unit、卸载器、LICENSE 与 README；
- `SHA256SUMS`；
- SPDX JSON 与 CycloneDX JSON SBOM；
- `SHA256SUMS.bundle`（Sigstore/Cosign keyless 签名 bundle）；
- GitHub build provenance attestation；
- `ghcr.io/witkitlab/witshield:<version>`、`<major.minor>`、`latest` 与不可变 digest；
- 多架构镜像的 registry SBOM/provenance attestation 与 Cosign keyless 签名。

## 发布前门槛

```bash
test -z "$(gofmt -l $(find . -name '*.go' -not -path './web/node_modules/*'))"
go vet ./cmd/... ./internal/...
go test -race ./cmd/... ./internal/...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./cmd/... ./internal/...

cd web
npm ci
npm audit --audit-level=high
npm run lint
npm run typecheck
npm run test
npm run build:embedded

cd ..
bash -n scripts/*.sh scripts/tests/*.sh
shellcheck scripts/*.sh scripts/tests/*.sh
for test_script in scripts/tests/*.sh; do "$test_script"; done
```

还要完成：

- 从上一稳定版升级及备份恢复演练；
- Ubuntu/Debian 的 amd64/arm64 原生安装烟测；
- Docker Compose 约束检查；
- 空数据库 bootstrap、单机自动注册和多机一次性 token 注册；
- AI 三种协议的成功、超时、429、无效结构和脱敏测试；
- 修复审批、拒绝、取消、重启恢复、重复消息、验证失败和回滚；
- SSH 自动临时封禁的 allowlist、TTL、限速、重启与失联保护；
- 对抗性审查和威胁模型差异更新。

任何一项未达到都应在发布说明中标为不可用或实验性，而不是仅依靠文案承诺。

## 版本流程

1. 合并经 CI 和审查通过的变更；
2. 更新 README 状态、兼容性和迁移说明；
3. 创建受保护的、带签名的 annotated 语义化版本标签；
4. 推送标签触发 Release workflow；
5. 只读 `preflight` job 验证标签、`GITHUB_SHA` 与 `main` 的关系，重新运行完整测试，从标签源码构建归档、SBOM 和未发布的 Docker 烟测镜像；
6. 只有 preflight 全部通过后，`publish` job 才进入 `release` Environment 等待人工批准；
7. 批准后重新核对源码身份，下载 preflight 的短期制品，再登录 GHCR；
8. 多架构镜像先按不可变 digest 推送且不附加公开版本标签，随后用 GitHub OIDC 和 Cosign 完成 keyless 签名；
9. 把镜像 digest 写入 `CONTAINER_IMAGE.txt`，为安装器、归档、SBOM 和 digest 清单生成统一校验表并签名；
10. 生成 build provenance，把完整资产上传到草稿 Release，并逐项核对远端资产名称；
11. 最后把已签名 digest 提升为版本、次版本和 `latest` 镜像标签，再公开草稿 Release；
12. 在干净虚拟机用公开 Release 重做安装烟测，并发布安全与升级说明。

workflow 使用 keyless 制品签名，不保存长期 Cosign 私钥。只有 `publish` job 拥有 `contents: write`、`packages: write`、`id-token: write` 和 `attestations: write`；preflight 只有 `contents: read`，所有 checkout 都禁用凭据持久化。workflow 会拒绝以下输入：

- 非 `vX.Y.Z` 的稳定 SemVer；
- lightweight tag、嵌套 tag 或 GitHub 未验证签名的 annotated tag；
- 没有受 tag ruleset 保护的 tag；
- tag 指向与事件 `GITHUB_SHA` 不同、或不在 `main` 历史上的 commit；
- 已存在同名 GitHub Release 或不可变版本镜像标签的重复发布。

草稿 Release 若在镜像标签提升开始前失败会自动删除；一旦开始提升版本标签，workflow 会刻意保留草稿，以便核验并恢复已经部分公开的状态。镜像在草稿完整前只有不可变 digest，没有版本或 `latest` 标签。GitHub Release 与 GHCR 是两个独立系统，最终提升标签和公开 Release 无法形成跨系统数据库事务：如果 GitHub/网络恰好在最后两个步骤之间故障，维护者必须先核对 Release、三个镜像标签及 `CONTAINER_IMAGE.txt` 的 digest，确认一致后再决定恢复，不能盲目重跑或复用 tag。

仓库维护者必须在 GitHub 设置中额外完成以下一次性保护；workflow 文件本身不能代替仓库规则：

- 建立名为 `release` 的 Environment，配置至少一名 required reviewer，并禁止管理员绕过；
- 用 repository ruleset 保护 `v*` tag，只允许受控发布角色创建或更新；
- 保护发布来源分支并要求 CI、代码审查和线性历史；
- 限制 Actions workflow 修改权限，并定期复核具有仓库写权限和 Environment 审批权的人员。

发布者还必须在 GitHub 账号中登记 Git/GPG/SSH 签名公钥，并用对应私钥创建 annotated tag；这与 Cosign keyless 制品签名是两条独立信任链。workflow 不会创建、注册或托管维护者的长期签名密钥。

若这些设置尚未在实际仓库启用，不得宣称发布“需要维护者批准”或“受标签保护”；应先配置并用测试标签验证规则。

### 发布失败恢复

- preflight 失败：修复代码并重新走合并流程；不要移动或复用已经推送的版本 tag，应提升版本号。
- Environment 未批准：不会登录 GHCR，也不会产生 Release 或制品签名，可直接取消 workflow。
- publish 在草稿创建前失败：可能留下无版本标签的不可变镜像 digest/签名，不会成为 `latest`；保留日志后按新版本重新发布。
- publish 在草稿阶段失败：workflow 会删除由本次运行创建的草稿；仍需人工确认 GHCR 没有同名版本标签。
- 最终提升阶段失败：停止重跑，先比较远端标签 digest、Release 状态和本次日志；不得覆盖已有版本标签。

## 独立验证

```bash
cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity \
    "https://github.com/witkitlab/witshield/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS

sha256sum --check SHA256SUMS
```

随后检查归档：

```bash
scripts/verify-release-archive.sh witshield_X.Y.Z_linux_amd64.tar.gz
```

镜像使用 Release 中 `CONTAINER_IMAGE.txt` 的不可变 digest 验证：

```bash
cosign verify \
  --certificate-identity \
    "https://github.com/witkitlab/witshield/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$(cat CONTAINER_IMAGE.txt)"
```

验证签名只能证明制品由指定 GitHub workflow 构建，不能证明代码没有缺陷；还应核对 tag、源码审查、SBOM 和 provenance。

## SBOM 与依赖

- 同时发布源码依赖清单的 SPDX JSON 和 CycloneDX JSON；两份 SBOM、安装器、归档和镜像 digest 清单都进入签名后的 `SHA256SUMS`，容器镜像另带 registry SBOM/provenance attestation；
- Go module、npm、GitHub Actions 和 Docker 基础镜像由 Dependabot 检查；
- workflow/action 固定到审核过的 commit SHA，并由 Dependabot 提议更新；
- Docker 基础镜像同时保留可读 tag 并固定 digest，由 Dependabot 提议更新；
- 高危依赖告警需要判断是否实际构建和可达，但不能仅因“间接依赖”而忽略。

## 吊销与应急

若发布制品或工作流被怀疑污染：

1. 暂停最新版本入口与自动更新；
2. 保留证据，不覆盖原 Release；
3. 发布 GitHub Security Advisory，列出受影响 tag/digest；
4. 修复构建来源并发布新版本，不复用标签；
5. 指导用户验证当前二进制 hash、轮换可能暴露的设备/API 凭据并恢复；
6. 记录时间线、根因和后续保护措施。
