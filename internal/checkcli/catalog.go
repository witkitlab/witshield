// Package checkcli implements `witshield check`: a one-shot, no-daemon health
// check that explains each finding in plain Chinese and, with --fix, repairs
// the fixable ones through the same typed playbooks the root Helper uses.
package checkcli

import (
	"github.com/witkitlab/witshield/internal/domain"
)

// FixKind names a finding that has a typed one-step repair. Everything else
// gets copyable manual guidance only; the CLI never runs free-form commands.
type FixKind string

const (
	FixNone          FixKind = ""
	FixSSHPassword   FixKind = "ssh_password"
	FixShadowPerm    FixKind = "shadow_permission"
	FixPackageUpdate FixKind = "package_update"
)

// Advice is the user-facing explanation of one scanner finding.
type Advice struct {
	Title  string
	Why    string
	Manual []string
	Fix    FixKind
}

// catalog is keyed by the scanner's stable English finding title.
var catalog = map[string]Advice{
	"SSH password authentication is enabled": {
		Title: "SSH 允许密码登录",
		Why:   "公网上的服务器每天都会被自动脚本反复猜密码，只要密码被猜中一次，服务器就归别人了。改成只用密钥登录后，这类攻击基本无效。",
		Manual: []string{
			"先确认自己能用密钥登录（ssh-copy-id 用户名@服务器）",
			"编辑 /etc/ssh/sshd_config，设置 PasswordAuthentication no",
			"sudo sshd -t && sudo systemctl reload ssh",
		},
		Fix: FixSSHPassword,
	},
	"Direct root SSH login is enabled": {
		Title: "允许 root 直接用密码登录 SSH",
		Why:   "root 是攻击者最先猜的用户名，一旦登录成功就拥有全部权限。建议用普通用户登录，需要时再 sudo。",
		Manual: []string{
			"先建一个普通用户并加入 sudo 组：sudo adduser 用户名 && sudo usermod -aG sudo 用户名",
			"编辑 /etc/ssh/sshd_config，设置 PermitRootLogin prohibit-password（或 no）",
			"sudo sshd -t && sudo systemctl reload ssh",
		},
	},
	"Root SSH login is allowed with keys": {
		Title: "root 可以用密钥直接登录 SSH",
		Why:   "风险不大，但 root 密钥一旦泄露，影响就是整台服务器。更稳妥的做法是用普通用户登录再 sudo。",
		Manual: []string{
			"确认普通用户能登录并 sudo 后，把 /etc/ssh/sshd_config 中的 PermitRootLogin 改为 no",
		},
	},
	"Additional UID 0 accounts found": {
		Title: "存在 root 以外的超级用户账号",
		Why:   "除了 root，还有账号拥有最高权限。如果不是你自己建的，很可能是入侵后留下的后门。",
		Manual: []string{
			"查看是哪些账号：awk -F: '$3==0' /etc/passwd",
			"确认不是自己建的，先锁定再排查：sudo usermod -L 账号名",
		},
	},
	"/etc/shadow is accessible to other users": {
		Title: "/etc/shadow 权限过宽",
		Why:   "这个文件保存所有用户的密码哈希，普通用户能读到就能离线暴力破解密码。",
		Manual: []string{
			"sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow",
		},
		Fix: FixShadowPerm,
	},
	"Services listen on non-loopback interfaces": {
		Title: "有服务对外开放端口",
		Why:   "不一定是问题，但每个对外端口都是一个入口。数据库、Redis、管理面板这类服务通常不该直接暴露在公网。",
		Manual: []string{
			"查看是哪些程序在监听：sudo ss -ltnp",
			"只在本机用的服务改为监听 127.0.0.1；需要对外的，在防火墙或云服务器安全组里只放行必要端口",
		},
	},
	"Host firewall is inactive": {
		Title: "服务器防火墙没有开启",
		Why:   "没有防火墙时，所有监听的端口都直接暴露在公网。云服务器的安全组能挡一部分，但最好两层都有。",
		Manual: []string{
			"先放行 SSH，避免把自己关在外面：sudo ufw allow OpenSSH（如果改过 SSH 端口，改成 sudo ufw allow 端口号/tcp）",
			"再放行网站等需要对外的端口，例如：sudo ufw allow 80,443/tcp",
			"最后开启：sudo ufw enable，并保持当前窗口，新开一个窗口确认还能登录",
		},
	},
	"System packages have pending updates": {
		Title: "有待安装的系统更新",
		Why:   "很多入侵利用的是早已修复的漏洞，只是服务器一直没更新。及时更新是最便宜的防护。",
		Manual: []string{
			"sudo apt update && sudo apt upgrade",
			"重要服务器先做快照或备份",
		},
		Fix: FixPackageUpdate,
	},
	"Docker socket is accessible to all users": {
		Title: "Docker 接口对所有用户开放",
		Why:   "能访问 Docker 接口就等于拥有 root 权限。任何普通用户、甚至被入侵的网站进程都能借它控制整台服务器。",
		Manual: []string{
			"sudo chmod 660 /var/run/docker.sock",
			"检查 docker 组里只有你信任的用户：getent group docker",
		},
	},
	"Full address-space randomization is disabled": {
		Title:  "内核地址随机化（ASLR）没有完全开启",
		Why:    "关闭后，内存漏洞更容易被稳定利用。",
		Manual: []string{"echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/90-witshield.conf && sudo sysctl --system"},
	},
	"Protected hard links are disabled": {
		Title:  "硬链接保护没有开启",
		Why:    "普通用户可能借硬链接绕过文件权限。",
		Manual: []string{"echo 'fs.protected_hardlinks = 1' | sudo tee -a /etc/sysctl.d/90-witshield.conf && sudo sysctl --system"},
	},
	"Protected symbolic links are disabled": {
		Title:  "符号链接保护没有开启",
		Why:    "公共可写目录（如 /tmp）里更容易发生符号链接攻击。",
		Manual: []string{"echo 'fs.protected_symlinks = 1' | sudo tee -a /etc/sysctl.d/90-witshield.conf && sudo sysctl --system"},
	},
	"TCP SYN cookies are disabled": {
		Title:  "TCP SYN Cookie 没有开启",
		Why:    "遇到 SYN 洪水攻击时，服务器更容易无法响应正常连接。",
		Manual: []string{"echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.d/90-witshield.conf && sudo sysctl --system"},
	},
	"Kernel logs are readable by unprivileged users": {
		Title:  "普通用户可以读取内核日志",
		Why:    "内核日志里的地址和系统细节，能帮本地攻击者提权。",
		Manual: []string{"echo 'kernel.dmesg_restrict = 1' | sudo tee -a /etc/sysctl.d/90-witshield.conf && sudo sysctl --system"},
	},
	"Kernel pointer exposure is not restricted": {
		Title:  "内核指针地址没有隐藏",
		Why:    "暴露的内核地址会让本地提权更容易成功。",
		Manual: []string{"echo 'kernel.kptr_restrict = 1' | sudo tee -a /etc/sysctl.d/90-witshield.conf && sudo sysctl --system"},
	},
}

// AdviceFor returns the Chinese explanation for a finding, falling back to the
// scanner's own English text for a title the catalog does not know yet.
func AdviceFor(f domain.Finding) Advice {
	if a, ok := catalog[f.Title]; ok {
		return a
	}
	a := Advice{Title: f.Title, Why: f.Description}
	if f.Remediation != "" {
		a.Manual = []string{f.Remediation}
	}
	return a
}

var severityLabel = map[domain.Severity]string{
	domain.SeverityCritical: "严重",
	domain.SeverityHigh:     "高危",
	domain.SeverityMedium:   "中危",
	domain.SeverityLow:      "低危",
	domain.SeverityInfo:     "提示",
}

var severityRank = map[domain.Severity]int{
	domain.SeverityCritical: 0,
	domain.SeverityHigh:     1,
	domain.SeverityMedium:   2,
	domain.SeverityLow:      3,
	domain.SeverityInfo:     4,
}

// Grade turns a score into the one word people remember.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "优秀"
	case score >= 75:
		return "良好"
	case score >= 60:
		return "及格"
	default:
		return "危险"
	}
}
