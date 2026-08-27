'use client';

import {
  ArrowRight,
  Bot,
  Check,
  Copy,
  Cpu,
  FileCheck2,
  GitBranch,
  Languages,
  LockKeyhole,
  Network,
  Radar,
  RotateCcw,
  ScanLine,
  ScrollText,
  Server,
  ShieldCheck,
  Sparkles,
  Terminal,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import styles from './marketing.module.css';

type Language = 'zh' | 'en';

const copy = {
  zh: {
    nav: { product: '产品', workflow: '工作方式', deploy: '部署', docs: '文档' },
    eyebrow: '开源 · 自托管 · 管理员掌控',
    title: '让每台服务器，\n都有一位懂边界的\n智能守卫。',
    lead: '妙计巡御持续检查风险、解释影响，在你批准后完成修复，并在明确授权的边界内响应攻击。',
    install: '一行命令安装',
    github: '查看 GitHub',
    demoLabel: '交互式产品演示',
    demoHint: '固定演示数据 · 不连接真实服务器',
    openDemo: '打开完整演示',
    statOne: '2 台',
    statOneLabel: '受保护设备',
    statTwo: '14 项',
    statTwoLabel: '本轮安全检查',
    statThree: '1 项',
    statThreeLabel: '等待管理员批准',
    guardOnline: '智能守卫在线',
    guardHealthy: '演示数据 · 策略链路正常',
    guardCore: '巡御核心',
    proofPoints: ['定时巡检', '风险证据', 'AI 解释', '管理员审批', '受限执行', '验证回滚'],
    scanComplete: '本轮巡检完成',
    scanTime: '刚刚 · 14 / 14 项',
    riskFound: '发现 1 项高优先级风险',
    approvalQueued: '修复计划等待管理员批准',
    workflowEyebrow: '从发现到闭环',
    workflowTitle: '不是再发一封告警，\n而是把问题处理完。',
    workflowLead: '规则负责事实，AI 负责解释，策略与管理员共同决定动作能否发生。每一步都有记录，每一次变更都要验证。',
    flowLegend: ['规则事实', 'AI 解释', '策略校验', '管理员批准', '受限执行'],
    workflowSteps: [
      { number: '01', title: '持续巡检', body: '按天或按周检查账号、SSH、敏感权限、端口、防火墙、软件更新与容器风险。' },
      { number: '02', title: '解释影响', body: '把可复现的证据交给你自己的 AI 服务，说明影响范围、优先级和处理思路。' },
      { number: '03', title: '预览并批准', body: '先展示将要执行的结构化计划、影响和回滚路径，再由管理员决定是否继续。' },
      { number: '04', title: '执行与验证', body: '受限执行器完成变更，重新扫描验证结果；失败时按预设路径停止或回滚。' },
    ],
    controlEyebrow: '边界优先',
    controlTitle: 'AI 提建议，\n策略决定能不能做。',
    controlLead: '巡御不把一个不受限制的 root Shell 交给模型。规则、审批、强类型动作与本机 Helper 共同构成安全边界。',
    controlProof: '模型输出不能绕过策略。自动响应只覆盖你明确授权、可逆、限时且有频率限制的本机防御动作。',
    policyLabel: '动作许可链',
    policyStages: ['AI 提案', '策略校验', '等待批准', 'Helper 执行'],
    controls: [
      { title: '默认等待批准', body: '修复与防御默认不会自动发生。', icon: LockKeyhole },
      { title: '强类型动作', body: '执行器只接受预先定义并校验的 Playbook。', icon: FileCheck2 },
      { title: '验证与回滚', body: '变更后重新检查，危险动作保留恢复路径。', icon: RotateCcw },
      { title: '完整审计', body: '计划、批准、执行、验证和回滚都有记录。', icon: ScrollText },
    ],
    deployEyebrow: '本地优先',
    deployTitle: '十分钟，把第一台服务器交给巡御。',
    deployLead: '单机模式把 Controller 与 Agent 装在同一台服务器；多机模式由一套自建控制台管理多个主动连接的 Agent。',
    commandLabel: '下载、审阅并安装最新签名版本',
    copy: '复制',
    copied: '已复制',
    nativeTitle: '原生安装',
    nativeBody: '支持完整巡检、经批准修复与自动防御。首发支持 Ubuntu / Debian，x86_64 与 arm64。',
    dockerTitle: 'Docker 观察模式',
    dockerBody: '适合快速体验和只读体检，不授予宿主机修复或自动防御权限。',
    deploymentGuide: '查看完整部署说明',
    openEyebrow: 'Open source',
    openTitle: '安全边界，应该能被检查。',
    openLead: '妙计巡御采用 Apache 2.0 许可证。你可以审计 Agent、Controller、执行器和安装链路，也可以使用自己的 AI API、模型和网络入口。',
    repository: '浏览源代码',
    threatModel: '阅读安全模型',
    currentStatus: '目前处于早期开发阶段。自动处置默认关闭；正式用于生产环境前，请验证备份与回滚路径。',
    footerLine: '妙计巡御 · AI Agent 服务器管家',
  },
  en: {
    nav: { product: 'Product', workflow: 'How it works', deploy: 'Deploy', docs: 'Docs' },
    eyebrow: 'Open source · Self-hosted · Admin controlled',
    title: 'An intelligent\nguard for every\nserver you run.',
    lead: 'WitShield AI continuously finds risk, explains impact, fixes issues after your approval, and responds to attacks within boundaries you define.',
    install: 'Install with one command',
    github: 'View on GitHub',
    demoLabel: 'Interactive product demo',
    demoHint: 'Fixed sample data · No real server connection',
    openDemo: 'Open full demo',
    statOne: '2',
    statOneLabel: 'protected servers',
    statTwo: '14',
    statTwoLabel: 'security checks',
    statThree: '1',
    statThreeLabel: 'awaiting approval',
    guardOnline: 'Agent guard online',
    guardHealthy: 'Fixture data · policy chain healthy',
    guardCore: 'Guard core',
    proofPoints: ['Scheduled scans', 'Risk evidence', 'AI explanation', 'Admin approval', 'Typed execution', 'Verify and roll back'],
    scanComplete: 'Inspection complete',
    scanTime: 'Just now · 14 / 14 checks',
    riskFound: '1 high-priority risk found',
    approvalQueued: 'Remediation plan awaits approval',
    workflowEyebrow: 'From signal to closure',
    workflowTitle: 'Not another alert.\nA problem carried to completion.',
    workflowLead: 'Rules establish facts. AI explains them. Policies and the administrator decide what may happen. Every step is recorded and every change is verified.',
    flowLegend: ['Rule facts', 'AI explanation', 'Policy check', 'Admin approval', 'Typed execution'],
    workflowSteps: [
      { number: '01', title: 'Inspect continuously', body: 'Check identities, SSH, sensitive permissions, ports, firewalls, security updates, and container exposure daily or weekly.' },
      { number: '02', title: 'Explain the impact', body: 'Give reproducible evidence to the AI service you choose, with scope, priority, and a concrete remediation approach.' },
      { number: '03', title: 'Preview and approve', body: 'See the structured plan, impact, and rollback path before an administrator decides whether it may proceed.' },
      { number: '04', title: 'Execute and verify', body: 'A constrained executor applies the change and scans again; failures stop or roll back along a defined path.' },
    ],
    controlEyebrow: 'Boundaries first',
    controlTitle: 'AI proposes.\nPolicy decides.',
    controlLead: 'WitShield never hands the model an unrestricted root shell. Rules, approvals, typed actions, and a local helper form the security boundary together.',
    controlProof: 'Model output cannot bypass policy. Automated response is limited to reversible, time-bound, rate-limited defenses you explicitly authorize on your own hosts.',
    policyLabel: 'Action permission chain',
    policyStages: ['AI proposal', 'Policy check', 'Await approval', 'Helper execution'],
    controls: [
      { title: 'Approval by default', body: 'Remediation and defense do not happen automatically.', icon: LockKeyhole },
      { title: 'Typed actions', body: 'The executor accepts only predefined, validated playbooks.', icon: FileCheck2 },
      { title: 'Verify and roll back', body: 'Changes are checked again and risky actions keep a recovery path.', icon: RotateCcw },
      { title: 'Complete audit trail', body: 'Plans, approvals, execution, verification, and rollback are recorded.', icon: ScrollText },
    ],
    deployEyebrow: 'Local first',
    deployTitle: 'Put your first server under guard in ten minutes.',
    deployLead: 'Standalone mode runs the Controller and Agent together. Hub mode lets one self-hosted console manage many outbound-connecting Agents.',
    commandLabel: 'Download, review, and install the latest signed release',
    copy: 'Copy',
    copied: 'Copied',
    nativeTitle: 'Native installation',
    nativeBody: 'Full inspection, approved remediation, and automated defense. Ubuntu / Debian on x86_64 and arm64 are supported first.',
    dockerTitle: 'Docker observer mode',
    dockerBody: 'A constrained read-only evaluation path. It cannot remediate the host or run automated defense.',
    deploymentGuide: 'Read the deployment guide',
    openEyebrow: 'Open source',
    openTitle: 'Security boundaries should be inspectable.',
    openLead: 'WitShield AI is Apache 2.0 licensed. Audit the Agent, Controller, executor, and release chain, and bring your own AI API, model, and network entry point.',
    repository: 'Browse the source',
    threatModel: 'Read the threat model',
    currentStatus: 'WitShield is in early development. Automated remediation is off by default; validate backup and rollback paths before production use.',
    footerLine: 'WitShield AI · Agentic server manager',
  },
} as const;

const installCommand = `curl --proto '=https' --tlsv1.2 -fsSLo install.sh \\
  https://github.com/witkitlab/witshield/releases/latest/download/install.sh && \\
less install.sh && sudo bash install.sh --mode standalone`;

export function MarketingHome() {
  const [language, setLanguage] = useState<Language>('zh');
  const [copied, setCopied] = useState(false);
  const text = copy[language];

  useEffect(() => {
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
  }, [language]);

  async function copyInstallCommand() {
    try {
      await navigator.clipboard.writeText(installCommand);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 3200);
    } catch {
      setCopied(false);
    }
  }

  return (
    <main className={styles.site}>
      <header className={styles.header}>
        <a className={styles.logo} href="#top" aria-label={language === 'zh' ? '妙计巡御首页' : 'WitShield AI home'}>
          <span className={styles.logoMark}><ShieldCheck size={17} strokeWidth={2.2} /></span>
          <span><strong>妙计巡御</strong><small>WitShield AI</small></span>
        </a>
        <nav className={styles.nav} aria-label={language === 'zh' ? '官网导航' : 'Site navigation'}>
          <a href="#product">{text.nav.product}</a>
          <a href="#workflow">{text.nav.workflow}</a>
          <a href="#deploy">{text.nav.deploy}</a>
          <a href="https://github.com/witkitlab/witshield#readme">{text.nav.docs}</a>
        </nav>
        <div className={styles.headerActions}>
          <button className={styles.language} onClick={() => setLanguage(language === 'zh' ? 'en' : 'zh')} aria-label={language === 'zh' ? 'Switch to English' : '切换至中文'}>
            <Languages size={15} /> {language === 'zh' ? 'EN' : '中文'}
          </button>
          <a className={styles.headerGithub} href="https://github.com/witkitlab/witshield" target="_blank" rel="noreferrer"><GitBranch size={16} /> GitHub</a>
        </div>
      </header>

      <section className={styles.hero} id="top">
        <div className={styles.heroCopy}>
          <p className={styles.eyebrow}>{text.eyebrow}</p>
          <h1>{text.title.split('\n').map((line) => <span key={line}>{line}</span>)}</h1>
          <p className={styles.lead}>{text.lead}</p>
          <div className={styles.ctas}>
            <a className={styles.primaryCta} href="#deploy"><Terminal size={16} />{text.install}<ArrowRight size={15} /></a>
            <a className={styles.secondaryCta} href="https://github.com/witkitlab/witshield" target="_blank" rel="noreferrer"><GitBranch size={16} />{text.github}</a>
          </div>
        </div>
        <div className={styles.heroVisual} role="group" aria-label={language === 'zh' ? '固定演示环境的智能守卫运行概况' : 'Agent guard status using fixed demo data'}>
          <div className={styles.heroHud}>
            <span><i />{text.guardOnline}</span>
            <small>{text.guardHealthy}</small>
          </div>
          <div className={styles.topology} aria-hidden="true">
            <i className={styles.signalOne} />
            <i className={styles.signalTwo} />
            <i className={styles.signalThree} />
            <div className={`${styles.serverNode} ${styles.serverNodeOne}`}><Server size={14} /><span>edge-sg-01</span><b /></div>
            <div className={`${styles.serverNode} ${styles.serverNodeTwo}`}><Server size={14} /><span>dev-bj-02</span><b /></div>
            <div className={styles.guardCore}><span><ShieldCheck size={24} /></span><small>{text.guardCore}</small></div>
            <span className={`${styles.pulseNode} ${styles.pulseNodeOne}`} />
            <span className={`${styles.pulseNode} ${styles.pulseNodeTwo}`} />
          </div>
          <div className={styles.guardActivity}>
            <div><span><Check size={13} />{text.scanComplete}</span><small>{text.scanTime}</small></div>
            <div><span className={styles.riskSignal}>{text.riskFound}</span><small>{text.approvalQueued}</small></div>
          </div>
          <dl className={styles.heroStats}>
            <div><dt>{text.statOne}</dt><dd>{text.statOneLabel}</dd></div>
            <div><dt>{text.statTwo}</dt><dd>{text.statTwoLabel}</dd></div>
            <div><dt>{text.statThree}</dt><dd>{text.statThreeLabel}</dd></div>
          </dl>
        </div>
      </section>

      <section className={styles.productSection} id="product">
        <div className={styles.demoHeading}>
          <div><span className={styles.liveDot} />{text.demoLabel}<small>{text.demoHint}</small></div>
          <a href="/demo" target="_blank">{text.openDemo}<ArrowRight size={14} /></a>
        </div>
        <div className={styles.demoFrame}>
          <div className={styles.windowBar} aria-hidden="true"><i /><i /><i /><span>demo.witshield.local</span><em>FIXTURE / ISOLATED</em></div>
          <div className={styles.demoViewport}>
            <iframe src="/demo" title={text.demoLabel} />
          </div>
        </div>
        <ul className={styles.proofRail} aria-label={language === 'zh' ? '妙计巡御核心闭环能力' : 'WitShield core control-loop capabilities'}>
          {text.proofPoints.map((item, index) => <li key={item}><span>{String(index + 1).padStart(2, '0')}</span>{item}</li>)}
        </ul>
      </section>

      <section className={styles.workflow} id="workflow">
        <div className={styles.sectionIntro}>
          <p className={styles.sectionEyebrow}>{text.workflowEyebrow}</p>
          <h2>{text.workflowTitle.split('\n').map((line) => <span key={line}>{line}</span>)}</h2>
          <p>{text.workflowLead}</p>
          <div className={styles.flowLegend} aria-label={language === 'zh' ? '巡御处理链路' : 'WitShield processing chain'}>
            {text.flowLegend.map((item, index) => <span key={item}><i>{index + 1}</i>{item}</span>)}
          </div>
        </div>
        <ol className={styles.workflowList}>
          {text.workflowSteps.map((step) => (
            <li key={step.number}>
              <span>{step.number}</span>
              <div><h3>{step.title}</h3><p>{step.body}</p></div>
              <ArrowRight size={17} aria-hidden="true" />
            </li>
          ))}
        </ol>
      </section>

      <section className={styles.controlSection}>
        <div className={styles.controlCopy}>
          <p className={styles.sectionEyebrow}>{text.controlEyebrow}</p>
          <h2>{text.controlTitle.split('\n').map((line) => <span key={line}>{line}</span>)}</h2>
          <p>{text.controlLead}</p>
          <div className={styles.policyFlow}>
            <small><Network size={13} />{text.policyLabel}</small>
            <div>{text.policyStages.map((stage, index) => <span key={stage} data-pending={index === 2 ? 'true' : undefined}><i />{stage}</span>)}</div>
          </div>
          <div className={styles.controlProof}><ShieldCheck size={20} /><span>{text.controlProof}</span></div>
        </div>
        <div className={styles.controlGrid}>
          {text.controls.map(({ title, body, icon: Icon }) => (
            <article key={title}><Icon size={19} /><h3>{title}</h3><p>{body}</p></article>
          ))}
        </div>
      </section>

      <section className={styles.deploySection} id="deploy">
        <div className={styles.deployIntro}>
          <p className={styles.sectionEyebrow}>{text.deployEyebrow}</p>
          <h2>{text.deployTitle}</h2>
          <p>{text.deployLead}</p>
        </div>
        <div className={styles.installPanel}>
          <div className={styles.codeHeading}>
            <span><Terminal size={15} />{text.commandLabel}</span>
            <button onClick={() => void copyInstallCommand()} aria-live="polite">
              {copied ? <Check size={14} /> : <Copy size={14} />}{copied ? text.copied : text.copy}
            </button>
          </div>
          <pre><code>{installCommand}</code></pre>
        </div>
        <div className={styles.deployModes}>
          <article><Server size={19} /><div><h3>{text.nativeTitle}</h3><p>{text.nativeBody}</p></div></article>
          <article><Radar size={19} /><div><h3>{text.dockerTitle}</h3><p>{text.dockerBody}</p></div></article>
          <a href="https://github.com/witkitlab/witshield/blob/main/docs/operations.md" target="_blank" rel="noreferrer">{text.deploymentGuide}<ArrowRight size={14} /></a>
        </div>
      </section>

      <section className={styles.openSection}>
        <p className={styles.sectionEyebrow}>{text.openEyebrow}</p>
        <div>
          <h2>{text.openTitle}</h2>
          <div className={styles.openCopy}>
            <p>{text.openLead}</p>
            <div className={styles.openActions}>
              <a href="https://github.com/witkitlab/witshield" target="_blank" rel="noreferrer"><GitBranch size={16} />{text.repository}</a>
              <a href="https://github.com/witkitlab/witshield/blob/main/docs/threat-model.md" target="_blank" rel="noreferrer">{text.threatModel}<ArrowRight size={14} /></a>
            </div>
            <div className={styles.openSignals} aria-hidden="true">
              <span><Bot size={14} />AGENT</span><span><Cpu size={14} />HELPER</span><span><ScanLine size={14} />SCANNER</span><span><Sparkles size={14} />YOUR AI</span>
            </div>
          </div>
        </div>
      </section>

      <aside className={styles.statusNote}><span>v0.1</span><p>{text.currentStatus}</p></aside>

      <footer className={styles.footer}>
        <a className={styles.logo} href="#top"><span className={styles.logoMark}><ShieldCheck size={17} /></span><span><strong>妙计巡御</strong><small>WitShield AI</small></span></a>
        <p>{text.footerLine}</p>
        <div><a href="https://github.com/witkitlab/witshield">GitHub</a><a href="https://github.com/witkitlab/witshield/blob/main/SECURITY.md">Security</a><span>Apache 2.0</span></div>
      </footer>
    </main>
  );
}
