import Link from 'next/link';
import {
  ArrowRight,
  Blocks,
  Bot,
  Boxes,
  Braces,
  Check,
  CircleGauge,
  CloudCog,
  FileCheck2,
  GitPullRequestArrow,
  KeyRound,
  Network,
  Radar,
  Scale,
  ShieldCheck,
  Siren,
  MessagesSquare,
  TerminalSquare,
  Workflow,
} from 'lucide-react';
import { AgentDemo } from '@/components/agent-demo';
import { Brand } from '@/components/brand';
import { CopyCommand } from '@/components/copy-command';

const capabilities = [
  {
    icon: Siren,
    label: 'Incident investigation',
    title: 'Move from alert to evidence.',
    copy: 'Trace crash loops, degraded rollouts, failed jobs, noisy logs, and cloud symptoms across the systems already in your path.',
    tags: ['Kubernetes', 'CloudWatch', 'Logs', 'Events'],
  },
  {
    icon: GitPullRequestArrow,
    label: 'CI recovery',
    title: 'Explain the failure. Propose the fix.',
    copy: 'Inspect GitHub Actions runs, connect the failing job to source, and keep remediation inside a reviewable pull request.',
    tags: ['GitHub Actions', 'Run logs', 'Scoped PRs'],
  },
  {
    icon: CloudCog,
    label: 'Cloud posture',
    title: 'Read broadly. Write narrowly.',
    copy: 'Investigate AWS, Google Cloud, and Azure with curated command families while provider-wide deployment and IAM changes stay denied.',
    tags: ['AWS', 'Google Cloud', 'Azure'],
  },
  {
    icon: Workflow,
    label: 'Guarded operations',
    title: 'Turn intent into a bounded change.',
    copy: 'Apply, roll out, scale, or roll back only when policy, credential scope, dry-run, approval, and an expiring capability all agree.',
    tags: ['Dry run', 'Approvals', 'Loop limits'],
  },
];

const interfaces = [
  {
    icon: TerminalSquare,
    title: 'CLI',
    copy: 'Stream investigations from a local REPL with per-turn cost and policy feedback.',
  },
  {
    icon: Bot,
    title: 'Operations UI',
    copy: 'Private agent chat, live runs, approvals, policy decisions, spend, and audit integrity.',
  },
  {
    icon: MessagesSquare,
    title: 'Slack',
    copy: 'Thread-aware chat-ops with identity mapping and the same escalation boundary.',
  },
  {
    icon: Braces,
    title: 'HTTP + webhooks',
    copy: 'Receive Alertmanager and GitHub events through authenticated, deduplicated routes.',
  },
  {
    icon: Radar,
    title: 'Scheduler',
    copy: 'Run drift, certificate, backup, and hygiene checks with fixed anti-overlap controls.',
  },
  {
    icon: Network,
    title: 'Remote executor',
    copy: 'Keep write credentials inside isolated environment-and-channel workers.',
  },
];

const guardrails = [
  ['01', 'Request', 'Natural-language intent enters through an identity-aware interface.'],
  ['02', 'Budget', 'Call, tool, recursion, time, and USD stop-losses are checked.'],
  ['03', 'Policy', 'Unknown tools, targets, flags, and configuration fail closed.'],
  ['04', 'Credential', 'One scoped credential family is selected for the winning rule.'],
  ['05', 'Execute', 'A structured argv request runs with shell expansion disabled.'],
  ['06', 'Audit', 'Decision, execution, cost, and resolution events join one hash chain.'],
];

export default function HomePage() {
  return (
    <main className="landing">
      <header className="site-header">
        <div className="page-shell header-inner">
          <Brand />
          <nav className="desktop-nav" aria-label="Primary navigation">
            <a href="#capabilities">Capabilities</a>
            <a href="#safety">Safety model</a>
            <a href="#interfaces">Interfaces</a>
            <Link href="/docs">Docs</Link>
          </nav>
          <div className="header-actions">
            <a
              className="github-link"
              href="https://github.com/skundu42/opendevops"
              rel="noreferrer"
              target="_blank"
            >
              GitHub
            </a>
            <Link className="nav-cta" href="/docs/getting-started">
              Get started <ArrowRight size={15} />
            </Link>
          </div>
        </div>
      </header>

      <section className="hero">
        <div className="hero-grid" aria-hidden="true" />
        <div className="page-shell hero-layout">
          <div className="hero-copy">
            <h1>
              Autonomous operations.
              <span>Bounded authority.</span>
            </h1>
            <p className="hero-lede">
              Investigate infrastructure, diagnose incidents, and execute tightly scoped
              remediation through fail-closed policy, least-privilege credentials, budget
              stop-losses, and verifiable audit chains.
            </p>
            <div className="hero-actions">
              <Link className="primary-button" href="/docs/getting-started">
                Read Documentation <ArrowRight size={17} />
              </Link>
              <a
                className="secondary-button"
                href="https://github.com/skundu42/opendevops"
                rel="noreferrer"
                target="_blank"
              >
                View source
              </a>
            </div>
            <div className="hero-proof">
              <div>
                <ShieldCheck size={17} />
                <span>
                  <strong>Default deny</strong>
                  Unknown actions stop.
                </span>
              </div>
              <div>
                <KeyRound size={17} />
                <span>
                  <strong>No shell surface</strong>
                  Structured argv only.
                </span>
              </div>
              <div>
                <FileCheck2 size={17} />
                <span>
                  <strong>Chain of record</strong>
                  Every decision linked.
                </span>
              </div>
            </div>
          </div>
          <AgentDemo />
        </div>
      </section>

      <section className="systems-band" aria-label="Supported systems">
        <div className="page-shell">
          <span className="band-label">Connected systems</span>
          <div className="systems-list">
            <span>Kubernetes</span>
            <span>GitHub</span>
            <span>AWS</span>
            <span>Google Cloud</span>
            <span>Azure</span>
            <span>SSH</span>
          </div>
          <span className="band-note">one safety core</span>
        </div>
      </section>

      <section className="section page-shell" id="capabilities">
        <div className="section-heading">
          <div>
            <span className="section-kicker">Operational range</span>
            <h2>Useful across the incident. Restrained at the boundary.</h2>
          </div>
          <p>
            The agent gets enough context to form a real diagnosis. Authority is granted
            separately, for a specific action, target, environment, and amount of time.
          </p>
        </div>
        <div className="capability-grid">
          {capabilities.map(({ icon: Icon, label, title, copy, tags }) => (
            <article className="capability-card" key={label}>
              <div className="card-topline">
                <span className="card-icon">
                  <Icon size={19} />
                </span>
                <span>{label}</span>
              </div>
              <h3>{title}</h3>
              <p>{copy}</p>
              <div className="tag-list">
                {tags.map((tag) => (
                  <span key={tag}>{tag}</span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="safety-section" id="safety">
        <div className="page-shell">
          <div className="safety-intro">
            <div>
              <span className="section-kicker light">Execution model</span>
              <h2>The prompt is never the permission.</h2>
            </div>
            <p>
              A model can ask. It cannot grant itself a credential, widen a target allowlist,
              bypass a policy deny, disable a dry run, or approve its own production change.
            </p>
          </div>

          <div className="guardrail-rail">
            {guardrails.map(([index, title, copy]) => (
              <div className="guardrail" key={index}>
                <span className="guardrail-index">{index}</span>
                <div className="guardrail-node">
                  {index === '03' ? <Scale size={19} /> : index === '06' ? <FileCheck2 size={19} /> : <Check size={18} />}
                </div>
                <h3>{title}</h3>
                <p>{copy}</p>
              </div>
            ))}
          </div>

          <div className="boundary-grid">
            <article className="boundary-card accent">
              <div className="boundary-heading">
                <ShieldCheck size={22} />
                <span>Fail-closed by construction</span>
              </div>
              <p>
                Missing configuration, unpriced models, unknown tools, unmatched commands, and
                unavailable credentials refuse to boot or deny the action.
              </p>
              <Link href="/docs/security/policy-engine">
                Read the policy pipeline <ArrowRight size={15} />
              </Link>
            </article>
            <article className="boundary-card">
              <div className="boundary-heading">
                <CircleGauge size={22} />
                <span>Stop-losses at every layer</span>
              </div>
              <p>
                Per-run calls, tool invocations, recursion, wall time, and USD cost meet
                per-principal daily budgets and hard executor timeouts.
              </p>
              <Link href="/docs/operations/budgets">
                Understand budgets <ArrowRight size={15} />
              </Link>
            </article>
            <article className="boundary-card">
              <div className="boundary-heading">
                <Boxes size={22} />
                <span>Credentials are architecture</span>
              </div>
              <p>
                Remote executors split credentials by environment and read/write channel, then
                accept only signed decisions that match their fixed identity.
              </p>
              <Link href="/docs/security/execution-boundaries">
                Inspect the boundary <ArrowRight size={15} />
              </Link>
            </article>
          </div>
        </div>
      </section>

      <section className="section page-shell" id="interfaces">
        <div className="section-heading interfaces-heading">
          <div>
            <span className="section-kicker">One agent, many entry points</span>
            <h2>Meet operators where incidents already happen.</h2>
          </div>
          <p>
            Every interface enters the same gateway, budget, policy, credential, approval, and
            audit path. There is no “convenient” side door.
          </p>
        </div>
        <div className="interfaces-grid">
          {interfaces.map(({ icon: Icon, title, copy }) => (
            <article key={title}>
              <Icon size={20} />
              <div>
                <h3>{title}</h3>
                <p>{copy}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="architecture-panel">
        <div className="page-shell architecture-layout">
          <div className="architecture-copy">
            <span className="section-kicker">Architecture</span>
            <h2>One graph. Explicit control planes.</h2>
            <p>
              The reasoning loop is separated from execution, policy, credentials, state, and
              audit. That keeps integrations composable without turning the model into a trusted
              control plane.
            </p>
            <Link href="/docs/core-concepts/architecture">
              Explore the architecture <ArrowRight size={16} />
            </Link>
          </div>
          <div className="architecture-map" aria-label="opendevops architecture flow">
            <div className="arch-column">
              <span className="arch-label">entry</span>
              <div><TerminalSquare size={16} /> Interfaces</div>
              <div><Siren size={16} /> Events</div>
            </div>
            <ArrowRight className="arch-arrow" size={20} />
            <div className="arch-column center">
              <span className="arch-label">reason</span>
              <div className="arch-agent"><Bot size={18} /> Agent graph</div>
              <div><CircleGauge size={16} /> Budgets</div>
              <div><Scale size={16} /> Policy</div>
            </div>
            <ArrowRight className="arch-arrow" size={20} />
            <div className="arch-column">
              <span className="arch-label">act</span>
              <div><Blocks size={16} /> Executor</div>
              <div><KeyRound size={16} /> Credential</div>
            </div>
            <div className="audit-bridge">
              <FileCheck2 size={16} /> hash-chained audit
            </div>
          </div>
        </div>
      </section>

      <section className="get-started">
        <div className="page-shell get-started-layout">
          <div>
            <span className="section-kicker light">Start locally</span>
            <h2>Your first read-only investigation takes one workspace.</h2>
            <p>
              Install the released tool, initialize a workspace, provision a secrets-denied
              Kubernetes identity, then choose the contexts the agent may see.
            </p>
          </div>
          <div className="install-panel">
            <CopyCommand />
            <ol>
              <li><span>1</span>Initialize the configuration workspace</li>
              <li><span>2</span>Add a scoped model and target credential</li>
              <li><span>3</span>Run <code>opendevops config check</code></li>
            </ol>
            <Link className="install-link" href="/docs/getting-started">
              Follow the complete quick start <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </section>

      <footer className="site-footer">
        <div className="page-shell footer-grid">
          <div className="footer-brand">
            <Brand />
            <p>An autonomous DevOps agent with a smaller blast radius than its prompt.</p>
          </div>
          <div>
            <span>Learn</span>
            <Link href="/docs">Documentation</Link>
            <Link href="/docs/getting-started">Getting started</Link>
            <Link href="/docs/core-concepts/architecture">Architecture</Link>
          </div>
          <div>
            <span>Operate</span>
            <Link href="/docs/security/policy-engine">Policy engine</Link>
            <Link href="/docs/deployment/service-mode">Deploy</Link>
            <Link href="/docs/operations/audit">Audit</Link>
          </div>
          <div>
            <span>Project</span>
            <a href="https://github.com/skundu42/opendevops">GitHub</a>
            <a href="https://github.com/skundu42/opendevops/releases">Releases</a>
            <a href="https://github.com/skundu42/opendevops/blob/main/SECURITY.md">Security</a>
          </div>
        </div>
        <div className="page-shell footer-bottom">
          <span>Apache-2.0 licensed</span>
          <span>Built for operators who need both leverage and limits.</span>
        </div>
      </footer>
    </main>
  );
}
