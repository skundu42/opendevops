'use client';

import { useState } from 'react';
import { Check, ChevronRight, CircleDollarSign, LockKeyhole, ShieldCheck } from 'lucide-react';

const scenarios = [
  {
    id: 'diagnose',
    label: 'Diagnose',
    prompt: 'Why is api-0 crash-looping in web?',
    environment: 'prod · read only',
    result: 'Root cause isolated',
    summary: 'Container OOMKilled. JVM heap is 22% above the workload memory limit.',
    cost: '$0.0841',
    steps: [
      ['scope', 'Loaded prod read-only credential', 'credential/k8s-view'],
      ['exec', 'kubectl describe pod api-0', 'allow · k8s-read'],
      ['exec', 'kubectl logs api-0 --previous', 'allow · output scrubbed'],
      ['reason', 'Correlated exit 137 with heap config', 'confidence 0.94'],
    ],
  },
  {
    id: 'change',
    label: 'Guarded change',
    prompt: 'Roll back checkout in staging.',
    environment: 'staging · guarded write',
    result: 'Rollback verified',
    summary: 'Revision 187 restored, rollout healthy, error rate returned to baseline.',
    cost: '$0.1274',
    steps: [
      ['scope', 'Matched staging deployment grant', 'expires in 18m'],
      ['plan', 'Server-side dry run passed', 'diff · 1 workload'],
      ['exec', 'rollout undo deployment/checkout', 'approved · deploy-staging'],
      ['verify', 'Waited for availability + checked errors', 'healthy · 3/3'],
    ],
  },
  {
    id: 'ci',
    label: 'CI recovery',
    prompt: 'Diagnose the failing release workflow.',
    environment: 'github · pull request only',
    result: 'Fix proposed',
    summary: 'Pinned action expects Node 24. Prepared a one-file PR with the compatible release action.',
    cost: '$0.0618',
    steps: [
      ['scope', 'Selected repository read credential', 'repo allowlisted'],
      ['exec', 'Inspected failed run and job logs', 'allow · gh-read'],
      ['reason', 'Located runtime compatibility failure', 'job/release'],
      ['propose', 'Created scoped patch for review', 'no direct push'],
    ],
  },
] as const;

const stepIcons = {
  scope: LockKeyhole,
  exec: ChevronRight,
  reason: ShieldCheck,
  plan: ShieldCheck,
  verify: Check,
  propose: Check,
};

export function AgentDemo() {
  const [activeId, setActiveId] = useState<(typeof scenarios)[number]['id']>('diagnose');
  const scenario = scenarios.find((item) => item.id === activeId) ?? scenarios[0];

  return (
    <div className="run-console" aria-label="Interactive examples of opendevops runs">
      <div className="console-tabs" role="tablist" aria-label="Agent examples">
        {scenarios.map((item) => (
          <button
            aria-selected={activeId === item.id}
            className={activeId === item.id ? 'active' : ''}
            key={item.id}
            onClick={() => setActiveId(item.id)}
            role="tab"
            type="button"
          >
            {item.label}
          </button>
        ))}
      </div>
      <div className="console-window" role="tabpanel">
        <div className="console-titlebar">
          <div className="window-dots" aria-hidden="true">
            <i />
            <i />
            <i />
          </div>
          <span>run_01J2F9 · live trace</span>
          <span className="console-status">
            <i /> complete
          </span>
        </div>
        <div className="console-body">
          <div className="prompt-line">
            <span>YOU</span>
            <p>{scenario.prompt}</p>
          </div>
          <div className="environment-line">
            <LockKeyhole size={13} />
            {scenario.environment}
          </div>
          <div className="trace-list">
            {scenario.steps.map(([kind, text, meta], index) => {
              const Icon = stepIcons[kind];
              return (
                <div className="trace-step" key={`${kind}-${text}`}>
                  <span className="trace-index">{String(index + 1).padStart(2, '0')}</span>
                  <span className={`trace-icon ${kind}`}>
                    <Icon size={14} />
                  </span>
                  <span className="trace-copy">{text}</span>
                  <span className="trace-meta">{meta}</span>
                </div>
              );
            })}
          </div>
          <div className="result-card">
            <div>
              <span className="result-label">
                <Check size={14} /> {scenario.result}
              </span>
              <p>{scenario.summary}</p>
            </div>
            <div className="result-cost">
              <CircleDollarSign size={14} />
              {scenario.cost}
            </div>
          </div>
          <div className="audit-line">
            <ShieldCheck size={13} />
            audit chain verified
            <span>sha256 · 8 events</span>
          </div>
        </div>
      </div>
    </div>
  );
}
