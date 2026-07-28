'use client';

import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

const command = 'uv tool install "opendevops[checkpoint,ssh]==0.1.2"';

export function CopyCommand() {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="install-command">
      <span aria-hidden="true">$</span>
      <code>{command}</code>
      <button onClick={copy} type="button" aria-label="Copy install command">
        {copied ? <Check size={16} /> : <Copy size={16} />}
      </button>
    </div>
  );
}
