/**
 * Injection-pattern flagging on wish submission (§3.4). A hit does NOT
 * block submission — that would be a censorship mechanism with false
 * positives — but it flags the wish on the board and in the task spec so
 * the maintainer sees it before approving and the agent run carries it.
 */
export interface InjectionPattern {
  name: string;
  regex: RegExp;
}

export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: "ignore-previous-instructions",
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions/i,
  },
  {
    name: "disregard-instructions",
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)?\s*instructions/i,
  },
  { name: "you-are-now", regex: /you\s+are\s+now\b/i },
  {
    name: "fake-system-prompt",
    regex: /(system\s+prompt|new\s+instructions)\s*:/i,
  },
  {
    name: "credential-request",
    regex: /send\s+(me\s+)?(your|the)?\s*(password|token|secret|api[-_ ]?key|credentials?)\b/i,
  },
  {
    name: "exfil-pipe",
    regex: /curl\s+\S+\s*\|\s*(sh|bash)\b/i,
  },
  {
    name: "exfil-env",
    regex: /(env|environment variables?)\s+to\s+https?:\/\//i,
  },
  {
    name: "override-role",
    regex: /act\s+as\s+(a\s+)?(system|developer|admin|root)\b/i,
  },
  // --- added in the fix round: the old list missed whole families ---
  {
    name: "forget-above",
    regex: /forget\s+(everything|all)\s+(above|before|that came before)/i,
  },
  {
    name: "pretend-roleplay",
    regex: /pretend\s+(to\s+be|you\s+are)|roleplay\s+as\b/i,
  },
  { name: "developer-mode", regex: /developer\s+mode\b/i },
  {
    name: "do-not-follow",
    regex: /do\s+not\s+follow\s+(the\s+)?(previous|above|system|earlier)?\s*instructions/i,
  },
  {
    name: "include-api-key",
    regex: /include\s+(the\s+)?(api[-_ ]?key|password|token|secret|credentials?)\b/i,
  },
  {
    name: "base64-decode",
    regex: /base64\s+(-d|--decode)|Buffer\.from\([^)]*,\s*['"]base64['"]\)|atob\s*\(/i,
  },
  {
    name: "ignore-instructions-nonenglish",
    // A small set of common translations, not a multilingual guarantee:
    // coverage is English-first (see README). Spanish, French, German,
    // Portuguese for "ignore the previous instructions".
    regex: /ignora\s+las\s+instrucciones\s+anteriores|ignore\s+les\s+instructions\s+précédentes|ignoriere\s+die\s+vorherigen\s+Anweisungen|ignore\s+as\s+instruções\s+anteriores/i,
  },
];

export function scanInjection(text: string): string[] {
  const hits: string[] = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.regex.test(text)) hits.push(p.name);
  }
  return hits;
}
