export interface SecretMatch {
  kind: 'aws_access_key' | 'private_key' | 'generic_api_key' | 'generic_password';
  matchPreview: string;
  severity: 'medium' | 'high' | 'critical';
}

const PATTERNS: Array<{ kind: SecretMatch['kind']; regex: RegExp; severity: SecretMatch['severity'] }> = [
  { kind: 'aws_access_key', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
  { kind: 'private_key', regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, severity: 'critical' },
  { kind: 'generic_api_key', regex: /(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+=]{16,}/i, severity: 'high' },
  { kind: 'generic_password', regex: /(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{6,}/i, severity: 'medium' },
];

/** Redacts a matched secret to a short, non-reversible preview — never the full value. */
function redact(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 8) return `${trimmed.slice(0, 2)}***`;
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-2)} (${trimmed.length} chars)`;
}

/**
 * Scans a piece of text (env var value, banner, config content) for common
 * secret patterns. Local, offline, regex-based — not a replacement for a
 * dedicated secrets-scanning product (e.g. entropy analysis, provider-
 * specific key formats beyond AWS), but it catches the highest-signal,
 * most common cases without any external service call.
 */
export function scanTextForSecrets(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const pattern of PATTERNS) {
    const match = text.match(pattern.regex);
    if (match) matches.push({ kind: pattern.kind, matchPreview: redact(match[0]), severity: pattern.severity });
  }
  return matches;
}
