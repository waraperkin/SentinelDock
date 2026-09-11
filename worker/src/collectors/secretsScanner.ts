export interface SecretMatch {
  kind: 'aws_access_key' | 'private_key' | 'generic_api_key' | 'generic_password' | 'high_entropy_string';
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

/** Shannon entropy in bits/character — high entropy is a signal of random-looking data (tokens, keys) vs. natural text/identifiers. */
export function shannonEntropy(text: string): number {
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Flags long, mixed-case alphanumeric strings with high Shannon entropy —
 * the shape of a generic API token/secret that doesn't match any known
 * provider format. Deliberately conservative (length >= 32, requires both
 * upper/lowercase letters AND digits, entropy threshold tuned above what
 * natural-language text or simple identifiers produce) to avoid flagging
 * UUIDs, git SHAs, or ordinary env values as false positives.
 */
function detectHighEntropyString(text: string): SecretMatch | null {
  const trimmed = text.trim();
  if (trimmed.length < 32 || trimmed.length > 256) return null;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(trimmed)) return null;
  if (!/[a-z]/.test(trimmed) || !/[A-Z]/.test(trimmed) || !/[0-9]/.test(trimmed)) return null;
  const entropy = shannonEntropy(trimmed);
  if (entropy < 4.0) return null;
  return { kind: 'high_entropy_string', matchPreview: redact(trimmed), severity: 'medium' };
}

/**
 * Scans a piece of text (env var value, banner, config content) for common
 * secret patterns. Local, offline — known-format regex patterns (AWS keys,
 * PEM headers, api_key/password assignments) plus a conservative Shannon-
 * entropy heuristic for generic high-entropy tokens that don't match any
 * known provider format. Not a replacement for a dedicated secrets-
 * scanning product, but it catches the highest-signal, most common cases
 * without any external service call.
 */
export function scanTextForSecrets(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const pattern of PATTERNS) {
    const match = text.match(pattern.regex);
    if (match) matches.push({ kind: pattern.kind, matchPreview: redact(match[0]), severity: pattern.severity });
  }
  if (matches.length === 0) {
    const entropyMatch = detectHighEntropyString(text);
    if (entropyMatch) matches.push(entropyMatch);
  }
  return matches;
}
