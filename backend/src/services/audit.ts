import { query } from '../db/pool.js';

export async function recordAudit(action: string, actor: string, detail: Record<string, unknown> = {}): Promise<void> {
  await query('INSERT INTO audit_log (action, actor, detail) VALUES ($1, $2, $3)', [action, actor, JSON.stringify(detail)]);
}
