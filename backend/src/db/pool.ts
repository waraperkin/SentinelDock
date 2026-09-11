import { Pool } from 'pg';

const connectionString =
  process.env.DATABASE_URL ?? 'postgres://sentineldock:change_me_local_dev@localhost:5432/sentineldock';

export const pool = new Pool({ connectionString });

export async function query<T = any>(text: string, params: unknown[] = []): Promise<T[]> {
  const result = await pool.query(text, params);
  return result.rows as T[];
}

export async function queryOne<T = any>(text: string, params: unknown[] = []): Promise<T | null> {
  const rows = await query<T>(text, params);
  return rows[0] ?? null;
}
