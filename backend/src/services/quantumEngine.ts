import { query } from '../db/pool.js';
import type { Risk, RiskScoreSnapshot, QuantumTrend, QuantumOutlier } from '../types/models.js';
import { globalRiskScore } from './riskEngine.js';

/**
 * GODMODE+ tier: QUANTUM Engine — local statistical analysis of the
 * platform's own risk data. Despite the tier name, this is classical
 * statistics (ordinary least-squares linear regression for trend
 * forecasting, z-score for outlier detection), computed entirely
 * in-process with no external ML service, GPU, or actual quantum
 * computing involved. Named to match this project's tier-naming
 * convention (TITAN, OMEGA, GODMODE, …), not a technical claim — see the
 * README for the explicit disclaimer.
 */

const TREND_STABLE_THRESHOLD = 0.05; // |slope| below this, in score points per sample, is treated as "stable" rather than a real trend

/** Records one point in the global-risk-score time series. Call once per evaluation cycle. */
export async function recordRiskScoreSnapshot(): Promise<RiskScoreSnapshot> {
  const score = await globalRiskScore();
  const [{ count }] = await query<{ count: string }>('SELECT count(*) FROM risks');
  const [row] = await query<RiskScoreSnapshot>(
    'INSERT INTO risk_score_snapshots (global_score, risk_count) VALUES ($1, $2) RETURNING *',
    [score, Number(count)],
  );
  return row;
}

/**
 * Ordinary least-squares linear regression over a time-ordered (oldest
 * first) list of scores, forecasting the next sample. Pure arithmetic, no
 * external library — this is the entirety of "QUANTUM"'s trend analysis.
 * Exported standalone (no DB access) so it is directly unit-testable.
 */
export function linearRegressionTrend(orderedScores: number[]): QuantumTrend | null {
  const n = orderedScores.length;
  if (n < 2) return null;

  const xs = orderedScores.map((_, i) => i);
  const ys = orderedScores;

  const meanX = xs.reduce((sum, x) => sum + x, 0) / n;
  const meanY = ys.reduce((sum, y) => sum + y, 0) / n;
  let numerator = 0;
  let denominator = 0;
  for (let i = 0; i < n; i++) {
    numerator += (xs[i] - meanX) * (ys[i] - meanY);
    denominator += (xs[i] - meanX) ** 2;
  }
  const slope = denominator === 0 ? 0 : numerator / denominator;
  const intercept = meanY - slope * meanX;
  const forecastNext = slope * n + intercept;

  const direction: QuantumTrend['direction'] = Math.abs(slope) < TREND_STABLE_THRESHOLD ? 'stable' : slope > 0 ? 'increasing' : 'decreasing';

  return {
    samples: n,
    slope: Math.round(slope * 10000) / 10000,
    current_score: ys[n - 1],
    forecast_next: Math.round(Math.max(0, forecastNext) * 100) / 100,
    direction,
  };
}

/** DB-backed wrapper: pulls the most recent snapshots and delegates to the pure `linearRegressionTrend`. */
export async function computeRiskTrend(sampleCount = 20): Promise<QuantumTrend | null> {
  const snapshots = await query<RiskScoreSnapshot>('SELECT * FROM risk_score_snapshots ORDER BY recorded_at DESC LIMIT $1', [sampleCount]);
  const ordered = [...snapshots].reverse(); // oldest first, so x increases with time
  return linearRegressionTrend(ordered.map((s) => Number(s.global_score)));
}

/**
 * Flags assets whose current risk score is a statistical outlier
 * (z-score, i.e. standard deviations from the mean) against the current
 * distribution of all risk scores — a different signal than severity
 * alone: an asset can have a "high" severity risk that is nonetheless
 * typical for this fleet, or a "medium" one that is unusually extreme
 * relative to everything else currently observed.
 */
export async function computeQuantumOutliers(zThreshold = 2): Promise<QuantumOutlier[]> {
  const risks = await query<Risk>('SELECT * FROM risks');
  await query('DELETE FROM quantum_outliers');
  if (risks.length < 3) return []; // too few points for a meaningful standard deviation

  const scores = risks.map((r) => Number(r.score));
  const mean = scores.reduce((sum, s) => sum + s, 0) / scores.length;
  const variance = scores.reduce((sum, s) => sum + (s - mean) ** 2, 0) / scores.length;
  const stddev = Math.sqrt(variance);
  if (stddev === 0) return [];

  const results: QuantumOutlier[] = [];
  for (const risk of risks) {
    const score = Number(risk.score);
    const zScore = (score - mean) / stddev;
    if (Math.abs(zScore) < zThreshold) continue;

    const [row] = await query<QuantumOutlier>(
      `INSERT INTO quantum_outliers (asset_type, asset_id, score, mean, stddev, z_score)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [risk.asset_type, risk.asset_id, score, Math.round(mean * 100) / 100, Math.round(stddev * 100) / 100, Math.round(zScore * 1000) / 1000],
    );
    results.push(row);
  }
  return results;
}
