import type { FastifyInstance } from 'fastify';
import { computeZeroTrustScores } from '../services/zeroTrustEngine.js';

export async function zeroTrustRoutes(app: FastifyInstance) {
  app.get('/zero-trust/segments', async () => computeZeroTrustScores());
}
