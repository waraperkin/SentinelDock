import Fastify from 'fastify';
import cors from '@fastify/cors';
import { assetRoutes } from './routes/assets.js';
import { configRoutes } from './routes/configs.js';
import { policyRoutes } from './routes/policies.js';
import { riskRoutes } from './routes/risks.js';
import { attackPathRoutes } from './routes/attackPaths.js';
import { incidentRoutes } from './routes/incidents.js';
import { dashboardRoutes } from './routes/dashboard.js';
import { secretRoutes } from './routes/secrets.js';
import { workerRoutes } from './routes/workers.js';
import { auditRoutes } from './routes/audit.js';
import { zeroTrustRoutes } from './routes/zeroTrust.js';
import { titanRoutes } from './routes/titan.js';
import { registerAuth } from './middleware/auth.js';

const app = Fastify({ logger: true });

await app.register(cors, { origin: true });

registerAuth(app);

app.get('/health', async () => ({ status: 'ok' }));

await app.register(assetRoutes);
await app.register(configRoutes);
await app.register(policyRoutes);
await app.register(riskRoutes);
await app.register(attackPathRoutes);
await app.register(incidentRoutes);
await app.register(dashboardRoutes);
await app.register(secretRoutes);
await app.register(workerRoutes);
await app.register(auditRoutes);
await app.register(zeroTrustRoutes);
await app.register(titanRoutes);

const port = Number(process.env.BACKEND_PORT ?? 4000);

app
  .listen({ port, host: '0.0.0.0' })
  .then(() => app.log.info(`SentinelDock backend listening on :${port}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
