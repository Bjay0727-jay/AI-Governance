/**
 * ForgeAI Govern™ - API Router (Hono)
 *
 * RESTful routing with tenant-scoped data isolation.
 * Uses Hono for structured route definitions, middleware, and parameter parsing.
 * All endpoints require JWT authentication except auth endpoints.
 */

import { Hono } from 'hono';
import { AuthService } from './auth.js';
import { AIAssetHandlers } from './handlers/ai-assets.js';
import { RiskAssessmentHandlers } from './handlers/risk-assessments.js';
import { ImpactAssessmentHandlers } from './handlers/impact-assessments.js';
import { ComplianceHandlers } from './handlers/compliance.js';
import { VendorHandlers } from './handlers/vendors.js';
import { MonitoringHandlers } from './handlers/monitoring.js';
import { DashboardHandlers } from './handlers/dashboard.js';
import { MaturityHandlers } from './handlers/maturity.js';
import { IncidentHandlers } from './handlers/incidents.js';
import { UserHandlers } from './handlers/users.js';
import { AuditLogHandlers } from './handlers/audit-log.js';
import { EvidenceHandlers } from './handlers/evidence.js';
import { NotificationHandlers } from './handlers/notifications.js';
import { TrainingHandlers } from './handlers/training.js';
import { SupportTicketHandlers } from './handlers/support-tickets.js';
import { FeatureRequestHandlers } from './handlers/feature-requests.js';
import { KnowledgeBaseHandlers } from './handlers/knowledge-base.js';
import { OpsHandlers } from './handlers/ops.js';
import { ExportHandlers } from './handlers/exports.js';
import { ReportHandlers } from './handlers/reports.js';
import { DocsHandlers } from './handlers/docs.js';
import { TenantHandlers } from './handlers/tenant.js';
import { jsonResponse, errorResponse, generateCsrfToken, validateCsrfToken } from './utils.js';

export class Router {
  constructor(env) {
    this.env = env;
    this.auth = new AuthService(env);

    // Initialize handlers
    const handlers = {
      assets: new AIAssetHandlers(env),
      risk: new RiskAssessmentHandlers(env),
      impact: new ImpactAssessmentHandlers(env),
      compliance: new ComplianceHandlers(env),
      vendors: new VendorHandlers(env),
      monitoring: new MonitoringHandlers(env),
      dashboard: new DashboardHandlers(env),
      maturity: new MaturityHandlers(env),
      incidents: new IncidentHandlers(env),
      users: new UserHandlers(env),
      auditLog: new AuditLogHandlers(env),
      evidence: new EvidenceHandlers(env),
      notifications: new NotificationHandlers(env),
      training: new TrainingHandlers(env),
      tickets: new SupportTicketHandlers(env),
      features: new FeatureRequestHandlers(env),
      knowledgeBase: new KnowledgeBaseHandlers(env),
      ops: new OpsHandlers(env),
      exports: new ExportHandlers(env),
      reports: new ReportHandlers(env),
      docs: new DocsHandlers(),
      tenant: new TenantHandlers(env),
    };

    this.app = this._buildApp(handlers);
  }

  _buildApp(h) {
    const app = new Hono({ strict: false });
    const auth = this.auth;
    const env = this.env;

    // --- Public Routes (no auth) ---
    app.post('/api/v1/auth/register', async (c) => auth.register(await c.req.json()));
    app.post('/api/v1/auth/login', async (c) => auth.login(await c.req.json(), c.req.raw));
    app.post('/api/v1/auth/refresh', async (c) => auth.refresh(await c.req.json()));
    app.post('/api/v1/auth/logout', async (c) => auth.logout(await c.req.json()));
    app.get('/api/v1/docs', () => h.docs.getDocs());
    app.get('/api/v1/csrf-token', async () => {
      const token = await generateCsrfToken(env.JWT_SECRET);
      return jsonResponse({ csrf_token: token });
    });

    // --- Auth + CSRF middleware for all remaining /api/v1/ routes ---
    app.use('/api/v1/*', async (c, next) => {
      const user = await auth.authenticate(c.req.raw);
      if (!user) return errorResponse('Authentication required', 401);

      // CSRF validation on state-changing requests
      const method = c.req.method;
      if (env.ENVIRONMENT !== 'test' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        const csrfToken = c.req.header('X-CSRF-Token');
        if (!csrfToken || !(await validateCsrfToken(csrfToken, env.JWT_SECRET))) {
          return errorResponse('Invalid or missing CSRF token', 403);
        }
      }

      // Build context available to handlers
      c.set('user', user);
      c.set('ctx', { user, db: env.DB, url: new URL(c.req.url), auth });
      await next();
    });

    // Helper to parse body for state-changing requests
    const withBody = async (c) => {
      try { return await c.req.json(); } catch { return {}; }
    };

    // --- AI Asset Routes ---
    app.get('/api/v1/ai-assets', (c) => h.assets.list(c.get('ctx')));
    app.post('/api/v1/ai-assets', async (c) => h.assets.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/ai-assets/:id', (c) => h.assets.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/ai-assets/:id', async (c) => h.assets.update(c.get('ctx'), c.req.param('id'), await withBody(c)));
    app.delete('/api/v1/ai-assets/:id', (c) => h.assets.delete(c.get('ctx'), c.req.param('id')));
    app.get('/api/v1/ai-assets/:id/risk-history', (c) => h.risk.listByAsset(c.get('ctx'), c.req.param('id')));
    app.get('/api/v1/ai-assets/:id/metrics', (c) => h.monitoring.listByAsset(c.get('ctx'), c.req.param('id')));

    // --- Risk Assessment Routes ---
    app.get('/api/v1/risk-assessments', (c) => h.risk.list(c.get('ctx')));
    app.post('/api/v1/risk-assessments', async (c) => h.risk.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/risk-assessments/:id', (c) => h.risk.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/risk-assessments/:id', async (c) => h.risk.update(c.get('ctx'), c.req.param('id'), await withBody(c)));
    app.post('/api/v1/risk-assessments/:id/approve', async (c) => h.risk.approve(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- Impact Assessment Routes ---
    app.get('/api/v1/impact-assessments', (c) => h.impact.list(c.get('ctx')));
    app.post('/api/v1/impact-assessments', async (c) => h.impact.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/impact-assessments/:id', (c) => h.impact.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/impact-assessments/:id', async (c) => h.impact.update(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- Compliance Routes ---
    app.get('/api/v1/controls', (c) => h.compliance.listControls(c.get('ctx')));
    app.get('/api/v1/controls/:id/frameworks', (c) => h.compliance.getFrameworkMappings(c.get('ctx'), c.req.param('id')));
    app.get('/api/v1/implementations', (c) => h.compliance.listImplementations(c.get('ctx')));
    app.post('/api/v1/implementations', async (c) => h.compliance.createImplementation(c.get('ctx'), await withBody(c)));
    app.put('/api/v1/implementations/:id', async (c) => h.compliance.updateImplementation(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- Vendor Assessment Routes ---
    app.get('/api/v1/vendor-assessments', (c) => h.vendors.list(c.get('ctx')));
    app.post('/api/v1/vendor-assessments', async (c) => h.vendors.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/vendor-assessments/:id', (c) => h.vendors.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/vendor-assessments/:id', async (c) => h.vendors.update(c.get('ctx'), c.req.param('id'), await withBody(c)));
    app.post('/api/v1/vendor-assessments/:id/score', (c) => h.vendors.calculateScore(c.get('ctx'), c.req.param('id')));

    // --- Monitoring Routes ---
    app.post('/api/v1/monitoring/metrics', async (c) => h.monitoring.record(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/monitoring/alerts', (c) => h.monitoring.getAlerts(c.get('ctx')));

    // --- Dashboard & Reports ---
    app.get('/api/v1/dashboard/stats', (c) => h.dashboard.getStats(c.get('ctx')));
    app.get('/api/v1/reports/compliance', (c) => h.dashboard.complianceReport(c.get('ctx')));
    app.get('/api/v1/reports/executive', (c) => h.dashboard.executiveReport(c.get('ctx')));
    app.get('/api/v1/onboarding/progress', (c) => h.dashboard.getOnboardingProgress(c.get('ctx')));

    // --- Maturity Assessment Routes ---
    app.get('/api/v1/maturity-assessments', (c) => h.maturity.list(c.get('ctx')));
    app.post('/api/v1/maturity-assessments', async (c) => h.maturity.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/maturity-assessments/:id', (c) => h.maturity.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/maturity-assessments/:id', async (c) => h.maturity.update(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- Incident Routes ---
    app.get('/api/v1/incidents', (c) => h.incidents.list(c.get('ctx')));
    app.post('/api/v1/incidents', async (c) => h.incidents.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/incidents/:id', (c) => h.incidents.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/incidents/:id', async (c) => h.incidents.update(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- User Management Routes ---
    app.get('/api/v1/users', (c) => h.users.list(c.get('ctx')));
    app.post('/api/v1/users', async (c) => h.users.create(c.get('ctx'), await withBody(c)));
    app.post('/api/v1/users/:id/unlock', (c) => h.users.unlock(c.get('ctx'), c.req.param('id')));
    app.post('/api/v1/users/:id/reset-password', async (c) => h.users.resetPassword(c.get('ctx'), c.req.param('id'), await withBody(c)));
    app.get('/api/v1/users/:id', (c) => h.users.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/users/:id', async (c) => h.users.update(c.get('ctx'), c.req.param('id'), await withBody(c)));
    app.delete('/api/v1/users/:id', (c) => h.users.deactivate(c.get('ctx'), c.req.param('id')));

    // --- Audit Log Routes ---
    app.get('/api/v1/audit-log', (c) => h.auditLog.list(c.get('ctx')));

    // --- Evidence Routes ---
    app.get('/api/v1/evidence', (c) => h.evidence.list(c.get('ctx')));
    app.post('/api/v1/evidence', async (c) => h.evidence.create(c.get('ctx'), await withBody(c)));
    app.post('/api/v1/evidence/upload', async (c) => h.evidence.upload(c.get('ctx'), c.req.raw));
    app.get('/api/v1/evidence/:id/download', (c) => h.evidence.download(c.get('ctx'), c.req.param('id')));
    app.get('/api/v1/evidence/:id/verify', (c) => h.evidence.verify(c.get('ctx'), c.req.param('id')));
    app.delete('/api/v1/evidence/:id', (c) => h.evidence.delete(c.get('ctx'), c.req.param('id')));

    // --- Notification Routes ---
    app.post('/api/v1/notifications/read-all', (c) => h.notifications.markAllRead(c.get('ctx')));
    app.get('/api/v1/notifications', (c) => h.notifications.list(c.get('ctx')));
    app.put('/api/v1/notifications/:id/read', (c) => h.notifications.markRead(c.get('ctx'), c.req.param('id')));

    // --- Training Routes ---
    app.get('/api/v1/training/progress', (c) => h.training.getProgress(c.get('ctx')));
    app.get('/api/v1/training/modules', (c) => h.training.listModules(c.get('ctx')));
    app.post('/api/v1/training/modules/:id/complete', async (c) => h.training.completeModule(c.get('ctx'), c.req.param('id'), await withBody(c)));
    app.get('/api/v1/training/modules/:id', (c) => h.training.getModule(c.get('ctx'), c.req.param('id')));

    // --- Support Ticket Routes ---
    app.get('/api/v1/support-tickets', (c) => h.tickets.list(c.get('ctx')));
    app.post('/api/v1/support-tickets', async (c) => h.tickets.create(c.get('ctx'), await withBody(c)));
    app.get('/api/v1/support-tickets/:id', (c) => h.tickets.get(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/support-tickets/:id', async (c) => h.tickets.update(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- Feature Request Routes ---
    app.get('/api/v1/feature-requests', (c) => h.features.list(c.get('ctx')));
    app.post('/api/v1/feature-requests', async (c) => h.features.create(c.get('ctx'), await withBody(c)));
    app.post('/api/v1/feature-requests/:id/vote', (c) => h.features.vote(c.get('ctx'), c.req.param('id')));
    app.put('/api/v1/feature-requests/:id', async (c) => h.features.update(c.get('ctx'), c.req.param('id'), await withBody(c)));

    // --- Knowledge Base Routes ---
    app.get('/api/v1/knowledge-base', (c) => h.knowledgeBase.list(c.get('ctx')));

    // --- Tenant Settings Routes ---
    app.get('/api/v1/tenant/settings', (c) => h.tenant.getSettings(c.get('ctx')));
    app.post('/api/v1/tenant/acknowledge-baa', (c) => h.tenant.acknowledgeBaa(c.get('ctx')));

    // --- Operations Dashboard Routes ---
    app.get('/api/v1/ops/metrics', (c) => h.ops.getMetrics(c.get('ctx')));
    app.get('/api/v1/ops/tenant-health', (c) => h.ops.getTenantHealth(c.get('ctx')));

    // --- Export Routes ---
    app.get('/api/v1/export/assets', (c) => h.exports.exportAssets(c.get('ctx')));
    app.get('/api/v1/export/risk-assessments', (c) => h.exports.exportRiskAssessments(c.get('ctx')));
    app.get('/api/v1/export/compliance', (c) => h.exports.exportCompliance(c.get('ctx')));
    app.get('/api/v1/export/vendor-assessments', (c) => h.exports.exportVendors(c.get('ctx')));
    app.get('/api/v1/export/incidents', (c) => h.exports.exportIncidents(c.get('ctx')));
    app.get('/api/v1/export/evidence', (c) => h.exports.exportEvidence(c.get('ctx')));

    // --- Audit Report Routes ---
    app.get('/api/v1/reports/audit-pack', (c) => h.reports.auditPack(c.get('ctx')));
    app.get('/api/v1/reports/asset-profile/:id', (c) => h.reports.assetProfile(c.get('ctx'), c.req.param('id')));

    return app;
  }

  /**
   * Handle a request - compatible with both Cloudflare Workers and the Express adapter.
   * @param {Request} request - Web API Request (or request-like object from the adapter)
   * @returns {Promise<Response>}
   */
  async handle(request) {
    return this.app.fetch(request, this.env);
  }
}
