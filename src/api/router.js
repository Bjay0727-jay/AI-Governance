/**
 * ForgeAI Govern™ - API Router
 *
 * RESTful routing with tenant-scoped data isolation.
 * All endpoints require JWT authentication except auth endpoints.
 */

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
import { jsonResponse, errorResponse } from './utils.js';

export class Router {
  constructor(env) {
    this.env = env;
    this.auth = new AuthService(env);
    this.assets = new AIAssetHandlers(env);
    this.risk = new RiskAssessmentHandlers(env);
    this.impact = new ImpactAssessmentHandlers(env);
    this.compliance = new ComplianceHandlers(env);
    this.vendors = new VendorHandlers(env);
    this.monitoring = new MonitoringHandlers(env);
    this.dashboard = new DashboardHandlers(env);
    this.maturity = new MaturityHandlers(env);
    this.incidents = new IncidentHandlers(env);
  }

  async handle(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // --- Public Auth Routes ---
    if (path === '/api/v1/auth/register' && method === 'POST') {
      return this.auth.register(await request.json());
    }
    if (path === '/api/v1/auth/login' && method === 'POST') {
      return this.auth.login(await request.json(), request);
    }
    if (path === '/api/v1/auth/refresh' && method === 'POST') {
      return this.auth.refresh(await request.json());
    }

    // --- All other routes require authentication ---
    const user = await this.auth.authenticate(request);
    if (!user) return errorResponse('Authentication required', 401);

    const ctx = { user, db: this.env.DB, url, auth: this.auth };
    let body = null;
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      try { body = await request.json(); } catch { body = {}; }
    }

    // --- AI Asset Routes ---
    const assetMatch = path.match(/^\/api\/v1\/ai-assets(?:\/([^/]+))?(?:\/(.+))?$/);
    if (assetMatch) {
      const [, id, sub] = assetMatch;
      if (!id && method === 'GET') return this.assets.list(ctx);
      if (!id && method === 'POST') return this.assets.create(ctx, body);
      if (id && !sub && method === 'GET') return this.assets.get(ctx, id);
      if (id && !sub && method === 'PUT') return this.assets.update(ctx, id, body);
      if (id && !sub && method === 'DELETE') return this.assets.delete(ctx, id);
      if (id && sub === 'risk-history' && method === 'GET') return this.risk.listByAsset(ctx, id);
      if (id && sub === 'metrics' && method === 'GET') return this.monitoring.listByAsset(ctx, id);
    }

    // --- Risk Assessment Routes ---
    const riskMatch = path.match(/^\/api\/v1\/risk-assessments(?:\/([^/]+))?(?:\/(.+))?$/);
    if (riskMatch) {
      const [, id, sub] = riskMatch;
      if (!id && method === 'GET') return this.risk.list(ctx);
      if (!id && method === 'POST') return this.risk.create(ctx, body);
      if (id && !sub && method === 'GET') return this.risk.get(ctx, id);
      if (id && !sub && method === 'PUT') return this.risk.update(ctx, id, body);
      if (id && sub === 'approve' && method === 'POST') return this.risk.approve(ctx, id, body);
    }

    // --- Impact Assessment Routes ---
    const impactMatch = path.match(/^\/api\/v1\/impact-assessments(?:\/([^/]+))?$/);
    if (impactMatch) {
      const [, id] = impactMatch;
      if (!id && method === 'GET') return this.impact.list(ctx);
      if (!id && method === 'POST') return this.impact.create(ctx, body);
      if (id && method === 'GET') return this.impact.get(ctx, id);
      if (id && method === 'PUT') return this.impact.update(ctx, id, body);
    }

    // --- Compliance Routes ---
    const controlsMatch = path.match(/^\/api\/v1\/controls(?:\/([^/]+))?(?:\/(.+))?$/);
    if (controlsMatch) {
      const [, id, sub] = controlsMatch;
      if (!id && method === 'GET') return this.compliance.listControls(ctx);
      if (id && sub === 'frameworks' && method === 'GET') return this.compliance.getFrameworkMappings(ctx, id);
    }

    const implMatch = path.match(/^\/api\/v1\/implementations(?:\/([^/]+))?$/);
    if (implMatch) {
      const [, id] = implMatch;
      if (!id && method === 'GET') return this.compliance.listImplementations(ctx);
      if (!id && method === 'POST') return this.compliance.createImplementation(ctx, body);
      if (id && method === 'PUT') return this.compliance.updateImplementation(ctx, id, body);
    }

    // --- Vendor Assessment Routes ---
    const vendorMatch = path.match(/^\/api\/v1\/vendor-assessments(?:\/([^/]+))?(?:\/(.+))?$/);
    if (vendorMatch) {
      const [, id, sub] = vendorMatch;
      if (!id && method === 'GET') return this.vendors.list(ctx);
      if (!id && method === 'POST') return this.vendors.create(ctx, body);
      if (id && !sub && method === 'GET') return this.vendors.get(ctx, id);
      if (id && !sub && method === 'PUT') return this.vendors.update(ctx, id, body);
      if (id && sub === 'score' && method === 'POST') return this.vendors.calculateScore(ctx, id);
    }

    // --- Monitoring Routes ---
    if (path === '/api/v1/monitoring/metrics' && method === 'POST') {
      return this.monitoring.record(ctx, body);
    }
    if (path === '/api/v1/monitoring/alerts' && method === 'GET') {
      return this.monitoring.getAlerts(ctx);
    }

    // --- Dashboard & Reports ---
    if (path === '/api/v1/dashboard/stats' && method === 'GET') return this.dashboard.getStats(ctx);
    if (path === '/api/v1/reports/compliance' && method === 'GET') return this.dashboard.complianceReport(ctx);
    if (path === '/api/v1/reports/executive' && method === 'GET') return this.dashboard.executiveReport(ctx);

    // --- Maturity Assessment Routes ---
    const maturityMatch = path.match(/^\/api\/v1\/maturity-assessments(?:\/([^/]+))?$/);
    if (maturityMatch) {
      const [, id] = maturityMatch;
      if (!id && method === 'GET') return this.maturity.list(ctx);
      if (!id && method === 'POST') return this.maturity.create(ctx, body);
      if (id && method === 'GET') return this.maturity.get(ctx, id);
      if (id && method === 'PUT') return this.maturity.update(ctx, id, body);
    }

    // --- Incident Routes ---
    const incidentMatch = path.match(/^\/api\/v1\/incidents(?:\/([^/]+))?$/);
    if (incidentMatch) {
      const [, id] = incidentMatch;
      if (!id && method === 'GET') return this.incidents.list(ctx);
      if (!id && method === 'POST') return this.incidents.create(ctx, body);
      if (id && method === 'GET') return this.incidents.get(ctx, id);
      if (id && method === 'PUT') return this.incidents.update(ctx, id, body);
    }

    return errorResponse('Not found', 404);
  }
}
