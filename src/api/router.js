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
    this.users = new UserHandlers(env);
    this.auditLog = new AuditLogHandlers(env);
    this.evidence = new EvidenceHandlers(env);
    this.notifications = new NotificationHandlers(env);
    this.training = new TrainingHandlers(env);
    this.tickets = new SupportTicketHandlers(env);
    this.features = new FeatureRequestHandlers(env);
    this.knowledgeBase = new KnowledgeBaseHandlers(env);
    this.ops = new OpsHandlers(env);
    this.exports = new ExportHandlers(env);
    this.reports = new ReportHandlers(env);
    this.docs = new DocsHandlers();
  }

  async handle(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // --- Public Routes (no auth) ---
    if (path === '/api/v1/auth/register' && method === 'POST') {
      return this.auth.register(await request.json());
    }
    if (path === '/api/v1/auth/login' && method === 'POST') {
      return this.auth.login(await request.json(), request);
    }
    if (path === '/api/v1/auth/refresh' && method === 'POST') {
      return this.auth.refresh(await request.json());
    }
    if (path === '/api/v1/docs' && method === 'GET') {
      return this.docs.getDocs();
    }
    if (path === '/api/v1/csrf-token' && method === 'GET') {
      const token = [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('');
      return jsonResponse({ csrf_token: token });
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
    if (path === '/api/v1/onboarding/progress' && method === 'GET') return this.dashboard.getOnboardingProgress(ctx);

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

    // --- User Management Routes ---
    const userMatch = path.match(/^\/api\/v1\/users(?:\/([^/]+))?(?:\/(.+))?$/);
    if (userMatch) {
      const [, id, sub] = userMatch;
      if (!id && method === 'GET') return this.users.list(ctx);
      if (!id && method === 'POST') return this.users.create(ctx, body);
      if (id && sub === 'unlock' && method === 'POST') return this.users.unlock(ctx, id);
      if (id && sub === 'reset-password' && method === 'POST') return this.users.resetPassword(ctx, id, body);
      if (id && !sub && method === 'GET') return this.users.get(ctx, id);
      if (id && !sub && method === 'PUT') return this.users.update(ctx, id, body);
      if (id && !sub && method === 'DELETE') return this.users.deactivate(ctx, id);
    }

    // --- Audit Log Routes ---
    if (path === '/api/v1/audit-log' && method === 'GET') {
      return this.auditLog.list(ctx);
    }

    // --- Evidence Routes ---
    const evidenceMatch = path.match(/^\/api\/v1\/evidence(?:\/([^/]+))?$/);
    if (evidenceMatch) {
      const [, id] = evidenceMatch;
      if (!id && method === 'GET') return this.evidence.list(ctx);
      if (!id && method === 'POST') return this.evidence.create(ctx, body);
      if (id && method === 'DELETE') return this.evidence.delete(ctx, id);
    }

    // --- Notification Routes ---
    if (path === '/api/v1/notifications/read-all' && method === 'POST') {
      return this.notifications.markAllRead(ctx);
    }
    const notifMatch = path.match(/^\/api\/v1\/notifications(?:\/([^/]+))?(?:\/(.+))?$/);
    if (notifMatch) {
      const [, id, sub] = notifMatch;
      if (!id && method === 'GET') return this.notifications.list(ctx);
      if (id && sub === 'read' && method === 'PUT') return this.notifications.markRead(ctx, id);
    }

    // --- Training Routes ---
    if (path === '/api/v1/training/progress' && method === 'GET') {
      return this.training.getProgress(ctx);
    }
    const trainingMatch = path.match(/^\/api\/v1\/training\/modules(?:\/([^/]+))?(?:\/(.+))?$/);
    if (trainingMatch) {
      const [, id, sub] = trainingMatch;
      if (!id && method === 'GET') return this.training.listModules(ctx);
      if (id && sub === 'complete' && method === 'POST') return this.training.completeModule(ctx, id, body);
      if (id && !sub && method === 'GET') return this.training.getModule(ctx, id);
    }

    // --- Support Ticket Routes ---
    const ticketMatch = path.match(/^\/api\/v1\/support-tickets(?:\/([^/]+))?$/);
    if (ticketMatch) {
      const [, id] = ticketMatch;
      if (!id && method === 'GET') return this.tickets.list(ctx);
      if (!id && method === 'POST') return this.tickets.create(ctx, body);
      if (id && method === 'GET') return this.tickets.get(ctx, id);
      if (id && method === 'PUT') return this.tickets.update(ctx, id, body);
    }

    // --- Feature Request Routes ---
    const featureMatch = path.match(/^\/api\/v1\/feature-requests(?:\/([^/]+))?(?:\/(.+))?$/);
    if (featureMatch) {
      const [, id, sub] = featureMatch;
      if (!id && method === 'GET') return this.features.list(ctx);
      if (!id && method === 'POST') return this.features.create(ctx, body);
      if (id && sub === 'vote' && method === 'POST') return this.features.vote(ctx, id);
      if (id && !sub && method === 'PUT') return this.features.update(ctx, id, body);
    }

    // --- Knowledge Base Routes ---
    if (path === '/api/v1/knowledge-base' && method === 'GET') {
      return this.knowledgeBase.list(ctx);
    }

    // --- Operations Dashboard Routes ---
    if (path === '/api/v1/ops/metrics' && method === 'GET') return this.ops.getMetrics(ctx);
    if (path === '/api/v1/ops/tenant-health' && method === 'GET') return this.ops.getTenantHealth(ctx);

    // --- Export Routes ---
    const exportMatch = path.match(/^\/api\/v1\/export\/(.+)$/);
    if (exportMatch) {
      const type = exportMatch[1];
      const exportMap = {
        'assets': () => this.exports.exportAssets(ctx),
        'risk-assessments': () => this.exports.exportRiskAssessments(ctx),
        'compliance': () => this.exports.exportCompliance(ctx),
        'vendor-assessments': () => this.exports.exportVendors(ctx),
        'incidents': () => this.exports.exportIncidents(ctx),
        'evidence': () => this.exports.exportEvidence(ctx),
      };
      if (exportMap[type]) return exportMap[type]();
    }

    // --- Audit Report Routes ---
    if (path === '/api/v1/reports/audit-pack' && method === 'GET') return this.reports.auditPack(ctx);
    const assetProfileMatch = path.match(/^\/api\/v1\/reports\/asset-profile\/([^/]+)$/);
    if (assetProfileMatch) {
      return this.reports.assetProfile(ctx, assetProfileMatch[1]);
    }

    return errorResponse('Not found', 404);
  }
}
