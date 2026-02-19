/**
 * ForgeAI Govern™ - API Documentation Handler
 *
 * Returns structured API documentation as JSON.
 */

import { jsonResponse } from '../utils.js';

export class DocsHandlers {
  getDocs() {
    return jsonResponse({
      title: 'ForgeAI Govern API',
      version: '1.0.0',
      description: 'Healthcare AI Governance Platform REST API',
      base_url: '/api/v1',
      authentication: {
        type: 'Bearer Token (JWT)',
        header: 'Authorization: Bearer <token>',
        token_expiry: '15 minutes',
        refresh: 'POST /api/v1/auth/refresh with refresh_token',
      },
      rate_limits: {
        global: '200 requests/minute per IP',
        auth: '10 attempts/15 minutes per IP',
      },
      endpoints: [
        { method: 'GET', path: '/health', auth: false, description: 'Health check' },
        { method: 'POST', path: '/auth/register', auth: false, description: 'Register organization', body: 'organization_name, email, password, first_name, last_name' },
        { method: 'POST', path: '/auth/login', auth: false, description: 'Sign in', body: 'email, password' },
        { method: 'POST', path: '/auth/refresh', auth: false, description: 'Refresh access token', body: 'refresh_token' },
        { method: 'GET', path: '/ai-assets', auth: true, description: 'List AI assets', query: 'page, limit, category, risk_tier, status, search' },
        { method: 'GET', path: '/ai-assets/:id', auth: true, description: 'Get AI asset detail' },
        { method: 'POST', path: '/ai-assets', auth: true, description: 'Register AI asset', roles: 'admin, governance_lead' },
        { method: 'PUT', path: '/ai-assets/:id', auth: true, description: 'Update AI asset', roles: 'admin, governance_lead, reviewer' },
        { method: 'DELETE', path: '/ai-assets/:id', auth: true, description: 'Decommission AI asset', roles: 'admin' },
        { method: 'GET', path: '/risk-assessments', auth: true, description: 'List risk assessments', query: 'ai_asset_id' },
        { method: 'POST', path: '/risk-assessments', auth: true, description: 'Create risk assessment', roles: 'admin, governance_lead, reviewer' },
        { method: 'PUT', path: '/risk-assessments/:id', auth: true, description: 'Update risk assessment' },
        { method: 'POST', path: '/risk-assessments/:id/approve', auth: true, description: 'Approve/reject assessment', roles: 'admin, governance_lead' },
        { method: 'GET', path: '/impact-assessments', auth: true, description: 'List impact assessments', query: 'ai_asset_id' },
        { method: 'POST', path: '/impact-assessments', auth: true, description: 'Create impact assessment' },
        { method: 'PUT', path: '/impact-assessments/:id', auth: true, description: 'Update impact assessment' },
        { method: 'GET', path: '/controls', auth: true, description: 'List compliance controls', query: 'family, search' },
        { method: 'GET', path: '/implementations', auth: true, description: 'List control implementations', query: 'ai_asset_id, status' },
        { method: 'POST', path: '/implementations', auth: true, description: 'Record control implementation' },
        { method: 'GET', path: '/vendor-assessments', auth: true, description: 'List vendor assessments' },
        { method: 'POST', path: '/vendor-assessments', auth: true, description: 'Create vendor assessment' },
        { method: 'PUT', path: '/vendor-assessments/:id', auth: true, description: 'Update vendor assessment' },
        { method: 'POST', path: '/vendor-assessments/:id/score', auth: true, description: 'Calculate vendor risk score' },
        { method: 'GET', path: '/incidents', auth: true, description: 'List incidents', query: 'status, severity, ai_asset_id' },
        { method: 'POST', path: '/incidents', auth: true, description: 'Report incident' },
        { method: 'PUT', path: '/incidents/:id', auth: true, description: 'Update incident' },
        { method: 'GET', path: '/evidence', auth: true, description: 'List evidence', query: 'entity_type, entity_id' },
        { method: 'POST', path: '/evidence', auth: true, description: 'Add evidence' },
        { method: 'DELETE', path: '/evidence/:id', auth: true, description: 'Delete evidence' },
        { method: 'GET', path: '/users', auth: true, description: 'List users', roles: 'admin' },
        { method: 'POST', path: '/users', auth: true, description: 'Create user', roles: 'admin' },
        { method: 'PUT', path: '/users/:id', auth: true, description: 'Update user', roles: 'admin' },
        { method: 'DELETE', path: '/users/:id', auth: true, description: 'Deactivate user', roles: 'admin' },
        { method: 'GET', path: '/audit-log', auth: true, description: 'View audit log', roles: 'admin' },
        { method: 'GET', path: '/support-tickets', auth: true, description: 'List support tickets' },
        { method: 'POST', path: '/support-tickets', auth: true, description: 'Create support ticket' },
        { method: 'PUT', path: '/support-tickets/:id', auth: true, description: 'Update support ticket' },
        { method: 'GET', path: '/feature-requests', auth: true, description: 'List feature requests', query: 'status, category, sort' },
        { method: 'POST', path: '/feature-requests', auth: true, description: 'Submit feature request' },
        { method: 'POST', path: '/feature-requests/:id/vote', auth: true, description: 'Toggle vote on feature request' },
        { method: 'PUT', path: '/feature-requests/:id', auth: true, description: 'Update feature request status', roles: 'admin' },
        { method: 'GET', path: '/knowledge-base', auth: true, description: 'Get knowledge base articles', query: 'category, search' },
        { method: 'GET', path: '/notifications', auth: true, description: 'List notifications for current user' },
        { method: 'PUT', path: '/notifications/:id/read', auth: true, description: 'Mark notification as read' },
        { method: 'POST', path: '/notifications/read-all', auth: true, description: 'Mark all notifications as read' },
        { method: 'GET', path: '/training/modules', auth: true, description: 'List training modules' },
        { method: 'GET', path: '/training/modules/:id', auth: true, description: 'Get training module detail' },
        { method: 'POST', path: '/training/modules/:id/complete', auth: true, description: 'Mark training module as completed' },
        { method: 'GET', path: '/training/progress', auth: true, description: 'Get training progress for current user' },
        { method: 'GET', path: '/onboarding/progress', auth: true, description: 'Get onboarding checklist progress' },
        { method: 'GET', path: '/dashboard/stats', auth: true, description: 'Dashboard statistics' },
        { method: 'GET', path: '/reports/compliance', auth: true, description: 'Compliance summary report' },
        { method: 'GET', path: '/reports/executive', auth: true, description: 'Executive summary report' },
        { method: 'GET', path: '/reports/audit-pack', auth: true, description: 'Generate audit-ready compliance package (HTML)' },
        { method: 'GET', path: '/reports/asset-profile/:id', auth: true, description: 'Generate asset profile report (HTML)' },
        { method: 'GET', path: '/export/:type', auth: true, description: 'Export data as CSV (assets, risk-assessments, compliance, vendor-assessments, incidents, evidence)' },
        { method: 'GET', path: '/ops/metrics', auth: true, description: 'Get operations metrics', roles: 'admin' },
        { method: 'GET', path: '/ops/tenant-health', auth: true, description: 'Get tenant health scores', roles: 'admin' },
        { method: 'GET', path: '/docs', auth: false, description: 'This API documentation' },
      ],
    });
  }
}
