/**
 * ForgeAI Govern™ - Healthcare AI Governance Platform
 * Main Cloudflare Worker Entry Point
 *
 * Edge-deployed API with JWT authentication, RBAC, and multi-tenant isolation.
 * Aligned with NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, and state AI laws.
 */

import { Router } from './router.js';
import { AuthService } from './auth.js';
import { corsHeaders, jsonResponse, errorResponse } from './utils.js';

// Nightly backup tables (subset for automated snapshots)
const BACKUP_TABLES = [
  'tenants', 'users', 'ai_assets', 'risk_assessments', 'impact_assessments',
  'vendor_assessments', 'compliance_controls', 'control_implementations',
  'incidents', 'maturity_assessments', 'evidence', 'audit_log',
  'notifications', 'training_completions', 'support_tickets', 'feature_requests',
];

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    const url = new URL(request.url);

    // Health check — always available, even before secrets are configured
    if (url.pathname === '/api/v1/health') {
      return jsonResponse({
        status: 'healthy',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        jwt_configured: !!(env.JWT_SECRET && env.JWT_SECRET.length >= 32),
      }, 200, request, env);
    }

    // Validate JWT_SECRET is configured (fail loudly for all other routes)
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      console.error('FATAL: JWT_SECRET environment variable is not set or too short (minimum 32 characters). Use `wrangler secret put JWT_SECRET` to configure.');
      return errorResponse('Server configuration error: authentication not available', 500, request, env);
    }

    // API routes handled by the router
    if (url.pathname.startsWith('/api/')) {
      try {
        const router = new Router(env);
        return await router.handle(request);
      } catch (error) {
        console.error('Unhandled error:', error);
        return errorResponse('Internal server error', 500, request, env);
      }
    }

    // Non-API routes are served by Workers Static Assets (configured in wrangler.toml)
    // This fallback only triggers if assets middleware doesn't match
    return jsonResponse({ message: 'ForgeAI Govern™ API v1.0' }, 200, request, env);
  },

  // --- Cron Trigger: Nightly D1 Backup ---
  async scheduled(event, env, ctx) {
    console.log(`[cron] Backup triggered at ${new Date().toISOString()} by cron: ${event.cron}`);
    const r2 = env.EVIDENCE_STORE;
    const db = env.DB;
    if (!r2 || !db) {
      console.error('[cron] Missing R2 or D1 binding — skipping backup');
      return;
    }

    try {
      // Get all active tenants
      const tenants = await db.prepare("SELECT id FROM tenants WHERE status = 'active'").all();

      for (const tenant of tenants.results) {
        const tid = tenant.id;
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const snapshotId = `nightly-${tid}-${timestamp}`;
        const snapshotData = { snapshot_id: snapshotId, tenant_id: tid, created_at: new Date().toISOString(), type: 'scheduled', tables: {} };
        let totalRows = 0;

        for (const table of BACKUP_TABLES) {
          try {
            const isGlobal = table === 'compliance_controls' || table === 'training_modules';
            const rows = await db.prepare(
              `SELECT * FROM ${table} WHERE ${isGlobal ? '1=1' : 'tenant_id = ?'} ORDER BY rowid`
            ).bind(...(isGlobal ? [] : [tid])).all();
            snapshotData.tables[table] = rows.results;
            totalRows += rows.results.length;
          } catch { snapshotData.tables[table] = []; }
        }

        const key = `backups/${tid}/${snapshotId}.json`;
        await r2.put(key, JSON.stringify(snapshotData), {
          httpMetadata: { contentType: 'application/json' },
          customMetadata: { tenant_id: tid, snapshot_id: snapshotId, total_rows: String(totalRows), type: 'nightly' },
        });
        console.log(`[cron] Backed up tenant ${tid}: ${totalRows} rows → ${key}`);
      }
    } catch (err) {
      console.error('[cron] Backup failed:', err.message);
    }
  },
};
