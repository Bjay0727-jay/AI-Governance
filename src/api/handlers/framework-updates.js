/**
 * ForgeAI Govern™ - Regulatory Framework Update Notification System
 *
 * Tracks NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, and state AI law updates.
 * Notifies governance leads and admins when regulatory changes affect controls.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

// Known framework versions for tracking updates
const FRAMEWORK_REGISTRY = [
  { id: 'nist-ai-rmf', name: 'NIST AI Risk Management Framework', version: '1.0', released: '2023-01-26', next_review: '2026-01-26' },
  { id: 'fda-samd', name: 'FDA Software as Medical Device (SaMD)', version: 'N51', released: '2024-09-01', next_review: '2026-09-01' },
  { id: 'onc-hti1', name: 'ONC Health Data, Technology, and Interoperability (HTI-1)', version: '89 FR 1192', released: '2024-01-09', next_review: '2026-06-01' },
  { id: 'hipaa-security', name: 'HIPAA Security Rule', version: '45 CFR 164', released: '2024-12-27', next_review: '2026-12-27' },
  { id: 'co-sb21-169', name: 'Colorado SB 21-169 (AI in Insurance)', version: '2021', released: '2021-07-06', next_review: '2026-07-06' },
  { id: 'nyc-ll144', name: 'NYC Local Law 144 (Automated Employment)', version: '2023', released: '2023-07-05', next_review: '2026-07-05' },
  { id: 'ca-ab2013', name: 'California AB-2013 (AI Transparency)', version: '2024', released: '2024-09-28', next_review: '2026-09-28' },
  { id: 'nist-csf', name: 'NIST Cybersecurity Framework', version: '2.0', released: '2024-02-26', next_review: '2027-02-26' },
];

export class FrameworkUpdateHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async listFrameworks(ctx) {
    // Return registry plus any tenant-specific tracking
    const tracked = await this.db.prepare(
      `SELECT * FROM framework_updates WHERE tenant_id = ? ORDER BY created_at DESC`
    ).bind(ctx.user.tenant_id).all().catch(() => ({ results: [] }));

    const enriched = FRAMEWORK_REGISTRY.map(fw => {
      const updates = tracked.results.filter(u => u.framework_id === fw.id);
      const daysUntilReview = Math.ceil((new Date(fw.next_review) - new Date()) / (1000 * 60 * 60 * 24));
      return {
        ...fw,
        updates: updates,
        review_status: daysUntilReview <= 0 ? 'overdue' : daysUntilReview <= 90 ? 'upcoming' : 'current',
        days_until_review: daysUntilReview,
      };
    });

    return jsonResponse({
      data: enriched,
      summary: {
        total_frameworks: enriched.length,
        overdue: enriched.filter(f => f.review_status === 'overdue').length,
        upcoming: enriched.filter(f => f.review_status === 'upcoming').length,
      },
    });
  }

  async recordUpdate(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { framework_id, title, description, effective_date, impact_level, affected_controls } = body;
    if (!framework_id || !title || !description) {
      return errorResponse('framework_id, title, and description are required', 400);
    }

    const validFrameworks = FRAMEWORK_REGISTRY.map(f => f.id);
    if (!validFrameworks.includes(framework_id)) {
      return errorResponse(`Invalid framework_id. Must be one of: ${validFrameworks.join(', ')}`, 400);
    }

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO framework_updates (id, tenant_id, framework_id, title, description, effective_date,
        impact_level, affected_controls, status, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?)`
    ).bind(
      id, ctx.user.tenant_id, framework_id, title, description,
      effective_date || null, impact_level || 'medium',
      JSON.stringify(affected_controls || []), ctx.user.user_id
    ).run();

    // Notify all admins and governance leads in the tenant
    const notifyRoles = await this.db.prepare(
      `SELECT id FROM users WHERE tenant_id = ? AND role IN ('admin', 'governance_lead') AND status = 'active'`
    ).bind(ctx.user.tenant_id).all();

    const framework = FRAMEWORK_REGISTRY.find(f => f.id === framework_id);
    for (const user of notifyRoles.results) {
      await this.db.prepare(
        `INSERT INTO notifications (id, user_id, tenant_id, type, title, message) VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        generateUUID(), user.id, ctx.user.tenant_id, 'regulatory_update',
        `Regulatory Update: ${framework?.name || framework_id}`,
        `${title} — Impact: ${impact_level || 'medium'}. Review required.`
      ).run();
    }

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'framework_update', id, {
      framework_id, title, impact_level,
    });

    return jsonResponse({ data: { id }, message: 'Framework update recorded and notifications sent' }, 201);
  }

  async acknowledgeUpdate(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM framework_updates WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Framework update not found', 404);

    await this.db.prepare(
      `UPDATE framework_updates SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`
    ).bind(ctx.user.user_id, id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'acknowledge', 'framework_update', id, {
      framework_id: existing.framework_id,
    });

    return jsonResponse({ message: 'Framework update acknowledged' });
  }
}
