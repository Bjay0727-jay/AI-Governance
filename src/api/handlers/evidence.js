/**
 * ForgeAI Govern™ - Evidence Management Handlers
 *
 * Compliance evidence artifacts linked to governance entities.
 */

import { jsonResponse, errorResponse, generateUUID, sanitizeInput } from '../utils.js';

export class EvidenceHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const entityType = ctx.url.searchParams.get('entity_type');
    const entityId = ctx.url.searchParams.get('entity_id');

    let where = 'WHERE e.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (entityType) { where += ' AND e.entity_type = ?'; params.push(entityType); }
    if (entityId) { where += ' AND e.entity_id = ?'; params.push(entityId); }

    const results = await this.db.prepare(
      `SELECT e.*, u.first_name || ' ' || u.last_name as uploaded_by_name
       FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id
       ${where} ORDER BY e.created_at DESC`
    ).bind(...params).all();

    return jsonResponse({ data: results.results });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { entity_type, entity_id, title, description, evidence_type, url } = body;
    if (!entity_type || !entity_id || !title) {
      return errorResponse('entity_type, entity_id, and title are required', 400);
    }

    const validEntityTypes = ['ai_asset', 'risk_assessment', 'impact_assessment', 'vendor_assessment', 'control_implementation'];
    if (!validEntityTypes.includes(entity_type)) return errorResponse('Invalid entity_type', 400);

    const validEvidenceTypes = ['document', 'link', 'screenshot', 'test_result', 'policy', 'audit_report', 'certification', 'other'];
    const evType = validEvidenceTypes.includes(evidence_type) ? evidence_type : 'other';

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO evidence (id, tenant_id, entity_type, entity_id, title, description, evidence_type, url, uploaded_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, ctx.user.tenant_id, entity_type, entity_id, sanitizeInput(title),
      description ? sanitizeInput(description) : null, evType, url || null, ctx.user.user_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'evidence', id, { entity_type, entity_id, title });

    const evidence = await this.db.prepare('SELECT * FROM evidence WHERE id = ?').bind(id).first();
    return jsonResponse({ data: evidence }, 201);
  }

  async delete(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare('SELECT * FROM evidence WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Evidence not found', 404);

    await this.db.prepare('DELETE FROM evidence WHERE id = ?').bind(id).run();
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'delete', 'evidence', id, { title: existing.title });
    return jsonResponse({ message: 'Evidence deleted' });
  }
}
