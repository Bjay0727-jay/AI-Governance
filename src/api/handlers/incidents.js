/**
 * ForgeAI Govern™ - Incident Management Handlers
 *
 * AI-related incident tracking: patient safety events, bias detection,
 * performance degradation, model failures, and regulatory violations.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

export class IncidentHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const status = ctx.url.searchParams.get('status');
    const severity = ctx.url.searchParams.get('severity');
    const assetId = ctx.url.searchParams.get('ai_asset_id');

    let where = 'WHERE i.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (status) { where += ' AND i.status = ?'; params.push(status); }
    if (severity) { where += ' AND i.severity = ?'; params.push(severity); }
    if (assetId) { where += ' AND i.ai_asset_id = ?'; params.push(assetId); }

    const results = await this.db.prepare(
      `SELECT i.*, a.name as asset_name, a.category,
        u.first_name || ' ' || u.last_name as reporter_name
       FROM incidents i
       JOIN ai_assets a ON i.ai_asset_id = a.id
       JOIN users u ON i.reported_by = u.id
       ${where} ORDER BY i.created_at DESC`
    ).bind(...params).all();

    return jsonResponse({ data: results.results });
  }

  async get(ctx, id) {
    const incident = await this.db.prepare(
      `SELECT i.*, a.name as asset_name, a.category, a.risk_tier,
        u.first_name || ' ' || u.last_name as reporter_name
       FROM incidents i
       JOIN ai_assets a ON i.ai_asset_id = a.id
       JOIN users u ON i.reported_by = u.id
       WHERE i.id = ? AND i.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();
    if (!incident) return errorResponse('Incident not found', 404);
    return jsonResponse({ data: incident });
  }

  async create(ctx, body) {
    const { ai_asset_id, incident_type, severity, title, description } = body;
    if (!ai_asset_id || !incident_type || !severity || !title || !description) {
      return errorResponse('ai_asset_id, incident_type, severity, title, and description are required', 400);
    }

    const asset = await this.db.prepare(
      'SELECT id FROM ai_assets WHERE id = ? AND tenant_id = ?'
    ).bind(ai_asset_id, ctx.user.tenant_id).first();
    if (!asset) return errorResponse('AI asset not found', 404);

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO incidents (id, tenant_id, ai_asset_id, reported_by, incident_type,
        severity, title, description, patient_impact, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`
    ).bind(
      id, ctx.user.tenant_id, ai_asset_id, ctx.user.user_id,
      incident_type, severity, title, description, body.patient_impact ? 1 : 0
    ).run();

    // If critical patient safety incident, suspend the AI asset
    if (severity === 'critical' && incident_type === 'patient_safety') {
      await this.db.prepare(
        `UPDATE ai_assets SET deployment_status = 'suspended', updated_at = datetime('now') WHERE id = ?`
      ).bind(ai_asset_id).run();
    }

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'incident', id, { severity, incident_type, ai_asset_id });

    const incident = await this.db.prepare('SELECT * FROM incidents WHERE id = ?').bind(id).first();
    return jsonResponse({ data: incident }, 201);
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM incidents WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Incident not found', 404);

    const updates = [];
    const values = [];
    const fields = ['status', 'root_cause', 'corrective_actions', 'severity'];

    for (const f of fields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(body[f]); }
    }
    if (body.patient_impact !== undefined) { updates.push('patient_impact = ?'); values.push(body.patient_impact ? 1 : 0); }
    if (body.status === 'resolved' || body.status === 'closed') {
      updates.push("resolved_at = datetime('now')");
    }

    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(
      `UPDATE incidents SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'incident', id, { updated_fields: Object.keys(body) });
    const updated = await this.db.prepare('SELECT * FROM incidents WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }
}
