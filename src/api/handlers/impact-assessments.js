/**
 * ForgeAI Govern™ - Algorithmic Impact Assessment Handlers
 *
 * Structured bias and fairness evaluations aligned with state AI legislation
 * and NIST AI RMF guidance. Tracks demographic disparities and model drift.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

export class ImpactAssessmentHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const status = ctx.url.searchParams.get('status');
    let where = 'WHERE ia.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (status) { where += ' AND ia.status = ?'; params.push(status); }

    const results = await this.db.prepare(
      `SELECT ia.*, a.name as asset_name, a.category, a.risk_tier,
        u.first_name || ' ' || u.last_name as assessor_name
       FROM impact_assessments ia
       JOIN ai_assets a ON ia.ai_asset_id = a.id
       JOIN users u ON ia.assessor_id = u.id
       ${where} ORDER BY ia.created_at DESC`
    ).bind(...params).all();

    return jsonResponse({ data: results.results });
  }

  async get(ctx, id) {
    const aia = await this.db.prepare(
      `SELECT ia.*, a.name as asset_name, a.category
       FROM impact_assessments ia
       JOIN ai_assets a ON ia.ai_asset_id = a.id
       WHERE ia.id = ? AND ia.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();
    if (!aia) return errorResponse('Impact assessment not found', 404);
    return jsonResponse({ data: aia });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { ai_asset_id } = body;
    if (!ai_asset_id) return errorResponse('ai_asset_id is required', 400);

    const asset = await this.db.prepare(
      'SELECT id FROM ai_assets WHERE id = ? AND tenant_id = ?'
    ).bind(ai_asset_id, ctx.user.tenant_id).first();
    if (!asset) return errorResponse('AI asset not found', 404);

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO impact_assessments (id, tenant_id, ai_asset_id, assessor_id, assessment_period,
        demographic_groups_tested, performance_by_group, bias_indicators, disparate_impact_ratio,
        drift_detected, drift_details, drift_score, clinical_outcomes,
        remediation_required, remediation_plan, remediation_status, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id, ctx.user.tenant_id, ai_asset_id, ctx.user.user_id,
      body.assessment_period || null,
      JSON.stringify(body.demographic_groups_tested || []),
      JSON.stringify(body.performance_by_group || {}),
      JSON.stringify(body.bias_indicators || {}),
      body.disparate_impact_ratio || null,
      body.drift_detected ? 1 : 0,
      JSON.stringify(body.drift_details || {}),
      body.drift_score || null,
      JSON.stringify(body.clinical_outcomes || {}),
      body.remediation_required ? 1 : 0,
      body.remediation_plan || null,
      body.remediation_required ? 'planned' : 'not_needed',
      body.status || 'in_progress'
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'impact_assessment', id, { ai_asset_id });

    const aia = await this.db.prepare('SELECT * FROM impact_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: aia }, 201);
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM impact_assessments WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Impact assessment not found', 404);

    const updates = [];
    const values = [];
    const jsonFields = ['demographic_groups_tested', 'performance_by_group', 'bias_indicators', 'drift_details', 'clinical_outcomes'];
    const scalarFields = ['assessment_period', 'disparate_impact_ratio', 'drift_score', 'remediation_plan', 'remediation_status', 'status'];

    for (const f of jsonFields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(JSON.stringify(body[f])); }
    }
    for (const f of scalarFields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(body[f]); }
    }
    if (body.drift_detected !== undefined) { updates.push('drift_detected = ?'); values.push(body.drift_detected ? 1 : 0); }
    if (body.remediation_required !== undefined) { updates.push('remediation_required = ?'); values.push(body.remediation_required ? 1 : 0); }

    if (body.status === 'completed') {
      updates.push("completed_at = datetime('now')");
    }

    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(
      `UPDATE impact_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'impact_assessment', id, {});
    const updated = await this.db.prepare('SELECT * FROM impact_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }
}
