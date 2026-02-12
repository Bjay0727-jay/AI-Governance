/**
 * ForgeAI Govern™ - Compliance & Governance Handlers
 *
 * Multi-framework compliance mapping engine: NIST AI RMF, FDA SaMD,
 * ONC HTI-1, HIPAA, and state AI regulations in a unified catalog.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

export class ComplianceHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async listControls(ctx) {
    const family = ctx.url.searchParams.get('family');
    const search = ctx.url.searchParams.get('search');

    let where = 'WHERE 1=1';
    const params = [];
    if (family) { where += ' AND family = ?'; params.push(family); }
    if (search) { where += ' AND (title LIKE ? OR description LIKE ? OR control_id LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }

    const controls = await this.db.prepare(
      `SELECT * FROM compliance_controls ${where} ORDER BY control_id`
    ).bind(...params).all();

    // Group by family for easy consumption
    const grouped = { Govern: [], Map: [], Measure: [], Manage: [] };
    for (const ctrl of controls.results) {
      if (grouped[ctrl.family]) grouped[ctrl.family].push(ctrl);
    }

    return jsonResponse({ data: controls.results, grouped });
  }

  async getFrameworkMappings(ctx, controlId) {
    const control = await this.db.prepare(
      'SELECT * FROM compliance_controls WHERE id = ? OR control_id = ?'
    ).bind(controlId, controlId).first();
    if (!control) return errorResponse('Control not found', 404);

    return jsonResponse({
      data: {
        control,
        frameworks: {
          nist_ai_rmf: control.nist_ai_rmf_ref,
          fda_samd: control.fda_samd_ref,
          onc_hti1: control.onc_hti1_ref,
          hipaa: control.hipaa_ref,
          state_laws: JSON.parse(control.state_law_refs || '{}'),
          joint_commission: control.joint_commission_ref,
        }
      }
    });
  }

  async listImplementations(ctx) {
    const assetId = ctx.url.searchParams.get('ai_asset_id');
    const status = ctx.url.searchParams.get('status');

    let where = 'WHERE ci.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (assetId) { where += ' AND ci.ai_asset_id = ?'; params.push(assetId); }
    if (status) { where += ' AND ci.implementation_status = ?'; params.push(status); }

    const results = await this.db.prepare(
      `SELECT ci.*, cc.control_id as control_code, cc.title as control_title,
        cc.family, cc.nist_ai_rmf_ref, a.name as asset_name
       FROM control_implementations ci
       JOIN compliance_controls cc ON ci.control_id = cc.id
       LEFT JOIN ai_assets a ON ci.ai_asset_id = a.id
       ${where} ORDER BY cc.control_id`
    ).bind(...params).all();

    // Compute compliance summary
    const summary = { implemented: 0, partially_implemented: 0, planned: 0, not_applicable: 0, total: results.results.length };
    for (const impl of results.results) {
      summary[impl.implementation_status]++;
    }
    summary.compliance_percentage = summary.total > 0
      ? Math.round(((summary.implemented + summary.not_applicable) / summary.total) * 100) : 0;

    return jsonResponse({ data: results.results, summary });
  }

  async createImplementation(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { ai_asset_id, control_id, implementation_status, implementation_details } = body;
    if (!control_id || !implementation_status) {
      return errorResponse('control_id and implementation_status are required', 400);
    }

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO control_implementations (id, tenant_id, ai_asset_id, control_id,
        implementation_status, implementation_details, evidence_ids, responsible_party)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id, ctx.user.tenant_id, ai_asset_id || null, control_id,
      implementation_status, implementation_details || null,
      JSON.stringify(body.evidence_ids || []), body.responsible_party || null
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'control_implementation', id, { control_id, implementation_status });

    return jsonResponse({ data: { id }, message: 'Control implementation recorded' }, 201);
  }

  async updateImplementation(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM control_implementations WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Implementation not found', 404);

    const updates = [];
    const values = [];
    if (body.implementation_status) { updates.push('implementation_status = ?'); values.push(body.implementation_status); }
    if (body.implementation_details) { updates.push('implementation_details = ?'); values.push(body.implementation_details); }
    if (body.evidence_ids) { updates.push('evidence_ids = ?'); values.push(JSON.stringify(body.evidence_ids)); }
    if (body.responsible_party) { updates.push('responsible_party = ?'); values.push(body.responsible_party); }
    if (body.last_reviewed) { updates.push('last_reviewed = ?'); values.push(body.last_reviewed); }
    if (body.next_review) { updates.push('next_review = ?'); values.push(body.next_review); }

    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(
      `UPDATE control_implementations SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'control_implementation', id, {});
    return jsonResponse({ message: 'Implementation updated' });
  }
}
