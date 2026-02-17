/**
 * ForgeAI Govern™ - Vendor Assessment Handlers
 *
 * AI-specific vendor due diligence for third-party tools.
 * Evaluates training data, bias testing, security, and contractual provisions.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

export class VendorHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const results = await this.db.prepare(
      `SELECT va.*, u.first_name || ' ' || u.last_name as assessor_name
       FROM vendor_assessments va
       LEFT JOIN users u ON va.assessed_by = u.id
       WHERE va.tenant_id = ?
       ORDER BY va.created_at DESC`
    ).bind(ctx.user.tenant_id).all();

    return jsonResponse({ data: results.results });
  }

  async get(ctx, id) {
    const va = await this.db.prepare(
      `SELECT va.*, u.first_name || ' ' || u.last_name as assessor_name
       FROM vendor_assessments va
       LEFT JOIN users u ON va.assessed_by = u.id
       WHERE va.id = ? AND va.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();
    if (!va) return errorResponse('Vendor assessment not found', 404);
    return jsonResponse({ data: va });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { vendor_name, product_name } = body;
    if (!vendor_name || !product_name) return errorResponse('vendor_name and product_name are required', 400);

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO vendor_assessments (id, tenant_id, vendor_name, product_name, ai_asset_id,
        training_data_provenance, training_data_representativeness, bias_testing_results,
        validation_methodology, model_update_practices, data_security_controls, privacy_controls,
        contractual_provisions, incident_response_capability,
        transparency_score, bias_testing_score, security_score, data_practices_score, contractual_score,
        recommendation, assessed_by, assessed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      id, ctx.user.tenant_id, vendor_name, product_name,
      body.ai_asset_id || null, body.training_data_provenance || null,
      body.training_data_representativeness || null,
      JSON.stringify(body.bias_testing_results || {}),
      body.validation_methodology || null, body.model_update_practices || null,
      JSON.stringify(body.data_security_controls || {}),
      JSON.stringify(body.privacy_controls || {}),
      JSON.stringify(body.contractual_provisions || {}),
      body.incident_response_capability || null,
      body.transparency_score || null, body.bias_testing_score || null,
      body.security_score || null, body.data_practices_score || null,
      body.contractual_score || null,
      body.recommendation || 'pending', ctx.user.user_id
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'vendor_assessment', id, { vendor_name, product_name });

    const va = await this.db.prepare('SELECT * FROM vendor_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: va }, 201);
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM vendor_assessments WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Vendor assessment not found', 404);

    const updates = [];
    const values = [];
    const fields = ['training_data_provenance', 'training_data_representativeness',
      'validation_methodology', 'model_update_practices', 'incident_response_capability',
      'transparency_score', 'bias_testing_score', 'security_score',
      'data_practices_score', 'contractual_score', 'recommendation', 'conditions'];
    const jsonFields = ['bias_testing_results', 'data_security_controls', 'privacy_controls', 'contractual_provisions'];

    for (const f of fields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(body[f]); }
    }
    for (const f of jsonFields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(JSON.stringify(body[f])); }
    }

    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(
      `UPDATE vendor_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'vendor_assessment', id, {});
    const updated = await this.db.prepare('SELECT * FROM vendor_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }

  async calculateScore(ctx, id) {
    const va = await this.db.prepare(
      'SELECT * FROM vendor_assessments WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!va) return errorResponse('Vendor assessment not found', 404);

    const scores = [va.transparency_score, va.bias_testing_score, va.security_score,
                    va.data_practices_score, va.contractual_score].filter(s => s != null);

    if (scores.length === 0) return errorResponse('No dimension scores to calculate from', 400);

    // Weighted scoring: security and bias weighted higher for healthcare
    const weights = { transparency: 0.15, bias_testing: 0.25, security: 0.25, data_practices: 0.20, contractual: 0.15 };
    const weightedScore = Math.round(
      ((va.transparency_score || 3) * weights.transparency +
       (va.bias_testing_score || 3) * weights.bias_testing +
       (va.security_score || 3) * weights.security +
       (va.data_practices_score || 3) * weights.data_practices +
       (va.contractual_score || 3) * weights.contractual) * 20
    );

    let recommendation = 'approved';
    if (weightedScore < 40) recommendation = 'rejected';
    else if (weightedScore < 60) recommendation = 'conditional';

    await this.db.prepare(
      `UPDATE vendor_assessments SET overall_risk_score = ?, recommendation = ?, updated_at = datetime('now') WHERE id = ?`
    ).bind(weightedScore, recommendation, id).run();

    return jsonResponse({
      data: { overall_risk_score: weightedScore, recommendation },
      scoring: {
        weights,
        dimension_scores: {
          transparency: va.transparency_score, bias_testing: va.bias_testing_score,
          security: va.security_score, data_practices: va.data_practices_score,
          contractual: va.contractual_score,
        }
      }
    });
  }
}
