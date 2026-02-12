/**
 * ForgeAI Govern™ - Risk Assessment Handlers
 *
 * Structured multi-dimensional risk evaluation tied to AI assets.
 * Supports NIST AI RMF Measure function with 6 risk dimensions.
 */

import { jsonResponse, errorResponse, generateUUID, paginate } from '../utils.js';

export class RiskAssessmentHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  calculateOverallRisk(scores) {
    const { patient_safety_score, bias_fairness_score, data_privacy_score,
            clinical_validity_score, cybersecurity_score, regulatory_score } = scores;
    // Weighted: patient safety and bias weighted higher for healthcare
    const weights = { patient_safety: 0.25, bias_fairness: 0.20, data_privacy: 0.15,
                      clinical_validity: 0.15, cybersecurity: 0.15, regulatory: 0.10 };
    const weighted = (patient_safety_score * weights.patient_safety) +
                     (bias_fairness_score * weights.bias_fairness) +
                     (data_privacy_score * weights.data_privacy) +
                     (clinical_validity_score * weights.clinical_validity) +
                     (cybersecurity_score * weights.cybersecurity) +
                     (regulatory_score * weights.regulatory);
    if (weighted >= 4.0 || patient_safety_score === 5) return 'critical';
    if (weighted >= 3.0) return 'high';
    if (weighted >= 2.0) return 'moderate';
    return 'low';
  }

  async list(ctx) {
    const { user, url } = ctx;
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = parseInt(url.searchParams.get('limit') || '25');
    const status = url.searchParams.get('status');
    const { offset, limit: safeLimit } = paginate(null, page, limit);

    let where = 'WHERE r.tenant_id = ?';
    const params = [user.tenant_id];
    if (status) { where += ' AND r.status = ?'; params.push(status); }

    const results = await this.db.prepare(
      `SELECT r.*, a.name as asset_name, a.category as asset_category, a.risk_tier,
        u.first_name || ' ' || u.last_name as assessor_name
       FROM risk_assessments r
       JOIN ai_assets a ON r.ai_asset_id = a.id
       JOIN users u ON r.assessor_id = u.id
       ${where} ORDER BY r.created_at DESC LIMIT ? OFFSET ?`
    ).bind(...params, safeLimit, offset).all();

    return jsonResponse({ data: results.results });
  }

  async listByAsset(ctx, assetId) {
    const results = await this.db.prepare(
      `SELECT r.*, u.first_name || ' ' || u.last_name as assessor_name,
        u2.first_name || ' ' || u2.last_name as approver_name
       FROM risk_assessments r
       JOIN users u ON r.assessor_id = u.id
       LEFT JOIN users u2 ON r.approved_by = u2.id
       WHERE r.ai_asset_id = ? AND r.tenant_id = ?
       ORDER BY r.created_at DESC`
    ).bind(assetId, ctx.user.tenant_id).all();

    return jsonResponse({ data: results.results });
  }

  async get(ctx, id) {
    const assessment = await this.db.prepare(
      `SELECT r.*, a.name as asset_name, a.category, a.risk_tier,
        u.first_name || ' ' || u.last_name as assessor_name
       FROM risk_assessments r
       JOIN ai_assets a ON r.ai_asset_id = a.id
       JOIN users u ON r.assessor_id = u.id
       WHERE r.id = ? AND r.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();
    if (!assessment) return errorResponse('Risk assessment not found', 404);
    return jsonResponse({ data: assessment });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { ai_asset_id, assessment_type } = body;
    if (!ai_asset_id || !assessment_type) return errorResponse('ai_asset_id and assessment_type are required', 400);

    // Verify asset exists in tenant
    const asset = await this.db.prepare(
      'SELECT id FROM ai_assets WHERE id = ? AND tenant_id = ?'
    ).bind(ai_asset_id, ctx.user.tenant_id).first();
    if (!asset) return errorResponse('AI asset not found', 404);

    const scores = {
      patient_safety_score: body.patient_safety_score,
      bias_fairness_score: body.bias_fairness_score,
      data_privacy_score: body.data_privacy_score,
      clinical_validity_score: body.clinical_validity_score,
      cybersecurity_score: body.cybersecurity_score,
      regulatory_score: body.regulatory_score,
    };

    const allScored = Object.values(scores).every(s => s >= 1 && s <= 5);
    const overallRisk = allScored ? this.calculateOverallRisk(scores) : null;

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO risk_assessments (id, tenant_id, ai_asset_id, assessment_type, assessor_id,
        patient_safety_score, bias_fairness_score, data_privacy_score, clinical_validity_score,
        cybersecurity_score, regulatory_score, overall_risk_level, findings, recommendations,
        mitigation_plan, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id, ctx.user.tenant_id, ai_asset_id, assessment_type, ctx.user.user_id,
      scores.patient_safety_score || null, scores.bias_fairness_score || null,
      scores.data_privacy_score || null, scores.clinical_validity_score || null,
      scores.cybersecurity_score || null, scores.regulatory_score || null,
      overallRisk, JSON.stringify(body.findings || {}),
      body.recommendations || null, body.mitigation_plan || null, 'draft'
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'risk_assessment', id, { ai_asset_id, overall_risk_level: overallRisk });

    const assessment = await this.db.prepare('SELECT * FROM risk_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: assessment }, 201);
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM risk_assessments WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Risk assessment not found', 404);
    if (existing.status === 'approved') return errorResponse('Cannot modify approved assessments', 400);

    const scoreFields = ['patient_safety_score', 'bias_fairness_score', 'data_privacy_score',
      'clinical_validity_score', 'cybersecurity_score', 'regulatory_score'];
    const updates = [];
    const values = [];

    for (const field of scoreFields) {
      if (body[field] !== undefined) { updates.push(`${field} = ?`); values.push(body[field]); }
    }
    if (body.findings) { updates.push('findings = ?'); values.push(JSON.stringify(body.findings)); }
    if (body.recommendations) { updates.push('recommendations = ?'); values.push(body.recommendations); }
    if (body.mitigation_plan) { updates.push('mitigation_plan = ?'); values.push(body.mitigation_plan); }
    if (body.status) { updates.push('status = ?'); values.push(body.status); }

    // Recalculate overall risk if scores changed
    const merged = { ...existing, ...body };
    const allScored = scoreFields.every(f => merged[f] >= 1 && merged[f] <= 5);
    if (allScored) {
      const overallRisk = this.calculateOverallRisk(merged);
      updates.push('overall_risk_level = ?');
      values.push(overallRisk);
    }

    updates.push("updated_at = datetime('now')");
    await this.db.prepare(
      `UPDATE risk_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'risk_assessment', id, {});
    const updated = await this.db.prepare('SELECT * FROM risk_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }

  async approve(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Only admins and governance leads can approve assessments', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM risk_assessments WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Risk assessment not found', 404);

    const newStatus = body.approved ? 'approved' : 'rejected';
    await this.db.prepare(
      `UPDATE risk_assessments SET status = ?, approved_by = ?, review_notes = ?,
        completed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`
    ).bind(newStatus, ctx.user.user_id, body.review_notes || null, id).run();

    // Update asset risk tier based on approved assessment
    if (newStatus === 'approved' && existing.overall_risk_level) {
      await this.db.prepare(
        `UPDATE ai_assets SET risk_tier = ?, updated_at = datetime('now') WHERE id = ?`
      ).bind(existing.overall_risk_level, existing.ai_asset_id).run();
    }

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, newStatus, 'risk_assessment', id, {});
    return jsonResponse({ message: `Assessment ${newStatus}` });
  }
}
