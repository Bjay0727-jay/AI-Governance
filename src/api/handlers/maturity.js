/**
 * ForgeAI Govern™ - Governance Maturity Assessment Handlers
 *
 * 7-domain maturity model aligned with NIST AI RMF functions.
 * 5-level maturity scale: Initial, Developing, Defined, Managed, Optimized.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

const MATURITY_LEVELS = {
  1: 'Initial',
  2: 'Developing',
  3: 'Defined',
  4: 'Managed',
  5: 'Optimized',
};

const DOMAIN_WEIGHTS = {
  governance_structure: 0.15,
  ai_inventory: 0.15,
  risk_assessment: 0.20,
  policy_compliance: 0.15,
  monitoring_performance: 0.15,
  vendor_management: 0.10,
  transparency: 0.10,
};

export class MaturityHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const results = await this.db.prepare(
      `SELECT ma.*, u.first_name || ' ' || u.last_name as assessor_name
       FROM maturity_assessments ma
       JOIN users u ON ma.assessor_id = u.id
       WHERE ma.tenant_id = ?
       ORDER BY ma.assessment_date DESC`
    ).bind(ctx.user.tenant_id).all();

    return jsonResponse({ data: results.results });
  }

  async get(ctx, id) {
    const assessment = await this.db.prepare(
      `SELECT ma.*, u.first_name || ' ' || u.last_name as assessor_name
       FROM maturity_assessments ma
       JOIN users u ON ma.assessor_id = u.id
       WHERE ma.id = ? AND ma.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();

    if (!assessment) return errorResponse('Maturity assessment not found', 404);

    return jsonResponse({
      data: assessment,
      maturity_levels: MATURITY_LEVELS,
      domain_weights: DOMAIN_WEIGHTS,
    });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const domainScoreFields = [
      'governance_structure_score', 'ai_inventory_score', 'risk_assessment_score',
      'policy_compliance_score', 'monitoring_performance_score',
      'vendor_management_score', 'transparency_score'
    ];

    // Calculate weighted overall score
    let overallScore = null;
    const scores = {};
    let allPresent = true;
    for (const field of domainScoreFields) {
      if (body[field] !== undefined && body[field] >= 1 && body[field] <= 5) {
        scores[field] = body[field];
      } else {
        allPresent = false;
      }
    }

    if (allPresent) {
      const domainKeys = Object.keys(DOMAIN_WEIGHTS);
      overallScore = 0;
      for (let i = 0; i < domainKeys.length; i++) {
        overallScore += scores[domainScoreFields[i]] * DOMAIN_WEIGHTS[domainKeys[i]];
      }
      overallScore = Math.round(overallScore * 100) / 100;
    }

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO maturity_assessments (id, tenant_id, assessor_id, assessment_date,
        governance_structure_score, ai_inventory_score, risk_assessment_score,
        policy_compliance_score, monitoring_performance_score, vendor_management_score,
        transparency_score, overall_maturity_score, domain_findings,
        immediate_actions, near_term_actions, strategic_actions, status)
       VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id, ctx.user.tenant_id, ctx.user.user_id,
      scores.governance_structure_score || null,
      scores.ai_inventory_score || null,
      scores.risk_assessment_score || null,
      scores.policy_compliance_score || null,
      scores.monitoring_performance_score || null,
      scores.vendor_management_score || null,
      scores.transparency_score || null,
      overallScore,
      JSON.stringify(body.domain_findings || {}),
      JSON.stringify(body.immediate_actions || []),
      JSON.stringify(body.near_term_actions || []),
      JSON.stringify(body.strategic_actions || []),
      body.status || 'draft'
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'maturity_assessment', id, { overall_score: overallScore });

    const assessment = await this.db.prepare('SELECT * FROM maturity_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({
      data: assessment,
      overall_maturity_level: overallScore ? MATURITY_LEVELS[Math.round(overallScore)] || 'N/A' : null,
    }, 201);
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM maturity_assessments WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Maturity assessment not found', 404);

    const updates = [];
    const values = [];

    const scoreFields = ['governance_structure_score', 'ai_inventory_score', 'risk_assessment_score',
      'policy_compliance_score', 'monitoring_performance_score', 'vendor_management_score', 'transparency_score'];
    const jsonFieldsList = ['domain_findings', 'immediate_actions', 'near_term_actions', 'strategic_actions'];

    for (const f of scoreFields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(body[f]); }
    }
    for (const f of jsonFieldsList) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(JSON.stringify(body[f])); }
    }
    if (body.status) { updates.push('status = ?'); values.push(body.status); }

    // Recalculate overall
    const merged = { ...existing, ...body };
    const domainKeys = Object.keys(DOMAIN_WEIGHTS);
    let allPresent = true;
    for (const f of scoreFields) {
      if (!(merged[f] >= 1 && merged[f] <= 5)) allPresent = false;
    }
    if (allPresent) {
      let overall = 0;
      for (let i = 0; i < domainKeys.length; i++) {
        overall += merged[scoreFields[i]] * DOMAIN_WEIGHTS[domainKeys[i]];
      }
      updates.push('overall_maturity_score = ?');
      values.push(Math.round(overall * 100) / 100);
    }

    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(
      `UPDATE maturity_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'maturity_assessment', id, {});
    const updated = await this.db.prepare('SELECT * FROM maturity_assessments WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }
}
