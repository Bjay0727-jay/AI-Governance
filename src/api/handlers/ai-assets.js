/**
 * ForgeAI Govern™ - AI Asset Management Handlers
 *
 * Central registry of all AI/ML systems within a tenant's portfolio.
 * Supports: CRUD, risk tier classification, lifecycle status tracking.
 */

import { jsonResponse, errorResponse, generateUUID, paginate } from '../utils.js';

export class AIAssetHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const { user, url } = ctx;
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = parseInt(url.searchParams.get('limit') || '25');
    const category = url.searchParams.get('category');
    const riskTier = url.searchParams.get('risk_tier');
    const status = url.searchParams.get('status');
    const search = url.searchParams.get('search');
    const { offset, limit: safeLimit } = paginate(null, page, limit);

    let where = 'WHERE a.tenant_id = ?';
    const params = [user.tenant_id];

    if (category) { where += ' AND a.category = ?'; params.push(category); }
    if (riskTier) { where += ' AND a.risk_tier = ?'; params.push(riskTier); }
    if (status) { where += ' AND a.deployment_status = ?'; params.push(status); }
    if (search) { where += ' AND (a.name LIKE ? OR a.vendor LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

    const countResult = await this.db.prepare(
      `SELECT COUNT(*) as total FROM ai_assets a ${where}`
    ).bind(...params).first();

    const assets = await this.db.prepare(
      `SELECT a.*,
        u1.first_name || ' ' || u1.last_name as owner_name,
        u2.first_name || ' ' || u2.last_name as champion_name
       FROM ai_assets a
       LEFT JOIN users u1 ON a.owner_user_id = u1.id
       LEFT JOIN users u2 ON a.clinical_champion_id = u2.id
       ${where}
       ORDER BY a.updated_at DESC
       LIMIT ? OFFSET ?`
    ).bind(...params, safeLimit, offset).all();

    return jsonResponse({
      data: assets.results,
      pagination: { page, limit: safeLimit, total: countResult.total, pages: Math.ceil(countResult.total / safeLimit) }
    });
  }

  async get(ctx, id) {
    const asset = await this.db.prepare(
      `SELECT a.*,
        u1.first_name || ' ' || u1.last_name as owner_name,
        u2.first_name || ' ' || u2.last_name as champion_name,
        (SELECT COUNT(*) FROM risk_assessments WHERE ai_asset_id = a.id) as risk_assessment_count,
        (SELECT COUNT(*) FROM impact_assessments WHERE ai_asset_id = a.id) as impact_assessment_count,
        (SELECT overall_risk_level FROM risk_assessments WHERE ai_asset_id = a.id ORDER BY created_at DESC LIMIT 1) as latest_risk_level
       FROM ai_assets a
       LEFT JOIN users u1 ON a.owner_user_id = u1.id
       LEFT JOIN users u2 ON a.clinical_champion_id = u2.id
       WHERE a.id = ? AND a.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();

    if (!asset) return errorResponse('AI asset not found', 404);
    return jsonResponse({ data: asset });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { name, vendor, version, category, risk_tier, description } = body;
    if (!name || !category) return errorResponse('Name and category are required', 400);

    const validCategories = ['clinical_decision_support', 'diagnostic_imaging', 'predictive_analytics',
      'nlp_extraction', 'operational', 'administrative', 'revenue_cycle', 'other'];
    if (!validCategories.includes(category)) return errorResponse(`Invalid category. Must be one of: ${validCategories.join(', ')}`, 400);

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO ai_assets (id, tenant_id, name, vendor, version, category, risk_tier, fda_classification,
        data_sources, phi_access, phi_data_types, deployment_status, owner_user_id, clinical_champion_id,
        department, description, intended_use, known_limitations, training_data_description)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id, ctx.user.tenant_id, name, vendor || null, version || null, category,
      risk_tier || 'moderate', body.fda_classification || null,
      JSON.stringify(body.data_sources || []), body.phi_access ? 1 : 0,
      JSON.stringify(body.phi_data_types || []), body.deployment_status || 'proposed',
      body.owner_user_id || null, body.clinical_champion_id || null,
      body.department || null, description || null, body.intended_use || null,
      body.known_limitations || null, body.training_data_description || null
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'ai_asset', id, { name, category, risk_tier });

    const asset = await this.db.prepare('SELECT * FROM ai_assets WHERE id = ?').bind(id).first();
    return jsonResponse({ data: asset, message: 'AI asset registered successfully' }, 201);
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM ai_assets WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('AI asset not found', 404);

    const fields = ['name', 'vendor', 'version', 'category', 'risk_tier', 'fda_classification',
      'fda_clearance_number', 'deployment_status', 'deployment_date', 'owner_user_id',
      'clinical_champion_id', 'department', 'description', 'intended_use',
      'known_limitations', 'training_data_description'];

    const updates = [];
    const values = [];
    for (const field of fields) {
      if (body[field] !== undefined) {
        updates.push(`${field} = ?`);
        values.push(body[field]);
      }
    }
    // JSON fields
    if (body.data_sources !== undefined) { updates.push('data_sources = ?'); values.push(JSON.stringify(body.data_sources)); }
    if (body.phi_access !== undefined) { updates.push('phi_access = ?'); values.push(body.phi_access ? 1 : 0); }
    if (body.phi_data_types !== undefined) { updates.push('phi_data_types = ?'); values.push(JSON.stringify(body.phi_data_types)); }

    if (updates.length === 0) return errorResponse('No fields to update', 400);

    updates.push("updated_at = datetime('now')");
    await this.db.prepare(
      `UPDATE ai_assets SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`
    ).bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'ai_asset', id, { updated_fields: Object.keys(body) });

    const updated = await this.db.prepare('SELECT * FROM ai_assets WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }

  async delete(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) {
      return errorResponse('Only admins can decommission AI assets', 403);
    }

    const existing = await this.db.prepare(
      'SELECT * FROM ai_assets WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('AI asset not found', 404);

    // Soft delete - mark as decommissioned
    await this.db.prepare(
      `UPDATE ai_assets SET deployment_status = 'decommissioned', updated_at = datetime('now') WHERE id = ?`
    ).bind(id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'decommission', 'ai_asset', id, { name: existing.name });
    return jsonResponse({ message: 'AI asset decommissioned successfully' });
  }
}
