/**
 * ForgeAI Govern™ - Feature Request Handlers
 *
 * Community feature voting system with admin status management.
 */

import { jsonResponse, errorResponse, generateUUID, sanitizeInput } from '../utils.js';

export class FeatureRequestHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const status = ctx.url.searchParams.get('status');
    const category = ctx.url.searchParams.get('category');
    const sort = ctx.url.searchParams.get('sort');

    let where = 'WHERE fr.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (status) { where += ' AND fr.status = ?'; params.push(status); }
    if (category) { where += ' AND fr.category = ?'; params.push(category); }
    const orderBy = sort === 'votes' ? 'fr.vote_count DESC' : 'fr.created_at DESC';

    const results = await this.db.prepare(
      `SELECT fr.*, u.first_name || ' ' || u.last_name as created_by_name,
        (SELECT COUNT(*) FROM feature_request_votes v WHERE v.feature_request_id = fr.id AND v.user_id = ?) as user_voted
       FROM feature_requests fr JOIN users u ON fr.created_by = u.id
       ${where} ORDER BY ${orderBy}`
    ).bind(ctx.user.user_id, ...params).all();

    return jsonResponse({ data: results.results });
  }

  async create(ctx, body) {
    const { title, description, category } = body;
    if (!title || !description) return errorResponse('title and description are required', 400);

    const validCategories = ['governance', 'compliance', 'reporting', 'monitoring', 'integration', 'general'];
    const cat = validCategories.includes(category) ? category : 'general';

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO feature_requests (id, tenant_id, created_by, title, description, category, vote_count)
       VALUES (?, ?, ?, ?, ?, ?, 1)`
    ).bind(id, ctx.user.tenant_id, ctx.user.user_id, sanitizeInput(title),
      sanitizeInput(description), cat).run();

    // Auto-vote for creator
    await this.db.prepare(
      `INSERT INTO feature_request_votes (id, feature_request_id, user_id, tenant_id)
       VALUES (?, ?, ?, ?)`
    ).bind(generateUUID(), id, ctx.user.user_id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'feature_request', id, { title, category: cat });

    const fr = await this.db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(id).first();
    return jsonResponse({ data: fr }, 201);
  }

  async vote(ctx, id) {
    const fr = await this.db.prepare('SELECT * FROM feature_requests WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!fr) return errorResponse('Feature request not found', 404);

    const existingVote = await this.db.prepare(
      'SELECT id FROM feature_request_votes WHERE feature_request_id = ? AND user_id = ?'
    ).bind(id, ctx.user.user_id).first();

    if (existingVote) {
      // Unvote
      await this.db.prepare('DELETE FROM feature_request_votes WHERE id = ?').bind(existingVote.id).run();
      await this.db.prepare('UPDATE feature_requests SET vote_count = vote_count - 1 WHERE id = ?').bind(id).run();
      const updated = await this.db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(id).first();
      return jsonResponse({ data: updated, voted: false });
    }

    // Vote
    await this.db.prepare(
      `INSERT INTO feature_request_votes (id, feature_request_id, user_id, tenant_id)
       VALUES (?, ?, ?, ?)`
    ).bind(generateUUID(), id, ctx.user.user_id, ctx.user.tenant_id).run();
    await this.db.prepare('UPDATE feature_requests SET vote_count = vote_count + 1 WHERE id = ?').bind(id).run();

    const updated = await this.db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated, voted: true });
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);

    const existing = await this.db.prepare('SELECT * FROM feature_requests WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Feature request not found', 404);

    const updates = [];
    const values = [];
    if (body.status !== undefined) {
      const validStatuses = ['submitted', 'under_review', 'planned', 'in_progress', 'completed', 'declined'];
      if (validStatuses.includes(body.status)) { updates.push('status = ?'); values.push(body.status); }
    }
    if (body.admin_response !== undefined) {
      updates.push('admin_response = ?'); values.push(sanitizeInput(body.admin_response));
    }
    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(`UPDATE feature_requests SET ${updates.join(', ')} WHERE id = ?`)
      .bind(...values, id).run();
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'feature_request', id, {});

    const updated = await this.db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }
}
