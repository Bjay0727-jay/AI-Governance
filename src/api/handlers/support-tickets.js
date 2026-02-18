/**
 * ForgeAI Govern™ - Support Ticket Handlers
 *
 * Customer self-service ticketing with role-based visibility.
 */

import { jsonResponse, errorResponse, generateUUID, sanitizeInput } from '../utils.js';

export class SupportTicketHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const status = ctx.url.searchParams.get('status');
    const category = ctx.url.searchParams.get('category');
    const isAdmin = ctx.auth.authorize(ctx.user, ['admin']);

    let where = 'WHERE t.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (!isAdmin) { where += ' AND t.created_by = ?'; params.push(ctx.user.user_id); }
    if (status) { where += ' AND t.status = ?'; params.push(status); }
    if (category) { where += ' AND t.category = ?'; params.push(category); }

    const results = await this.db.prepare(
      `SELECT t.*, u.first_name || ' ' || u.last_name as created_by_name, u.email as created_by_email
       FROM support_tickets t JOIN users u ON t.created_by = u.id
       ${where} ORDER BY t.created_at DESC`
    ).bind(...params).all();

    return jsonResponse({ data: results.results });
  }

  async get(ctx, id) {
    const ticket = await this.db.prepare(
      `SELECT t.*, u.first_name || ' ' || u.last_name as created_by_name
       FROM support_tickets t JOIN users u ON t.created_by = u.id
       WHERE t.id = ? AND t.tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();
    if (!ticket) return errorResponse('Ticket not found', 404);

    if (!ctx.auth.authorize(ctx.user, ['admin']) && ticket.created_by !== ctx.user.user_id) {
      return errorResponse('Access denied', 403);
    }
    return jsonResponse({ data: ticket });
  }

  async create(ctx, body) {
    const { subject, description, category, priority } = body;
    if (!subject || !description) return errorResponse('subject and description are required', 400);

    const validCategories = ['general', 'technical', 'compliance', 'billing', 'feature_request', 'bug_report'];
    const validPriorities = ['low', 'medium', 'high', 'urgent'];
    const cat = validCategories.includes(category) ? category : 'general';
    const pri = validPriorities.includes(priority) ? priority : 'medium';

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO support_tickets (id, tenant_id, created_by, subject, description, category, priority)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, ctx.user.tenant_id, ctx.user.user_id, sanitizeInput(subject),
      sanitizeInput(description), cat, pri).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'support_ticket', id, { subject, category: cat });

    const ticket = await this.db.prepare('SELECT * FROM support_tickets WHERE id = ?').bind(id).first();
    return jsonResponse({ data: ticket }, 201);
  }

  async update(ctx, id, body) {
    const existing = await this.db.prepare('SELECT * FROM support_tickets WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Ticket not found', 404);

    const isAdmin = ctx.auth.authorize(ctx.user, ['admin']);
    const isOwner = existing.created_by === ctx.user.user_id;
    if (!isAdmin && !isOwner) return errorResponse('Access denied', 403);

    const updates = [];
    const values = [];
    if (body.status !== undefined) {
      const validStatuses = ['open', 'in_progress', 'waiting', 'resolved', 'closed'];
      if (validStatuses.includes(body.status)) {
        updates.push('status = ?'); values.push(body.status);
        if (['resolved', 'closed'].includes(body.status)) updates.push("resolved_at = datetime('now')");
      }
    }
    if (body.admin_notes !== undefined && isAdmin) {
      updates.push('admin_notes = ?'); values.push(sanitizeInput(body.admin_notes));
    }
    if (body.priority !== undefined && isAdmin) {
      const validPriorities = ['low', 'medium', 'high', 'urgent'];
      if (validPriorities.includes(body.priority)) { updates.push('priority = ?'); values.push(body.priority); }
    }
    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(`UPDATE support_tickets SET ${updates.join(', ')} WHERE id = ?`)
      .bind(...values, id).run();
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'support_ticket', id, {});

    const updated = await this.db.prepare('SELECT * FROM support_tickets WHERE id = ?').bind(id).first();
    return jsonResponse({ data: updated });
  }
}
