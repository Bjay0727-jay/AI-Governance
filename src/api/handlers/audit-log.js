/**
 * ForgeAI Govern™ - Audit Log Handlers
 *
 * Admin-only access to immutable audit trail of all governance activities.
 */

import { jsonResponse, errorResponse } from '../utils.js';

export class AuditLogHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);

    const entityType = ctx.url.searchParams.get('entity_type');
    const userId = ctx.url.searchParams.get('user_id');
    const action = ctx.url.searchParams.get('action');
    const limit = Math.min(parseInt(ctx.url.searchParams.get('limit') || '100'), 500);

    let where = 'WHERE al.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (entityType) { where += ' AND al.entity_type = ?'; params.push(entityType); }
    if (userId) { where += ' AND al.user_id = ?'; params.push(userId); }
    if (action) { where += ' AND al.action = ?'; params.push(action); }

    const results = await this.db.prepare(
      `SELECT al.*, u.first_name || ' ' || u.last_name as user_name, u.email as user_email
       FROM audit_log al LEFT JOIN users u ON al.user_id = u.id
       ${where} ORDER BY al.created_at DESC LIMIT ?`
    ).bind(...params, limit).all();

    return jsonResponse({ data: results.results });
  }
}
