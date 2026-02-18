/**
 * ForgeAI Govern™ - Notification Handlers
 *
 * User-scoped in-app notification management.
 */

import { jsonResponse, errorResponse } from '../utils.js';

export class NotificationHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    const unreadOnly = ctx.url.searchParams.get('unread_only');
    const limit = Math.min(parseInt(ctx.url.searchParams.get('limit') || '50'), 100);

    let where = 'WHERE n.user_id = ? AND n.tenant_id = ?';
    const params = [ctx.user.user_id, ctx.user.tenant_id];
    if (unreadOnly === 'true') { where += ' AND n.read = 0'; }

    const results = await this.db.prepare(
      `SELECT n.* FROM notifications n ${where} ORDER BY n.created_at DESC LIMIT ?`
    ).bind(...params, limit).all();

    const unreadCount = await this.db.prepare(
      'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND tenant_id = ? AND read = 0'
    ).bind(ctx.user.user_id, ctx.user.tenant_id).first();

    return jsonResponse({ data: results.results, unread_count: unreadCount.c });
  }

  async markRead(ctx, id) {
    const notif = await this.db.prepare('SELECT * FROM notifications WHERE id = ? AND user_id = ?')
      .bind(id, ctx.user.user_id).first();
    if (!notif) return errorResponse('Notification not found', 404);

    await this.db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'Notification marked as read' });
  }

  async markAllRead(ctx) {
    await this.db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ? AND tenant_id = ? AND read = 0')
      .bind(ctx.user.user_id, ctx.user.tenant_id).run();
    return jsonResponse({ message: 'All notifications marked as read' });
  }
}
