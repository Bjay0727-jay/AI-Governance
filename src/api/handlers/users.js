/**
 * ForgeAI Govern™ - User Management Handlers
 *
 * Admin-only CRUD for tenant users, account unlock, and password reset.
 */

import { jsonResponse, errorResponse, generateUUID, validateEmail, sanitizeInput } from '../utils.js';

export class UserHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async list(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    const users = await this.db.prepare(
      `SELECT id, email, first_name, last_name, role, mfa_enabled, status, last_login, created_at
       FROM users WHERE tenant_id = ? ORDER BY created_at DESC`
    ).bind(ctx.user.tenant_id).all();
    return jsonResponse({ data: users.results });
  }

  async get(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    const user = await this.db.prepare(
      `SELECT id, email, first_name, last_name, role, mfa_enabled, status, last_login,
              failed_login_attempts, locked_until, created_at, updated_at
       FROM users WHERE id = ? AND tenant_id = ?`
    ).bind(id, ctx.user.tenant_id).first();
    if (!user) return errorResponse('User not found', 404);
    return jsonResponse({ data: user });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    const { email, password, first_name, last_name, role } = body;
    if (!email || !password || !first_name || !last_name) {
      return errorResponse('email, password, first_name, and last_name are required', 400);
    }
    if (!validateEmail(email)) return errorResponse('Invalid email format', 400);
    if (password.length < 12) return errorResponse('Password must be at least 12 characters', 400);
    if (password.length > 128) return errorResponse('Password must be at most 128 characters', 400);

    const validRoles = ['admin', 'governance_lead', 'reviewer', 'viewer'];
    const userRole = validRoles.includes(role) ? role : 'viewer';

    try {
      const id = generateUUID();
      const passwordHash = await ctx.auth.hashPassword(password);
      await this.db.prepare(
        `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`
      ).bind(id, ctx.user.tenant_id, sanitizeInput(email), passwordHash,
        sanitizeInput(first_name), sanitizeInput(last_name), userRole).run();

      await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'user', id, { email, role: userRole });

      return jsonResponse({
        data: { id, email, first_name, last_name, role: userRole, status: 'active' },
        message: 'User created successfully',
      }, 201);
    } catch (err) {
      if (err.message?.includes('UNIQUE')) return errorResponse('Email already exists in this organization', 409);
      return errorResponse('Internal server error', 500);
    }
  }

  async update(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    const existing = await this.db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('User not found', 404);

    const updates = [];
    const values = [];
    if (body.first_name !== undefined) { updates.push('first_name = ?'); values.push(sanitizeInput(body.first_name)); }
    if (body.last_name !== undefined) { updates.push('last_name = ?'); values.push(sanitizeInput(body.last_name)); }
    if (body.role !== undefined) {
      const validRoles = ['admin', 'governance_lead', 'reviewer', 'viewer'];
      if (validRoles.includes(body.role)) { updates.push('role = ?'); values.push(body.role); }
    }
    if (body.status !== undefined) {
      const validStatuses = ['active', 'deactivated'];
      if (validStatuses.includes(body.status)) { updates.push('status = ?'); values.push(body.status); }
    }
    if (body.password) {
      if (body.password.length < 12) return errorResponse('Password must be at least 12 characters', 400);
      const passwordHash = await ctx.auth.hashPassword(body.password);
      updates.push('password_hash = ?'); values.push(passwordHash);
      updates.push('failed_login_attempts = 0');
      updates.push('locked_until = NULL');
    }
    if (updates.length === 0) return errorResponse('No fields to update', 400);
    updates.push("updated_at = datetime('now')");

    await this.db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`)
      .bind(...values, id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'update', 'user', id, { fields: Object.keys(body) });

    const updated = await this.db.prepare(
      `SELECT id, email, first_name, last_name, role, mfa_enabled, status, last_login, created_at, updated_at
       FROM users WHERE id = ?`
    ).bind(id).first();
    return jsonResponse({ data: updated });
  }

  async deactivate(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    if (id === ctx.user.user_id) return errorResponse('Cannot deactivate your own account', 400);
    const existing = await this.db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('User not found', 404);

    await this.db.prepare(`UPDATE users SET status = 'deactivated', updated_at = datetime('now') WHERE id = ?`)
      .bind(id).run();
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'deactivate', 'user', id, {});
    return jsonResponse({ message: 'User deactivated' });
  }

  async unlock(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    const existing = await this.db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('User not found', 404);

    await this.db.prepare(
      `UPDATE users SET failed_login_attempts = 0, locked_until = NULL, status = 'active', updated_at = datetime('now') WHERE id = ?`
    ).bind(id).run();
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'unlock', 'user', id, {});
    return jsonResponse({ message: 'User account unlocked' });
  }

  async resetPassword(ctx, id, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);
    const { new_password } = body;
    if (!new_password || new_password.length < 12) return errorResponse('Password must be at least 12 characters', 400);
    if (new_password.length > 128) return errorResponse('Password must be at most 128 characters', 400);

    const existing = await this.db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('User not found', 404);

    const passwordHash = await ctx.auth.hashPassword(new_password);
    await this.db.prepare(
      `UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?`
    ).bind(passwordHash, id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'reset_password', 'user', id, {});
    return jsonResponse({ message: 'Password reset successfully' });
  }
}
