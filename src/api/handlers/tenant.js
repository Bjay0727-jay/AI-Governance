/**
 * ForgeAI Govern™ - Tenant Management Handlers
 *
 * Organization-level settings including HIPAA BAA acknowledgment.
 */

import { jsonResponse, errorResponse } from '../utils.js';

export class TenantHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  /**
   * Get tenant settings including BAA status and jurisdiction config.
   */
  async getSettings(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) {
      return errorResponse('Admin access required', 403);
    }

    const tenant = await this.db.prepare(
      `SELECT id, name, slug, plan, hipaa_baa_signed, hipaa_baa_signed_at, hipaa_baa_signed_by,
              data_residency, settings, status, created_at
       FROM tenants WHERE id = ?`
    ).bind(ctx.user.tenant_id).first();

    if (!tenant) return errorResponse('Tenant not found', 404);

    // If BAA was signed, include signer info
    let signerName = null;
    if (tenant.hipaa_baa_signed_by) {
      const signer = await this.db.prepare(
        'SELECT first_name, last_name, email FROM users WHERE id = ?'
      ).bind(tenant.hipaa_baa_signed_by).first();
      if (signer) signerName = `${signer.first_name} ${signer.last_name} (${signer.email})`;
    }

    return jsonResponse({
      data: {
        ...tenant,
        hipaa_baa_signer_name: signerName,
        settings: tenant.settings ? JSON.parse(tenant.settings) : {},
      },
    });
  }

  /**
   * Acknowledge HIPAA Business Associate Agreement.
   * Required before any AI asset can be registered with phi_access = true.
   */
  async acknowledgeBaa(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) {
      return errorResponse('Only admins can acknowledge the HIPAA BAA', 403);
    }

    const tenant = await this.db.prepare('SELECT hipaa_baa_signed FROM tenants WHERE id = ?')
      .bind(ctx.user.tenant_id).first();
    if (!tenant) return errorResponse('Tenant not found', 404);

    if (tenant.hipaa_baa_signed) {
      return errorResponse('HIPAA BAA has already been acknowledged', 409);
    }

    const now = new Date().toISOString();
    await this.db.prepare(
      `UPDATE tenants SET hipaa_baa_signed = 1, hipaa_baa_signed_at = ?, hipaa_baa_signed_by = ?, updated_at = datetime('now') WHERE id = ?`
    ).bind(now, ctx.user.user_id, ctx.user.tenant_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'acknowledge_baa', 'tenant', ctx.user.tenant_id, {
      acknowledged_at: now,
    });

    return jsonResponse({
      data: {
        hipaa_baa_signed: true,
        hipaa_baa_signed_at: now,
        hipaa_baa_signed_by: ctx.user.user_id,
      },
      message: 'HIPAA Business Associate Agreement acknowledged successfully',
    });
  }
}
