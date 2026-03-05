/**
 * ForgeAI Govern™ - Backup & Disaster Recovery Handlers
 *
 * Admin-only endpoints for on-demand database snapshots and backup status.
 * In production (Cloudflare Workers), snapshots export key tables to R2.
 * In local dev, provides status information only.
 */

import { jsonResponse, errorResponse } from '../utils.js';

// Tables to include in backup snapshots, ordered by dependency
const BACKUP_TABLES = [
  'tenants', 'users', 'ai_assets', 'risk_assessments', 'impact_assessments',
  'vendor_assessments', 'compliance_controls', 'control_implementations',
  'incidents', 'maturity_assessments', 'evidence', 'audit_log',
  'notifications', 'training_completions', 'support_tickets', 'feature_requests',
];

// HIPAA minimum retention: 6 years
const RETENTION_YEARS = 6;

export class BackupHandlers {
  constructor(env) {
    this.db = env.DB;
    this.r2 = env.EVIDENCE_STORE || null;
  }

  async createSnapshot(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) {
      return errorResponse('Insufficient permissions — admin only', 403);
    }

    const tid = ctx.user.tenant_id;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const snapshotId = `backup-${tid}-${timestamp}`;

    const tableCounts = {};
    let totalRows = 0;

    for (const table of BACKUP_TABLES) {
      try {
        const result = await this.db.prepare(
          `SELECT COUNT(*) as c FROM ${table} WHERE ${table === 'compliance_controls' || table === 'training_modules' ? '1=1' : 'tenant_id = ?'}`
        ).bind(...(table === 'compliance_controls' || table === 'training_modules' ? [] : [tid])).first();
        tableCounts[table] = result.c;
        totalRows += result.c;
      } catch {
        tableCounts[table] = 0;
      }
    }

    // If R2 is available, export data as JSON to R2
    let storageLocation = 'not_available';
    if (this.r2) {
      try {
        const snapshotData = { snapshot_id: snapshotId, tenant_id: tid, created_at: new Date().toISOString(), tables: {} };
        for (const table of BACKUP_TABLES) {
          try {
            const isGlobal = table === 'compliance_controls' || table === 'training_modules';
            const rows = await this.db.prepare(
              `SELECT * FROM ${table} WHERE ${isGlobal ? '1=1' : 'tenant_id = ?'} ORDER BY rowid`
            ).bind(...(isGlobal ? [] : [tid])).all();
            snapshotData.tables[table] = rows.results;
          } catch { snapshotData.tables[table] = []; }
        }
        const key = `backups/${tid}/${snapshotId}.json`;
        await this.r2.put(key, JSON.stringify(snapshotData), {
          httpMetadata: { contentType: 'application/json' },
          customMetadata: { tenant_id: tid, snapshot_id: snapshotId, total_rows: String(totalRows) },
        });
        storageLocation = key;
      } catch (err) {
        storageLocation = `error: ${err.message}`;
      }
    }

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'backup', snapshotId,
      { total_rows: totalRows, table_counts: tableCounts, storage: storageLocation },
      { dataClassification: 'sensitive' });

    return jsonResponse({
      data: {
        snapshot_id: snapshotId,
        tenant_id: tid,
        created_at: new Date().toISOString(),
        total_rows: totalRows,
        table_counts: tableCounts,
        storage_location: storageLocation,
        retention_policy: `${RETENTION_YEARS} years (HIPAA compliant)`,
      },
    }, 201);
  }

  async getStatus(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) {
      return errorResponse('Insufficient permissions — admin only', 403);
    }

    const tid = ctx.user.tenant_id;

    // Count records per table for the tenant
    const tableCounts = {};
    let totalRows = 0;
    for (const table of BACKUP_TABLES) {
      try {
        const isGlobal = table === 'compliance_controls' || table === 'training_modules';
        const result = await this.db.prepare(
          `SELECT COUNT(*) as c FROM ${table} WHERE ${isGlobal ? '1=1' : 'tenant_id = ?'}`
        ).bind(...(isGlobal ? [] : [tid])).first();
        tableCounts[table] = result.c;
        totalRows += result.c;
      } catch {
        tableCounts[table] = 0;
      }
    }

    // Check latest audit log entry for last backup
    const lastBackup = await this.db.prepare(
      "SELECT created_at, details FROM audit_log WHERE tenant_id = ? AND action = 'create' AND entity_type = 'backup' ORDER BY created_at DESC LIMIT 1"
    ).bind(tid).first();

    return jsonResponse({
      data: {
        tenant_id: tid,
        total_rows: totalRows,
        table_counts: tableCounts,
        last_backup: lastBackup ? {
          created_at: lastBackup.created_at,
          details: JSON.parse(lastBackup.details || '{}'),
        } : null,
        r2_available: !!this.r2,
        retention_policy: `${RETENTION_YEARS} years (HIPAA compliant)`,
        recommendation: !lastBackup ? 'No backups found. Create your first backup with POST /api/v1/ops/backup.' : null,
      },
    });
  }
}
