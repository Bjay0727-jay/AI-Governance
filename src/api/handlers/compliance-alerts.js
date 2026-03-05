/**
 * ForgeAI Govern™ - Compliance Alerting Handlers
 *
 * Proactive compliance violation detection: overdue risk reassessments,
 * expired evidence, low implementation rates, and approaching thresholds.
 */

import { jsonResponse, errorResponse } from '../utils.js';

export class ComplianceAlertHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async getAlerts(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const tenantId = ctx.user.tenant_id;
    const alerts = [];

    const [overdueAssessments, expiredEvidence, lowCompliance, overdueReviews] =
      await Promise.all([
        this._checkOverdueAssessments(tenantId),
        this._checkExpiredEvidence(tenantId),
        this._checkLowCompliance(tenantId),
        this._checkOverdueControlReviews(tenantId),
      ]);

    alerts.push(...overdueAssessments, ...expiredEvidence, ...lowCompliance, ...overdueReviews);

    // Sort by severity: critical > high > moderate
    const order = { critical: 0, high: 1, moderate: 2 };
    alerts.sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));

    return jsonResponse({
      data: alerts,
      summary: {
        total: alerts.length,
        critical: alerts.filter(a => a.severity === 'critical').length,
        high: alerts.filter(a => a.severity === 'high').length,
        moderate: alerts.filter(a => a.severity === 'moderate').length,
      },
    });
  }

  async _checkOverdueAssessments(tenantId) {
    const alerts = [];
    // Find high/critical assets without a risk assessment in their required period
    let assets;
    try {
      assets = await this.db.prepare(
        `SELECT a.id, a.name, a.risk_tier,
          MAX(r.created_at) as last_assessment
         FROM ai_assets a
         LEFT JOIN risk_assessments r ON r.ai_asset_id = a.id AND r.tenant_id = a.tenant_id
         WHERE a.tenant_id = ? AND a.deployment_status != 'decommissioned'
         GROUP BY a.id`
      ).bind(tenantId).all();
    } catch { return alerts; }

    const now = new Date();
    for (const asset of assets.results) {
      const maxDays = { critical: 90, high: 90, moderate: 180, low: 365 }[asset.risk_tier] || 365;
      if (!asset.last_assessment) {
        alerts.push({
          type: 'overdue_assessment',
          severity: asset.risk_tier === 'critical' || asset.risk_tier === 'high' ? 'critical' : 'high',
          entity_type: 'ai_asset',
          entity_id: asset.id,
          message: `"${asset.name}" (${asset.risk_tier}) has never been assessed`,
        });
      } else {
        const daysSince = Math.floor((now - new Date(asset.last_assessment)) / 86400000);
        if (daysSince > maxDays) {
          alerts.push({
            type: 'overdue_assessment',
            severity: asset.risk_tier === 'critical' ? 'critical' : 'high',
            entity_type: 'ai_asset',
            entity_id: asset.id,
            message: `"${asset.name}" (${asset.risk_tier}) assessment overdue by ${daysSince - maxDays} days`,
          });
        } else if (daysSince > maxDays * 0.8) {
          alerts.push({
            type: 'approaching_assessment_due',
            severity: 'moderate',
            entity_type: 'ai_asset',
            entity_id: asset.id,
            message: `"${asset.name}" (${asset.risk_tier}) assessment due in ${maxDays - daysSince} days`,
          });
        }
      }
    }
    return alerts;
  }

  async _checkExpiredEvidence(tenantId) {
    const alerts = [];
    try {
      const expired = this.db.prepare(
        `SELECT e.id, e.filename, e.entity_type, e.entity_id, e.retention_expires_at
         FROM evidence e
         WHERE e.tenant_id = ? AND e.retention_expires_at IS NOT NULL
           AND e.retention_expires_at < datetime('now')`
      ).bind(tenantId).all();

      for (const ev of expired.results) {
        alerts.push({
          type: 'expired_evidence',
          severity: 'high',
          entity_type: 'evidence',
          entity_id: ev.id,
          message: `Evidence "${ev.filename}" expired on ${ev.retention_expires_at}`,
        });
      }
    } catch { /* evidence table may not have retention_expires_at */ }
    return alerts;
  }

  async _checkLowCompliance(tenantId) {
    const alerts = [];
    let result;
    try {
      result = await this.db.prepare(
        `SELECT implementation_status, COUNT(*) as cnt
         FROM control_implementations WHERE tenant_id = ?
         GROUP BY implementation_status`
      ).bind(tenantId).all();
    } catch { return alerts; }

    const counts = {};
    let total = 0;
    for (const row of result.results) {
      counts[row.implementation_status] = row.cnt;
      total += row.cnt;
    }

    if (total > 0) {
      const implemented = (counts.implemented || 0) + (counts.not_applicable || 0);
      const pct = Math.round((implemented / total) * 100);
      if (pct < 50) {
        alerts.push({
          type: 'low_compliance_rate',
          severity: 'critical',
          entity_type: 'compliance',
          entity_id: null,
          message: `Overall compliance rate is ${pct}% (below 50% threshold)`,
        });
      } else if (pct < 70) {
        alerts.push({
          type: 'low_compliance_rate',
          severity: 'high',
          entity_type: 'compliance',
          entity_id: null,
          message: `Overall compliance rate is ${pct}% (below 70% target)`,
        });
      }
    }
    return alerts;
  }

  async _checkOverdueControlReviews(tenantId) {
    const alerts = [];
    try {
      const overdue = this.db.prepare(
        `SELECT ci.id, cc.control_id, cc.title, ci.next_review
         FROM control_implementations ci
         JOIN compliance_controls cc ON ci.control_id = cc.id
         WHERE ci.tenant_id = ? AND ci.next_review IS NOT NULL
           AND ci.next_review < datetime('now')`
      ).bind(tenantId).all();

      for (const item of overdue.results) {
        alerts.push({
          type: 'overdue_control_review',
          severity: 'high',
          entity_type: 'control_implementation',
          entity_id: item.id,
          message: `Control ${item.control_id} "${item.title}" review overdue since ${item.next_review}`,
        });
      }
    } catch { /* next_review column may not exist in all environments */ }
    return alerts;
  }
}
