/**
 * ForgeAI Govern™ - Operations Dashboard Handlers
 *
 * Admin-only platform metrics and tenant health scoring.
 */

import { jsonResponse, errorResponse } from '../utils.js';

export class OpsHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async getMetrics(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);

    const tid = ctx.user.tenant_id;
    const [totalUsers, totalAssets, totalRisk, totalImpact, totalIncidents, openIncidents,
      totalEvidence, totalVendors, totalTickets, openTickets, auditEntries,
      recentAudit, usersByRole, assetsByRisk, recentLogins] = await Promise.all([
      this.db.prepare("SELECT COUNT(*) as c FROM users WHERE tenant_id = ? AND status = 'active'").bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM ai_assets WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM risk_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM impact_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ? AND status NOT IN ('resolved', 'closed')").bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM evidence WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM vendor_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM support_tickets WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare("SELECT COUNT(*) as c FROM support_tickets WHERE tenant_id = ? AND status NOT IN ('resolved', 'closed')").bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM audit_log WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare("SELECT DATE(created_at) as day, COUNT(*) as count FROM audit_log WHERE tenant_id = ? AND created_at >= datetime('now', '-7 days') GROUP BY DATE(created_at) ORDER BY day").bind(tid).all(),
      this.db.prepare("SELECT role, COUNT(*) as count FROM users WHERE tenant_id = ? AND status = 'active' GROUP BY role").bind(tid).all(),
      this.db.prepare('SELECT risk_tier, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? GROUP BY risk_tier').bind(tid).all(),
      this.db.prepare("SELECT COUNT(DISTINCT user_id) as c FROM audit_log WHERE tenant_id = ? AND action = 'login' AND created_at >= datetime('now', '-30 days')").bind(tid).first(),
    ]);

    return jsonResponse({
      data: {
        totals: {
          users: totalUsers.c, assets: totalAssets.c, risk_assessments: totalRisk.c,
          impact_assessments: totalImpact.c, incidents: totalIncidents.c, open_incidents: openIncidents.c,
          evidence: totalEvidence.c, vendors: totalVendors.c, tickets: totalTickets.c,
          open_tickets: openTickets.c, audit_entries: auditEntries.c,
        },
        activity_7d: recentAudit.results,
        users_by_role: usersByRole.results,
        assets_by_risk: assetsByRisk.results,
        active_users_30d: recentLogins.c,
      },
    });
  }

  async getTenantHealth(ctx) {
    if (!ctx.auth.authorize(ctx.user, ['admin'])) return errorResponse('Admin access required', 403);

    const tid = ctx.user.tenant_id;
    const [hasAssets, hasRisk, hasImpact, hasCompliance, hasVendors, hasMonitoring, hasMaturity,
      recentActivity, overdueAssessments, criticalIncidents] = await Promise.all([
      this.db.prepare('SELECT COUNT(*) as c FROM ai_assets WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM risk_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM impact_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM control_implementations WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM vendor_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM monitoring_metrics WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare('SELECT COUNT(*) as c FROM maturity_assessments WHERE tenant_id = ?').bind(tid).first(),
      this.db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE tenant_id = ? AND created_at >= datetime('now', '-30 days')").bind(tid).first(),
      this.db.prepare("SELECT COUNT(*) as c FROM risk_assessments WHERE tenant_id = ? AND next_review_date < datetime('now') AND status != 'rejected'").bind(tid).first(),
      this.db.prepare("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ? AND severity = 'critical' AND status NOT IN ('resolved', 'closed')").bind(tid).first(),
    ]);

    let healthScore = 0;
    if (hasAssets.c > 0) healthScore += 15;
    if (hasRisk.c > 0) healthScore += 15;
    if (hasImpact.c > 0) healthScore += 10;
    if (hasCompliance.c > 0) healthScore += 20;
    if (hasVendors.c > 0) healthScore += 10;
    if (hasMonitoring.c > 0) healthScore += 10;
    if (hasMaturity.c > 0) healthScore += 10;
    if (recentActivity.c > 0) healthScore += 10;
    if (overdueAssessments.c > 0) healthScore -= 10;
    if (criticalIncidents.c > 0) healthScore -= 15;
    healthScore = Math.max(0, Math.min(100, healthScore));

    const alerts = [];
    if (hasAssets.c === 0) alerts.push({ type: 'warning', message: 'No AI assets registered. Register your first AI system to begin governance.' });
    if (hasRisk.c === 0) alerts.push({ type: 'warning', message: 'No risk assessments completed. Assess risk for your AI systems.' });
    if (hasCompliance.c === 0) alerts.push({ type: 'warning', message: 'No compliance controls mapped. Begin control implementation.' });
    if (overdueAssessments.c > 0) alerts.push({ type: 'danger', message: `${overdueAssessments.c} risk assessment(s) overdue for review.` });
    if (criticalIncidents.c > 0) alerts.push({ type: 'danger', message: `${criticalIncidents.c} unresolved critical incident(s).` });
    if (recentActivity.c === 0) alerts.push({ type: 'info', message: 'No platform activity in the last 30 days.' });

    return jsonResponse({
      data: {
        health_score: healthScore,
        health_grade: healthScore >= 80 ? 'A' : healthScore >= 60 ? 'B' : healthScore >= 40 ? 'C' : healthScore >= 20 ? 'D' : 'F',
        coverage: {
          assets: hasAssets.c > 0, risk_assessments: hasRisk.c > 0, impact_assessments: hasImpact.c > 0,
          compliance: hasCompliance.c > 0, vendors: hasVendors.c > 0, monitoring: hasMonitoring.c > 0, maturity: hasMaturity.c > 0,
        },
        alerts,
        overdue_assessments: overdueAssessments.c,
        critical_incidents: criticalIncidents.c,
        recent_activity_count: recentActivity.c,
      },
    });
  }
}
