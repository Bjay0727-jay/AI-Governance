/**
 * ForgeAI Govern™ - Dashboard & Reporting Handlers
 *
 * Portfolio-level governance statistics, compliance reports,
 * and executive summaries for board and C-suite consumption.
 */

import { jsonResponse, errorResponse } from '../utils.js';

export class DashboardHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async getStats(ctx) {
    const tenantId = ctx.user.tenant_id;

    // Run all queries in parallel via batch
    const [assets, riskDist, statusDist, categoryDist, assessments, alerts, incidents, compliance] = await Promise.all([
      this.db.prepare('SELECT COUNT(*) as total FROM ai_assets WHERE tenant_id = ? AND deployment_status != ?')
        .bind(tenantId, 'decommissioned').first(),
      this.db.prepare(
        `SELECT risk_tier, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? AND deployment_status != 'decommissioned' GROUP BY risk_tier`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT deployment_status, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? GROUP BY deployment_status`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT category, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? AND deployment_status != 'decommissioned' GROUP BY category`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT status, COUNT(*) as count FROM risk_assessments WHERE tenant_id = ? GROUP BY status`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT COUNT(*) as total, SUM(CASE WHEN alert_severity = 'critical' THEN 1 ELSE 0 END) as critical
         FROM monitoring_metrics WHERE tenant_id = ? AND alert_triggered = 1
         AND recorded_at >= datetime('now', '-30 days')`
      ).bind(tenantId).first(),
      this.db.prepare(
        `SELECT severity, COUNT(*) as count FROM incidents WHERE tenant_id = ? AND status != 'closed' GROUP BY severity`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT implementation_status, COUNT(*) as count FROM control_implementations WHERE tenant_id = ? GROUP BY implementation_status`
      ).bind(tenantId).all(),
    ]);

    const complianceSummary = {};
    let implTotal = 0;
    let implDone = 0;
    for (const row of compliance.results) {
      complianceSummary[row.implementation_status] = row.count;
      implTotal += row.count;
      if (row.implementation_status === 'implemented' || row.implementation_status === 'not_applicable') implDone += row.count;
    }

    return jsonResponse({
      data: {
        ai_portfolio: {
          total_assets: assets.total,
          risk_distribution: Object.fromEntries(riskDist.results.map(r => [r.risk_tier, r.count])),
          status_distribution: Object.fromEntries(statusDist.results.map(r => [r.deployment_status, r.count])),
          category_distribution: Object.fromEntries(categoryDist.results.map(r => [r.category, r.count])),
        },
        risk_assessments: Object.fromEntries(assessments.results.map(r => [r.status, r.count])),
        monitoring: {
          alerts_last_30_days: alerts.total || 0,
          critical_alerts: alerts.critical || 0,
        },
        open_incidents: Object.fromEntries(incidents.results.map(r => [r.severity, r.count])),
        compliance: {
          ...complianceSummary,
          compliance_percentage: implTotal > 0 ? Math.round((implDone / implTotal) * 100) : 0,
        },
      }
    });
  }

  async complianceReport(ctx) {
    const tenantId = ctx.user.tenant_id;
    const framework = ctx.url.searchParams.get('framework'); // nist_ai_rmf, fda_samd, onc_hti1, hipaa

    // Get all controls with implementation status
    let controlQuery = `
      SELECT cc.*, ci.implementation_status, ci.implementation_details, ci.last_reviewed,
        a.name as asset_name
      FROM compliance_controls cc
      LEFT JOIN control_implementations ci ON cc.id = ci.control_id AND ci.tenant_id = ?
      LEFT JOIN ai_assets a ON ci.ai_asset_id = a.id`;
    const params = [tenantId];

    if (framework) {
      const frameworkCol = {
        nist_ai_rmf: 'nist_ai_rmf_ref', fda_samd: 'fda_samd_ref',
        onc_hti1: 'onc_hti1_ref', hipaa: 'hipaa_ref'
      }[framework];
      if (frameworkCol) {
        controlQuery += ` WHERE cc.${frameworkCol} IS NOT NULL AND cc.${frameworkCol} != ''`;
      }
    }
    controlQuery += ' ORDER BY cc.family, cc.control_id';

    const results = await this.db.prepare(controlQuery).bind(...params).all();

    // Compute compliance by family
    const byFamily = {};
    for (const row of results.results) {
      if (!byFamily[row.family]) byFamily[row.family] = { total: 0, implemented: 0, partial: 0, planned: 0, na: 0, gap: 0 };
      byFamily[row.family].total++;
      const s = row.implementation_status;
      if (s === 'implemented') byFamily[row.family].implemented++;
      else if (s === 'partially_implemented') byFamily[row.family].partial++;
      else if (s === 'planned') byFamily[row.family].planned++;
      else if (s === 'not_applicable') byFamily[row.family].na++;
      else byFamily[row.family].gap++;
    }

    return jsonResponse({
      report: {
        title: 'AI Governance Compliance Report',
        generated_at: new Date().toISOString(),
        framework_filter: framework || 'all',
        summary_by_family: byFamily,
        controls: results.results,
      }
    });
  }

  async executiveReport(ctx) {
    const tenantId = ctx.user.tenant_id;

    const [stats, recentAssessments, recentIncidents, maturity] = await Promise.all([
      this.getStatsData(tenantId),
      this.db.prepare(
        `SELECT r.*, a.name as asset_name FROM risk_assessments r
         JOIN ai_assets a ON r.ai_asset_id = a.id
         WHERE r.tenant_id = ? ORDER BY r.created_at DESC LIMIT 5`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT i.*, a.name as asset_name FROM incidents i
         JOIN ai_assets a ON i.ai_asset_id = a.id
         WHERE i.tenant_id = ? AND i.status != 'closed' ORDER BY i.created_at DESC LIMIT 5`
      ).bind(tenantId).all(),
      this.db.prepare(
        `SELECT * FROM maturity_assessments WHERE tenant_id = ? ORDER BY assessment_date DESC LIMIT 1`
      ).bind(tenantId).first(),
    ]);

    return jsonResponse({
      report: {
        title: 'AI Governance Executive Summary',
        generated_at: new Date().toISOString(),
        portfolio_overview: stats,
        maturity_assessment: maturity ? {
          date: maturity.assessment_date,
          overall_score: maturity.overall_maturity_score,
          domains: {
            governance_structure: maturity.governance_structure_score,
            ai_inventory: maturity.ai_inventory_score,
            risk_assessment: maturity.risk_assessment_score,
            policy_compliance: maturity.policy_compliance_score,
            monitoring: maturity.monitoring_performance_score,
            vendor_management: maturity.vendor_management_score,
            transparency: maturity.transparency_score,
          }
        } : null,
        recent_assessments: recentAssessments.results,
        open_incidents: recentIncidents.results,
      }
    });
  }

  async getStatsData(tenantId) {
    const assets = await this.db.prepare(
      `SELECT COUNT(*) as total,
        SUM(CASE WHEN risk_tier = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN risk_tier = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN phi_access = 1 THEN 1 ELSE 0 END) as phi_accessing
       FROM ai_assets WHERE tenant_id = ? AND deployment_status != 'decommissioned'`
    ).bind(tenantId).first();
    return assets;
  }
}
