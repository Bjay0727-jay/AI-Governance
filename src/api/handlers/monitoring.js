/**
 * ForgeAI Govern™ - Monitoring & Metrics Handlers
 *
 * Time-series performance, bias, and drift metrics for deployed AI systems.
 * Supports automated alerting when thresholds are breached.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

export class MonitoringHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async listByAsset(ctx, assetId) {
    const metricType = ctx.url.searchParams.get('metric_type');
    const from = ctx.url.searchParams.get('from');
    const to = ctx.url.searchParams.get('to');
    const limit = parseInt(ctx.url.searchParams.get('limit') || '100');

    let where = 'WHERE tenant_id = ? AND ai_asset_id = ?';
    const params = [ctx.user.tenant_id, assetId];

    if (metricType) { where += ' AND metric_type = ?'; params.push(metricType); }
    if (from) { where += ' AND recorded_at >= ?'; params.push(from); }
    if (to) { where += ' AND recorded_at <= ?'; params.push(to); }

    const metrics = await this.db.prepare(
      `SELECT * FROM monitoring_metrics ${where} ORDER BY recorded_at DESC LIMIT ?`
    ).bind(...params, Math.min(limit, 1000)).all();

    // Compute summary statistics
    const summary = {};
    for (const m of metrics.results) {
      if (!summary[m.metric_type]) {
        summary[m.metric_type] = { values: [], alerts: 0 };
      }
      summary[m.metric_type].values.push(m.metric_value);
      if (m.alert_triggered) summary[m.metric_type].alerts++;
    }
    for (const type of Object.keys(summary)) {
      const vals = summary[type].values;
      summary[type] = {
        count: vals.length,
        min: Math.min(...vals),
        max: Math.max(...vals),
        avg: vals.reduce((a, b) => a + b, 0) / vals.length,
        latest: vals[0],
        alerts: summary[type].alerts,
      };
    }

    return jsonResponse({ data: metrics.results, summary });
  }

  async record(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { ai_asset_id, metric_type, metric_value } = body;
    if (!ai_asset_id || !metric_type || metric_value === undefined) {
      return errorResponse('ai_asset_id, metric_type, and metric_value are required', 400);
    }

    const validTypes = ['accuracy', 'precision', 'recall', 'f1_score', 'auc_roc',
      'bias_index', 'drift_score', 'false_positive_rate', 'false_negative_rate',
      'disparate_impact', 'latency', 'availability', 'error_rate'];
    if (!validTypes.includes(metric_type)) {
      return errorResponse(`Invalid metric_type. Must be one of: ${validTypes.join(', ')}`, 400);
    }

    // Check thresholds for alerting
    let alertTriggered = false;
    let alertSeverity = null;
    const thresholdMin = body.threshold_min;
    const thresholdMax = body.threshold_max;

    if (thresholdMin !== undefined && metric_value < thresholdMin) {
      alertTriggered = true;
      alertSeverity = metric_value < thresholdMin * 0.8 ? 'critical' : 'warning';
    }
    if (thresholdMax !== undefined && metric_value > thresholdMax) {
      alertTriggered = true;
      alertSeverity = metric_value > thresholdMax * 1.2 ? 'critical' : 'warning';
    }

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO monitoring_metrics (id, tenant_id, ai_asset_id, metric_type, metric_value,
        threshold_min, threshold_max, alert_triggered, alert_severity, demographic_group, metadata, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      id, ctx.user.tenant_id, ai_asset_id, metric_type, metric_value,
      thresholdMin || null, thresholdMax || null,
      alertTriggered ? 1 : 0, alertSeverity,
      body.demographic_group || null,
      JSON.stringify(body.metadata || {})
    ).run();

    if (alertTriggered) {
      await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'alert', 'monitoring_metric', id, {
        metric_type, metric_value, alert_severity: alertSeverity, ai_asset_id
      });
    }

    return jsonResponse({
      data: { id, alert_triggered: alertTriggered, alert_severity: alertSeverity },
      message: alertTriggered ? `Alert triggered: ${metric_type} threshold breached` : 'Metric recorded'
    }, 201);
  }

  async getAlerts(ctx) {
    const severity = ctx.url.searchParams.get('severity');
    const from = ctx.url.searchParams.get('from');

    let where = 'WHERE m.tenant_id = ? AND m.alert_triggered = 1';
    const params = [ctx.user.tenant_id];
    if (severity) { where += ' AND m.alert_severity = ?'; params.push(severity); }
    if (from) { where += ' AND m.recorded_at >= ?'; params.push(from); }

    const alerts = await this.db.prepare(
      `SELECT m.*, a.name as asset_name, a.category, a.risk_tier
       FROM monitoring_metrics m
       JOIN ai_assets a ON m.ai_asset_id = a.id
       ${where} ORDER BY m.recorded_at DESC LIMIT 100`
    ).bind(...params).all();

    return jsonResponse({ data: alerts.results });
  }
}
