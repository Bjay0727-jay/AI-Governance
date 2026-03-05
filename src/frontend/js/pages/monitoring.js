export const monitoring = {
  async monitoring() {
    let alerts = { data: [] };
    try { alerts = await API.getAlerts(); } catch (e) { /* empty */ }

    return `
      <div class="page-header">
        <div><h2>AI Monitoring</h2><p>Real-time performance, bias, and drift metrics across the AI portfolio</p></div>
      </div>
      <div class="card">
        <div class="card-header"><h3>Recent Alerts</h3></div>
        ${alerts.data.length > 0 ? alerts.data.map(a => `
          <div class="alert-item">
            <div class="alert-severity ${a.alert_severity}"></div>
            <div class="alert-text">
              <strong>${a.asset_name}</strong> - ${a.metric_type}: ${a.metric_value}
              ${a.threshold_min ? `(min: ${a.threshold_min})` : ''} ${a.threshold_max ? `(max: ${a.threshold_max})` : ''}
            </div>
            <div class="alert-time">${App.formatDate(a.recorded_at)}</div>
          </div>
        `).join('') : '<div class="empty-state"><div class="empty-icon">&#9673;</div><p>No alerts triggered. All AI systems operating within thresholds.</p></div>'}
      </div>`;
  },
};
