export const dashboard = {
  async dashboard() {
    let stats = { data: { ai_portfolio: { total_assets: 0, risk_distribution: {}, status_distribution: {}, category_distribution: {} }, risk_assessments: {}, monitoring: {}, open_incidents: {}, compliance: {} } };
    let onboarding = { data: { steps: [], percentage: 100, completed: 0, total: 0 } };
    try {
      [stats, onboarding] = await Promise.all([
        API.getDashboardStats(),
        API.getOnboardingProgress(),
      ]);
    } catch (e) { /* use defaults */ }
    const d = stats.data;
    const total = d.ai_portfolio.total_assets;
    const risk = d.ai_portfolio.risk_distribution;
    const comp = d.compliance;
    const ob = onboarding.data;

    const showOnboarding = ob.percentage < 100;

    return `
      <div class="page-header">
        <div><h2>AI Governance Dashboard</h2><p>Portfolio overview and compliance status for ${API.tenant?.name || 'your organization'}</p></div>
      </div>
      ${showOnboarding ? `
      <div class="card onboarding-card" style="margin-bottom:24px">
        <div class="card-header">
          <h3>Getting Started - ${ob.completed}/${ob.total} Complete</h3>
          <button class="btn btn-sm btn-outline" onclick="document.querySelector('.onboarding-card').style.display='none'">Dismiss</button>
        </div>
        <div class="onboarding-progress-bar" style="margin-bottom:16px">
          <div class="onboarding-track">
            <div class="onboarding-fill" style="width:${ob.percentage}%"></div>
          </div>
          <span class="onboarding-pct">${ob.percentage}%</span>
        </div>
        <div class="onboarding-steps">
          ${ob.steps.map(s => `
            <div class="onboarding-step ${s.completed ? 'completed' : ''}" ${!s.completed ? `onclick="Pages.onboardingNavigate('${s.key}')"` : ''}>
              <span class="step-check">${s.completed ? '&#10003;' : '&#9675;'}</span>
              <div class="step-info">
                <strong>${s.label}</strong>
                <span class="step-desc">${s.description}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>` : ''}
      <div class="stats-row">
        <div class="stat-card info"><div class="stat-value">${total}</div><div class="stat-label">AI Systems in Portfolio</div></div>
        <div class="stat-card critical"><div class="stat-value">${(risk.critical || 0) + (risk.high || 0)}</div><div class="stat-label">High/Critical Risk Systems</div></div>
        <div class="stat-card warning"><div class="stat-value">${d.monitoring.alerts_last_30_days || 0}</div><div class="stat-label">Alerts (30 Days)</div></div>
        <div class="stat-card success"><div class="stat-value">${comp.compliance_percentage || 0}%</div><div class="stat-label">Compliance Score</div></div>
      </div>
      <div class="card-grid grid-2">
        <div class="card">
          <div class="card-header"><h3>Risk Distribution</h3></div>
          ${total > 0 ? `
          <div class="risk-bar">
            ${risk.critical ? `<div class="segment critical" style="width:${(risk.critical/total*100)}%">${risk.critical}</div>` : ''}
            ${risk.high ? `<div class="segment high" style="width:${(risk.high/total*100)}%">${risk.high}</div>` : ''}
            ${risk.moderate ? `<div class="segment moderate" style="width:${(risk.moderate/total*100)}%">${risk.moderate}</div>` : ''}
            ${risk.low ? `<div class="segment low" style="width:${(risk.low/total*100)}%">${risk.low}</div>` : ''}
          </div>
          <div class="risk-legend">
            <span><span class="dot" style="background:var(--danger)"></span> Critical (${risk.critical||0})</span>
            <span><span class="dot" style="background:#ef4444"></span> High (${risk.high||0})</span>
            <span><span class="dot" style="background:var(--warning)"></span> Moderate (${risk.moderate||0})</span>
            <span><span class="dot" style="background:var(--success)"></span> Low (${risk.low||0})</span>
          </div>` : '<div class="empty-state"><p>No AI assets registered yet</p></div>'}
        </div>
        <div class="card">
          <div class="card-header"><h3>Compliance Status</h3></div>
          <div style="text-align:center">
            <div class="compliance-gauge">
              <svg width="120" height="120" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="50" fill="none" stroke="#e2e8f0" stroke-width="10"/>
                <circle cx="60" cy="60" r="50" fill="none" stroke="#14b8a6" stroke-width="10"
                  stroke-dasharray="${(comp.compliance_percentage||0)*3.14} 314" stroke-linecap="round"/>
              </svg>
              <div class="gauge-text">${comp.compliance_percentage||0}%</div>
            </div>
            <div style="font-size:12px;color:var(--text-secondary)">
              Implemented: ${comp.implemented||0} | Partial: ${comp.partially_implemented||0} | Planned: ${comp.planned||0}
            </div>
          </div>
        </div>
      </div>
      <div class="card-grid grid-2" style="margin-top:16px">
        <div class="card">
          <div class="card-header"><h3>Assessment Status</h3></div>
          <table>
            <thead><tr><th>Status</th><th>Count</th></tr></thead>
            <tbody>
              ${Object.entries(d.risk_assessments).map(([s,c]) =>
                `<tr><td>${App.badge(s)}</td><td>${c}</td></tr>`
              ).join('') || '<tr><td colspan="2" style="text-align:center;color:var(--text-muted)">No assessments yet</td></tr>'}
            </tbody>
          </table>
        </div>
        <div class="card">
          <div class="card-header"><h3>Open Incidents</h3></div>
          ${Object.keys(d.open_incidents).length > 0 ? `<table>
            <thead><tr><th>Severity</th><th>Count</th></tr></thead>
            <tbody>
              ${Object.entries(d.open_incidents).map(([s,c]) =>
                `<tr><td>${App.badge(s)}</td><td>${c}</td></tr>`
              ).join('')}
            </tbody>
          </table>` : '<div class="empty-state"><p>No open incidents</p></div>'}
        </div>
      </div>`;
  },

  onboardingNavigate(step) {
    const routes = {
      add_asset: 'ai-assets', risk_assessment: 'risk-assessments',
      impact_assessment: 'impact-assessments', compliance: 'compliance',
      vendor_assessment: 'vendors', maturity: 'maturity', invite_team: 'users',
    };
    if (routes[step]) App.navigate(routes[step]);
  },
};
