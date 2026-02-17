/**
 * ForgeAI Govern™ - Page Renderers
 *
 * Generates HTML for each application page.
 * All pages are tenant-scoped with role-based visibility.
 */

const Pages = {
  // ==================== DASHBOARD ====================
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
                <circle cx="60" cy="60" r="50" fill="none" stroke="#2563eb" stroke-width="10"
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

  // ==================== AI ASSETS ====================
  async aiAssets() {
    let data = { data: [], pagination: { total: 0 } };
    try { data = await API.getAssets(); } catch (e) { /* empty */ }

    const categoryLabels = {
      clinical_decision_support: 'Clinical Decision Support', diagnostic_imaging: 'Diagnostic Imaging',
      predictive_analytics: 'Predictive Analytics', nlp_extraction: 'NLP Extraction',
      operational: 'Operational', administrative: 'Administrative', revenue_cycle: 'Revenue Cycle', other: 'Other'
    };

    return `
      <div class="page-header">
        <div><h2>AI Asset Registry</h2><p>${data.pagination?.total || 0} AI systems registered</p></div>
        <button class="btn btn-primary" id="btn-add-asset">+ Register AI Asset</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Name</th><th>Vendor</th><th>Category</th><th>Risk Tier</th><th>Status</th><th>PHI</th><th>Owner</th><th>Actions</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(a => `
                <tr>
                  <td><strong>${a.name}</strong></td>
                  <td>${a.vendor || 'Internal'}</td>
                  <td>${categoryLabels[a.category] || a.category}</td>
                  <td>${App.badge(a.risk_tier)}</td>
                  <td>${App.badge(a.deployment_status)}</td>
                  <td>${a.phi_access ? '<span class="badge badge-high">PHI</span>' : 'No'}</td>
                  <td>${a.owner_name || 'Unassigned'}</td>
                  <td><button class="btn btn-sm btn-outline" onclick="Pages.viewAsset('${a.id}')">View</button></td>
                </tr>
              `).join('') : '<tr><td colspan="8" class="empty-state">No AI assets registered. Click "Register AI Asset" to add your first system.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  // ==================== RISK ASSESSMENTS ====================
  async riskAssessments() {
    let data = { data: [] };
    try { data = await API.getRiskAssessments(); } catch (e) { /* empty */ }

    return `
      <div class="page-header">
        <div><h2>Risk Assessments</h2><p>Multi-dimensional risk evaluations aligned with NIST AI RMF</p></div>
        <button class="btn btn-primary" id="btn-add-risk">+ New Risk Assessment</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>AI System</th><th>Type</th><th>Safety</th><th>Bias</th><th>Privacy</th><th>Clinical</th><th>Cyber</th><th>Regulatory</th><th>Overall</th><th>Status</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(r => `
                <tr>
                  <td><strong>${r.asset_name}</strong></td>
                  <td>${r.assessment_type}</td>
                  <td>${r.patient_safety_score || '-'}/5</td>
                  <td>${r.bias_fairness_score || '-'}/5</td>
                  <td>${r.data_privacy_score || '-'}/5</td>
                  <td>${r.clinical_validity_score || '-'}/5</td>
                  <td>${r.cybersecurity_score || '-'}/5</td>
                  <td>${r.regulatory_score || '-'}/5</td>
                  <td>${App.badge(r.overall_risk_level)}</td>
                  <td>${App.badge(r.status)}</td>
                </tr>
              `).join('') : '<tr><td colspan="10" class="empty-state">No risk assessments yet</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  // ==================== IMPACT ASSESSMENTS ====================
  async impactAssessments() {
    let data = { data: [] };
    try { data = await API.getImpactAssessments(); } catch (e) { /* empty */ }

    return `
      <div class="page-header">
        <div><h2>Algorithmic Impact Assessments</h2><p>Bias testing, fairness evaluation, and drift detection</p></div>
        <button class="btn btn-primary" id="btn-add-aia">+ New Impact Assessment</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>AI System</th><th>Period</th><th>Drift Detected</th><th>Remediation</th><th>Status</th><th>Assessor</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(ia => `
                <tr>
                  <td><strong>${ia.asset_name}</strong></td>
                  <td>${ia.assessment_period || 'N/A'}</td>
                  <td>${ia.drift_detected ? '<span class="badge badge-critical">Yes</span>' : '<span class="badge badge-low">No</span>'}</td>
                  <td>${ia.remediation_required ? App.badge(ia.remediation_status || 'planned') : 'Not needed'}</td>
                  <td>${App.badge(ia.status)}</td>
                  <td>${ia.assessor_name}</td>
                </tr>
              `).join('') : '<tr><td colspan="6" class="empty-state">No impact assessments yet</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  // ==================== COMPLIANCE ====================
  async compliance() {
    let controls = { data: [], grouped: {} };
    let implementations = { data: [], summary: {} };
    try {
      controls = await API.getControls();
      implementations = await API.getImplementations();
    } catch (e) { /* empty */ }

    const families = ['Govern', 'Map', 'Measure', 'Manage'];
    const familyDescriptions = {
      Govern: 'Organizational governance structures and policies',
      Map: 'AI system categorization and context mapping',
      Measure: 'Risk assessment and performance measurement',
      Manage: 'Risk mitigation and ongoing management',
    };

    return `
      <div class="page-header">
        <div><h2>Compliance Management</h2><p>Multi-framework compliance mapping: NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA</p></div>
      </div>
      <div class="stats-row">
        <div class="stat-card success"><div class="stat-value">${implementations.summary.compliance_percentage || 0}%</div><div class="stat-label">Overall Compliance</div></div>
        <div class="stat-card info"><div class="stat-value">${implementations.summary.implemented || 0}</div><div class="stat-label">Implemented</div></div>
        <div class="stat-card warning"><div class="stat-value">${implementations.summary.partially_implemented || 0}</div><div class="stat-label">Partially Implemented</div></div>
        <div class="stat-card"><div class="stat-value">${implementations.summary.planned || 0}</div><div class="stat-label">Planned</div></div>
      </div>
      ${families.map(family => `
        <div class="card" style="margin-bottom:16px">
          <div class="card-header">
            <h3>${family} - ${familyDescriptions[family]}</h3>
            <span class="badge badge-info">${(controls.grouped?.[family] || []).length} controls</span>
          </div>
          <div class="table-container">
            <table>
              <thead><tr><th>Control ID</th><th>Title</th><th>NIST AI RMF</th><th>FDA SaMD</th><th>ONC HTI-1</th><th>HIPAA</th><th>Status</th></tr></thead>
              <tbody>
                ${(controls.grouped?.[family] || []).map(c => {
                  const impl = implementations.data.find(i => i.control_id === c.id);
                  return `<tr>
                    <td><strong>${c.control_id}</strong></td>
                    <td>${c.title}</td>
                    <td>${c.nist_ai_rmf_ref || '-'}</td>
                    <td>${c.fda_samd_ref || '-'}</td>
                    <td>${c.onc_hti1_ref || '-'}</td>
                    <td>${c.hipaa_ref || '-'}</td>
                    <td>${impl ? App.badge(impl.implementation_status) : '<span class="badge badge-draft">Gap</span>'}</td>
                  </tr>`;
                }).join('') || `<tr><td colspan="7" class="empty-state">No controls loaded. Run database seed to populate the control catalog.</td></tr>`}
              </tbody>
            </table>
          </div>
        </div>
      `).join('')}`;
  },

  // ==================== VENDORS ====================
  async vendors() {
    let data = { data: [] };
    try { data = await API.getVendorAssessments(); } catch (e) { /* empty */ }

    return `
      <div class="page-header">
        <div><h2>Vendor AI Assessments</h2><p>Third-party AI tool due diligence and risk scoring</p></div>
        <button class="btn btn-primary" id="btn-add-vendor">+ New Vendor Assessment</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Vendor</th><th>Product</th><th>Transparency</th><th>Bias Testing</th><th>Security</th><th>Data Practices</th><th>Contractual</th><th>Overall</th><th>Recommendation</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(v => `
                <tr>
                  <td><strong>${v.vendor_name}</strong></td>
                  <td>${v.product_name}</td>
                  <td>${v.transparency_score || '-'}/5</td>
                  <td>${v.bias_testing_score || '-'}/5</td>
                  <td>${v.security_score || '-'}/5</td>
                  <td>${v.data_practices_score || '-'}/5</td>
                  <td>${v.contractual_score || '-'}/5</td>
                  <td>${v.overall_risk_score || '-'}/100</td>
                  <td>${App.badge(v.recommendation || 'pending')}</td>
                </tr>
              `).join('') : '<tr><td colspan="9" class="empty-state">No vendor assessments yet</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  // ==================== MONITORING ====================
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

  // ==================== MATURITY ====================
  async maturity() {
    let data = { data: [] };
    try { data = await API.getMaturityAssessments(); } catch (e) { /* empty */ }

    const latest = data.data[0];
    const domains = [
      { key: 'governance_structure_score', label: 'Governance Structure' },
      { key: 'ai_inventory_score', label: 'AI Inventory' },
      { key: 'risk_assessment_score', label: 'Risk Assessment' },
      { key: 'policy_compliance_score', label: 'Policy & Compliance' },
      { key: 'monitoring_performance_score', label: 'Monitoring' },
      { key: 'vendor_management_score', label: 'Vendor Mgmt' },
      { key: 'transparency_score', label: 'Transparency' },
    ];
    const levels = { 1: 'Initial', 2: 'Developing', 3: 'Defined', 4: 'Managed', 5: 'Optimized' };

    return `
      <div class="page-header">
        <div><h2>Governance Maturity Assessment</h2><p>7-domain maturity model aligned with NIST AI RMF</p></div>
        <button class="btn btn-primary" id="btn-add-maturity">+ New Assessment</button>
      </div>
      ${latest ? `
        <div class="card" style="margin-bottom:16px">
          <div class="card-header">
            <h3>Current Maturity: ${levels[Math.round(latest.overall_maturity_score)] || 'N/A'} (${latest.overall_maturity_score?.toFixed(1) || 'N/A'}/5.0)</h3>
            <span style="font-size:12px;color:var(--text-secondary)">${App.formatDate(latest.assessment_date)}</span>
          </div>
          <div class="maturity-display">
            ${domains.map(d => {
              const score = latest[d.key] || 0;
              return `<div class="maturity-domain level-${score}">
                <div class="domain-score">${score || '-'}</div>
                <div class="domain-label">${d.label}</div>
              </div>`;
            }).join('')}
          </div>
        </div>
        <div class="card"><div class="card-header"><h3>Maturity Levels Reference</h3></div>
          <table>
            <thead><tr><th>Level</th><th>Name</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td>1</td><td>Initial</td><td>No formal governance. AI adopted ad hoc without oversight or documentation.</td></tr>
              <tr><td>2</td><td>Developing</td><td>Awareness exists. Some informal processes, but inconsistent application.</td></tr>
              <tr><td>3</td><td>Defined</td><td>Formal policies and processes established. Consistent but manual execution.</td></tr>
              <tr><td>4</td><td>Managed</td><td>Automated governance workflows. Systematic monitoring and measurement.</td></tr>
              <tr><td>5</td><td>Optimized</td><td>Continuous improvement. AI governance integrated into enterprise risk management.</td></tr>
            </tbody>
          </table>
        </div>
      ` : '<div class="card"><div class="empty-state"><div class="empty-icon">&#9670;</div><p>No maturity assessments yet. Click "New Assessment" to evaluate your organization.</p></div></div>'}`;
  },

  // ==================== INCIDENTS ====================
  async incidents() {
    let data = { data: [] };
    try { data = await API.getIncidents(); } catch (e) { /* empty */ }

    return `
      <div class="page-header">
        <div><h2>AI Incident Management</h2><p>Track and manage AI-related incidents</p></div>
        <button class="btn btn-danger" id="btn-add-incident">+ Report Incident</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Title</th><th>AI System</th><th>Type</th><th>Severity</th><th>Patient Impact</th><th>Status</th><th>Reported</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(i => `
                <tr>
                  <td><strong>${i.title}</strong></td>
                  <td>${i.asset_name}</td>
                  <td>${i.incident_type.replace(/_/g, ' ')}</td>
                  <td>${App.badge(i.severity)}</td>
                  <td>${i.patient_impact ? '<span class="badge badge-critical">Yes</span>' : 'No'}</td>
                  <td>${App.badge(i.status)}</td>
                  <td>${App.formatDate(i.created_at)}</td>
                </tr>
              `).join('') : '<tr><td colspan="7" class="empty-state">No incidents reported</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  // ==================== VIEW ASSET DETAIL ====================
  viewAsset(id) {
    this._selectedAssetId = id;
    App.navigate('asset-detail');
  },

  async assetDetail() {
    const id = this._selectedAssetId;
    if (!id) return '<div class="empty-state"><p>No asset selected</p><button class="btn btn-outline" onclick="App.navigate(\'ai-assets\')">Back to Registry</button></div>';

    try {
      const [assetRes, riskRes, impactRes, incidentRes, metricsRes, evidenceRes] = await Promise.all([
        API.getAsset(id),
        API.getRiskAssessments({ ai_asset_id: id }),
        API.getImpactAssessments({ ai_asset_id: id }),
        API.getIncidents({ ai_asset_id: id }),
        API.getAssetMetrics(id, { limit: 20 }),
        API.getEvidence({ entity_type: 'ai_asset', entity_id: id }),
      ]);

      const a = assetRes.data;
      const risks = riskRes.data || [];
      const impacts = impactRes.data || [];
      const incidents = incidentRes.data || [];
      const metrics = metricsRes.data || [];
      const evidence = evidenceRes.data || [];

      const categoryLabels = {
        clinical_decision_support: 'Clinical Decision Support', diagnostic_imaging: 'Diagnostic Imaging',
        predictive_analytics: 'Predictive Analytics', nlp_extraction: 'NLP Extraction',
        operational: 'Operational', administrative: 'Administrative', revenue_cycle: 'Revenue Cycle', other: 'Other'
      };

      return `
        <div class="page-header">
          <div>
            <button class="btn btn-sm btn-outline" onclick="App.navigate('ai-assets')" style="margin-bottom:8px">&larr; Back to Registry</button>
            <h2>${a.name} ${App.badge(a.risk_tier)} ${App.badge(a.deployment_status)}</h2>
            <p>${categoryLabels[a.category] || a.category} ${a.vendor ? '| ' + a.vendor : ''} ${a.version ? 'v' + a.version : ''}</p>
          </div>
          <div class="btn-group">
            <button class="btn btn-outline" onclick="Pages.showEditAssetForm('${a.id}')">Edit Asset</button>
          </div>
        </div>

        <div class="card" style="margin-bottom:16px">
          <div class="card-header"><h3>Overview</h3></div>
          <div class="detail-grid">
            <div class="detail-item"><span class="detail-label">Department</span><span>${a.department || 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-label">FDA Classification</span><span>${a.fda_classification || 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-label">PHI Access</span><span>${a.phi_access ? '<span class="badge badge-high">Yes</span>' : 'No'}</span></div>
            <div class="detail-item"><span class="detail-label">Owner</span><span>${a.owner_name || 'Unassigned'}</span></div>
            <div class="detail-item"><span class="detail-label">Clinical Champion</span><span>${a.champion_name || 'Unassigned'}</span></div>
            <div class="detail-item"><span class="detail-label">Deployment Date</span><span>${a.deployment_date ? App.formatDate(a.deployment_date) : 'N/A'}</span></div>
          </div>
          ${a.description ? `<div style="margin-top:12px"><strong>Description:</strong> ${a.description}</div>` : ''}
          ${a.intended_use ? `<div style="margin-top:8px"><strong>Intended Use:</strong> ${a.intended_use}</div>` : ''}
          ${a.known_limitations ? `<div style="margin-top:8px"><strong>Known Limitations:</strong> ${a.known_limitations}</div>` : ''}
        </div>

        <div class="tab-nav">
          <button class="tab-btn active" onclick="Pages.switchAssetTab('risk')">Risk Assessments (${risks.length})</button>
          <button class="tab-btn" onclick="Pages.switchAssetTab('impact')">Impact Assessments (${impacts.length})</button>
          <button class="tab-btn" onclick="Pages.switchAssetTab('incidents')">Incidents (${incidents.length})</button>
          <button class="tab-btn" onclick="Pages.switchAssetTab('monitoring')">Monitoring (${metrics.length})</button>
          <button class="tab-btn" onclick="Pages.switchAssetTab('evidence')">Evidence (${evidence.length})</button>
        </div>

        <div class="tab-panel active" id="tab-risk">
          <div class="card">
            <div class="table-container"><table>
              <thead><tr><th>Type</th><th>Safety</th><th>Bias</th><th>Privacy</th><th>Clinical</th><th>Cyber</th><th>Regulatory</th><th>Overall</th><th>Status</th><th>Date</th></tr></thead>
              <tbody>
                ${risks.length > 0 ? risks.map(r => `<tr>
                  <td>${r.assessment_type}</td>
                  <td>${r.patient_safety_score || '-'}/5</td><td>${r.bias_fairness_score || '-'}/5</td>
                  <td>${r.data_privacy_score || '-'}/5</td><td>${r.clinical_validity_score || '-'}/5</td>
                  <td>${r.cybersecurity_score || '-'}/5</td><td>${r.regulatory_score || '-'}/5</td>
                  <td>${App.badge(r.overall_risk_level)}</td><td>${App.badge(r.status)}</td>
                  <td>${App.formatDate(r.created_at)}</td>
                </tr>`).join('') : '<tr><td colspan="10" class="empty-state">No risk assessments</td></tr>'}
              </tbody>
            </table></div>
          </div>
        </div>

        <div class="tab-panel" id="tab-impact">
          <div class="card">
            <div class="table-container"><table>
              <thead><tr><th>Period</th><th>Drift Detected</th><th>Remediation</th><th>Status</th><th>Assessor</th><th>Date</th></tr></thead>
              <tbody>
                ${impacts.length > 0 ? impacts.map(ia => `<tr>
                  <td>${ia.assessment_period || 'N/A'}</td>
                  <td>${ia.drift_detected ? '<span class="badge badge-critical">Yes</span>' : '<span class="badge badge-low">No</span>'}</td>
                  <td>${ia.remediation_required ? App.badge(ia.remediation_status || 'planned') : 'Not needed'}</td>
                  <td>${App.badge(ia.status)}</td><td>${ia.assessor_name}</td>
                  <td>${App.formatDate(ia.created_at)}</td>
                </tr>`).join('') : '<tr><td colspan="6" class="empty-state">No impact assessments</td></tr>'}
              </tbody>
            </table></div>
          </div>
        </div>

        <div class="tab-panel" id="tab-incidents">
          <div class="card">
            <div class="table-container"><table>
              <thead><tr><th>Title</th><th>Type</th><th>Severity</th><th>Patient Impact</th><th>Status</th><th>Date</th></tr></thead>
              <tbody>
                ${incidents.length > 0 ? incidents.map(i => `<tr>
                  <td><strong>${i.title}</strong></td><td>${i.incident_type.replace(/_/g, ' ')}</td>
                  <td>${App.badge(i.severity)}</td>
                  <td>${i.patient_impact ? '<span class="badge badge-critical">Yes</span>' : 'No'}</td>
                  <td>${App.badge(i.status)}</td><td>${App.formatDate(i.created_at)}</td>
                </tr>`).join('') : '<tr><td colspan="6" class="empty-state">No incidents reported</td></tr>'}
              </tbody>
            </table></div>
          </div>
        </div>

        <div class="tab-panel" id="tab-monitoring">
          <div class="card">
            <div class="table-container"><table>
              <thead><tr><th>Metric</th><th>Value</th><th>Min Threshold</th><th>Max Threshold</th><th>Alert</th><th>Recorded</th></tr></thead>
              <tbody>
                ${metrics.length > 0 ? metrics.map(m => `<tr>
                  <td>${m.metric_type}</td><td><strong>${m.metric_value}</strong></td>
                  <td>${m.threshold_min || '-'}</td><td>${m.threshold_max || '-'}</td>
                  <td>${m.alert_triggered ? `<span class="badge badge-${m.alert_severity}">${m.alert_severity}</span>` : '<span class="badge badge-low">OK</span>'}</td>
                  <td>${App.formatDate(m.recorded_at)}</td>
                </tr>`).join('') : '<tr><td colspan="6" class="empty-state">No monitoring data</td></tr>'}
              </tbody>
            </table></div>
          </div>
        </div>

        <div class="tab-panel" id="tab-evidence">
          <div class="card">
            <div class="card-header">
              <h3>Evidence & Documentation</h3>
              <button class="btn btn-sm btn-primary" onclick="Pages.showEvidenceForm('ai_asset', '${a.id}')">+ Add Evidence</button>
            </div>
            <div class="table-container"><table>
              <thead><tr><th>Title</th><th>Type</th><th>Description</th><th>URL</th><th>Uploaded By</th><th>Date</th><th>Actions</th></tr></thead>
              <tbody>
                ${evidence.length > 0 ? evidence.map(e => `<tr>
                  <td><strong>${e.title}</strong></td><td>${App.badge(e.evidence_type)}</td>
                  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.description || '-'}</td>
                  <td>${e.url ? `<a href="${e.url}" target="_blank" rel="noopener">Link</a>` : '-'}</td>
                  <td>${e.uploaded_by_name || 'Unknown'}</td><td>${App.formatDate(e.created_at)}</td>
                  <td><button class="btn btn-sm btn-outline" onclick="Pages.deleteEvidence('${e.id}')">Delete</button></td>
                </tr>`).join('') : '<tr><td colspan="7" class="empty-state">No evidence attached. Click "Add Evidence" to link documentation.</td></tr>'}
              </tbody>
            </table></div>
          </div>
        </div>
      `;
    } catch (err) {
      return `<div class="empty-state"><p>Error loading asset: ${err.message}</p><button class="btn btn-outline" onclick="App.navigate('ai-assets')">Back to Registry</button></div>`;
    }
  },

  switchAssetTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
    document.querySelector(`[onclick="Pages.switchAssetTab('${tabName}')"]`)?.classList.add('active');
    document.getElementById(`tab-${tabName}`)?.classList.add('active');
  },

  async showEditAssetForm(assetId) {
    try {
      const { data: a } = await API.getAsset(assetId);
      App.openModal('Edit AI Asset', `
        <form id="edit-asset-form">
          <div class="form-group"><label>System Name *</label><input type="text" id="ea-name" value="${a.name}" required></div>
          <div class="form-row">
            <div class="form-group"><label>Vendor</label><input type="text" id="ea-vendor" value="${a.vendor || ''}"></div>
            <div class="form-group"><label>Version</label><input type="text" id="ea-version" value="${a.version || ''}"></div>
          </div>
          <div class="form-row">
            <div class="form-group"><label>Category</label>
              <select id="ea-category">
                <option value="clinical_decision_support" ${a.category==='clinical_decision_support'?'selected':''}>Clinical Decision Support</option>
                <option value="diagnostic_imaging" ${a.category==='diagnostic_imaging'?'selected':''}>Diagnostic Imaging</option>
                <option value="predictive_analytics" ${a.category==='predictive_analytics'?'selected':''}>Predictive Analytics</option>
                <option value="nlp_extraction" ${a.category==='nlp_extraction'?'selected':''}>NLP Extraction</option>
                <option value="operational" ${a.category==='operational'?'selected':''}>Operational</option>
                <option value="administrative" ${a.category==='administrative'?'selected':''}>Administrative</option>
                <option value="revenue_cycle" ${a.category==='revenue_cycle'?'selected':''}>Revenue Cycle</option>
                <option value="other" ${a.category==='other'?'selected':''}>Other</option>
              </select>
            </div>
            <div class="form-group"><label>Risk Tier</label>
              <select id="ea-risk">
                <option value="low" ${a.risk_tier==='low'?'selected':''}>Low</option>
                <option value="moderate" ${a.risk_tier==='moderate'?'selected':''}>Moderate</option>
                <option value="high" ${a.risk_tier==='high'?'selected':''}>High</option>
                <option value="critical" ${a.risk_tier==='critical'?'selected':''}>Critical</option>
              </select>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group"><label>Status</label>
              <select id="ea-status">
                <option value="proposed" ${a.deployment_status==='proposed'?'selected':''}>Proposed</option>
                <option value="validating" ${a.deployment_status==='validating'?'selected':''}>Validating</option>
                <option value="deployed" ${a.deployment_status==='deployed'?'selected':''}>Deployed</option>
                <option value="monitoring" ${a.deployment_status==='monitoring'?'selected':''}>Monitoring</option>
                <option value="suspended" ${a.deployment_status==='suspended'?'selected':''}>Suspended</option>
              </select>
            </div>
            <div class="form-group"><label>Department</label><input type="text" id="ea-dept" value="${a.department || ''}"></div>
          </div>
          <div class="form-group"><label>Description</label><textarea id="ea-desc">${a.description || ''}</textarea></div>
          <div class="form-group"><label>Intended Use</label><textarea id="ea-use">${a.intended_use || ''}</textarea></div>
          <div class="form-group"><label>Known Limitations</label><textarea id="ea-lim">${a.known_limitations || ''}</textarea></div>
        </form>
      `, '<button class="btn btn-primary" id="ea-submit">Save Changes</button>');
      document.getElementById('ea-submit').addEventListener('click', async () => {
        try {
          await API.updateAsset(assetId, {
            name: document.getElementById('ea-name').value,
            vendor: document.getElementById('ea-vendor').value || null,
            version: document.getElementById('ea-version').value || null,
            category: document.getElementById('ea-category').value,
            risk_tier: document.getElementById('ea-risk').value,
            deployment_status: document.getElementById('ea-status').value,
            department: document.getElementById('ea-dept').value || null,
            description: document.getElementById('ea-desc').value || null,
            intended_use: document.getElementById('ea-use').value || null,
            known_limitations: document.getElementById('ea-lim').value || null,
          });
          App.closeModal();
          App.toast('Asset updated', 'success');
          App.navigate('asset-detail');
        } catch (err) { App.toast(err.message, 'error'); }
      });
    } catch (err) { App.toast(err.message, 'error'); }
  },

  showEvidenceForm(entityType, entityId) {
    App.openModal('Add Evidence', `
      <form id="evidence-form">
        <div class="form-group"><label>Title *</label><input type="text" id="ev-title" required placeholder="e.g., Validation Test Results"></div>
        <div class="form-group"><label>Evidence Type</label>
          <select id="ev-type">
            <option value="document">Document</option>
            <option value="link">Link/URL</option>
            <option value="test_result">Test Result</option>
            <option value="policy">Policy</option>
            <option value="audit_report">Audit Report</option>
            <option value="certification">Certification</option>
            <option value="screenshot">Screenshot</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="form-group"><label>URL (optional)</label><input type="url" id="ev-url" placeholder="https://..."></div>
        <div class="form-group"><label>Description</label><textarea id="ev-desc" placeholder="Describe this evidence..."></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="ev-submit">Add Evidence</button>');
    document.getElementById('ev-submit').addEventListener('click', async () => {
      try {
        await API.createEvidence({
          entity_type: entityType,
          entity_id: entityId,
          title: document.getElementById('ev-title').value,
          evidence_type: document.getElementById('ev-type').value,
          url: document.getElementById('ev-url').value || null,
          description: document.getElementById('ev-desc').value || null,
        });
        App.closeModal();
        App.toast('Evidence added', 'success');
        if (entityType === 'ai_asset') App.navigate('asset-detail');
        else App.navigate(App.currentPage);
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async deleteEvidence(evidenceId) {
    if (!confirm('Delete this evidence record?')) return;
    try {
      await API.deleteEvidence(evidenceId);
      App.toast('Evidence deleted', 'success');
      App.navigate('asset-detail');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  // ==================== ONBOARDING NAVIGATION ====================
  onboardingNavigate(step) {
    const routes = {
      add_asset: 'ai-assets', risk_assessment: 'risk-assessments',
      impact_assessment: 'impact-assessments', compliance: 'compliance',
      vendor_assessment: 'vendors', maturity: 'maturity', invite_team: 'users',
    };
    if (routes[step]) App.navigate(routes[step]);
  },

  // ==================== KNOWLEDGE BASE ====================
  async knowledgeBase() {
    let data = { data: [] };
    try { data = await API.getKnowledgeBase(); } catch (e) { /* empty */ }

    const categoryLabels = {
      framework: 'Framework', regulatory: 'Regulatory', guide: 'How-To Guide',
    };
    const categoryIcons = {
      framework: '&#9881;', regulatory: '&#9878;', guide: '&#9997;',
    };

    return `
      <div class="page-header">
        <div><h2>Knowledge Base</h2><p>Regulatory guidance, framework references, and how-to guides for healthcare AI governance</p></div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline kb-filter active" onclick="Pages.filterKB('')">All</button>
          <button class="btn btn-sm btn-outline kb-filter" onclick="Pages.filterKB('framework')">Frameworks</button>
          <button class="btn btn-sm btn-outline kb-filter" onclick="Pages.filterKB('regulatory')">Regulatory</button>
          <button class="btn btn-sm btn-outline kb-filter" onclick="Pages.filterKB('guide')">Guides</button>
        </div>
      </div>
      <div class="kb-search" style="margin-bottom:20px">
        <input type="text" id="kb-search-input" placeholder="Search articles..." class="form-input" style="width:100%;max-width:400px"
          oninput="Pages.searchKB(this.value)">
      </div>
      <div class="kb-articles" id="kb-articles">
        ${data.data.map(article => `
          <div class="card kb-article" data-category="${article.category}" style="margin-bottom:12px;cursor:pointer"
            onclick="Pages.expandKBArticle('${article.id}')">
            <div class="card-header">
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:18px">${categoryIcons[article.category] || ''}</span>
                <div>
                  <h3 style="margin:0">${article.title}</h3>
                  <span class="badge badge-info" style="margin-top:4px">${categoryLabels[article.category] || article.category}</span>
                  ${article.frameworks ? article.frameworks.map(f => `<span class="badge badge-moderate" style="margin-left:4px">${f}</span>`).join('') : ''}
                </div>
              </div>
            </div>
            <p style="color:var(--text-secondary);font-size:13px;margin:8px 0 0">${article.summary}</p>
            <div class="kb-content" id="kb-${article.id}" style="display:none;margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
              <div class="kb-body">${article.content.split('\n').map(line => {
                if (line.startsWith('**') && line.endsWith('**')) return `<h4>${line.replace(/\*\*/g, '')}</h4>`;
                if (line.startsWith('- ')) return `<li>${line.slice(2)}</li>`;
                return line ? `<p>${line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')}</p>` : '';
              }).join('')}</div>
            </div>
          </div>
        `).join('')}
      </div>`;
  },

  expandKBArticle(articleId) {
    const el = document.getElementById(`kb-${articleId}`);
    if (!el) return;
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
  },

  filterKB(category) {
    document.querySelectorAll('.kb-filter').forEach(b => b.classList.remove('active'));
    if (category) {
      event.target.classList.add('active');
    } else {
      document.querySelector('.kb-filter').classList.add('active');
    }
    document.querySelectorAll('.kb-article').forEach(el => {
      el.style.display = !category || el.dataset.category === category ? '' : 'none';
    });
  },

  searchKB(term) {
    const lower = term.toLowerCase();
    document.querySelectorAll('.kb-article').forEach(el => {
      const text = el.textContent.toLowerCase();
      el.style.display = !term || text.includes(lower) ? '' : 'none';
    });
  },

  // ==================== SUPPORT TICKETS ====================
  async support() {
    let data = { data: [] };
    try { data = await API.getSupportTickets(); } catch (e) { /* empty */ }

    const isAdmin = API.user?.role === 'admin';
    const openCount = data.data.filter(t => ['open', 'in_progress', 'waiting'].includes(t.status)).length;
    const resolvedCount = data.data.filter(t => ['resolved', 'closed'].includes(t.status)).length;

    return `
      <div class="page-header">
        <div><h2>Support Center</h2><p>${isAdmin ? 'Manage all support tickets' : 'Submit and track your support requests'}</p></div>
        <button class="btn btn-primary" id="btn-add-ticket">+ New Ticket</button>
      </div>
      <div class="stats-row" style="grid-template-columns: repeat(3, 1fr)">
        <div class="stat-card info"><div class="stat-value">${data.data.length}</div><div class="stat-label">Total Tickets</div></div>
        <div class="stat-card warning"><div class="stat-value">${openCount}</div><div class="stat-label">Open</div></div>
        <div class="stat-card success"><div class="stat-value">${resolvedCount}</div><div class="stat-label">Resolved</div></div>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Subject</th>${isAdmin ? '<th>Submitted By</th>' : ''}<th>Category</th><th>Priority</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(t => `
                <tr>
                  <td><strong>${t.subject}</strong></td>
                  ${isAdmin ? `<td>${t.created_by_name || 'Unknown'}<br><span style="font-size:11px;color:var(--text-muted)">${t.created_by_email || ''}</span></td>` : ''}
                  <td>${App.badge(t.category)}</td>
                  <td>${App.badge(t.priority)}</td>
                  <td>${App.badge(t.status)}</td>
                  <td>${App.formatDate(t.created_at)}</td>
                  <td><button class="btn btn-sm btn-outline" onclick="Pages.viewTicket('${t.id}')">View</button></td>
                </tr>
              `).join('') : '<tr><td colspan="7" class="empty-state">No support tickets. Click "New Ticket" to submit a request.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  showTicketForm() {
    App.openModal('Submit Support Ticket', `
      <form id="ticket-form">
        <div class="form-group"><label>Subject *</label><input type="text" id="tk-subject" required placeholder="Brief description of your issue"></div>
        <div class="form-row">
          <div class="form-group"><label>Category</label>
            <select id="tk-category">
              <option value="general">General</option>
              <option value="technical">Technical Issue</option>
              <option value="compliance">Compliance Question</option>
              <option value="billing">Billing</option>
              <option value="feature_request">Feature Request</option>
              <option value="bug_report">Bug Report</option>
            </select>
          </div>
          <div class="form-group"><label>Priority</label>
            <select id="tk-priority">
              <option value="low">Low</option>
              <option value="medium" selected>Medium</option>
              <option value="high">High</option>
              <option value="urgent">Urgent</option>
            </select>
          </div>
        </div>
        <div class="form-group"><label>Description *</label><textarea id="tk-desc" required rows="5" placeholder="Describe your issue in detail..."></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="tk-submit">Submit Ticket</button>');
    document.getElementById('tk-submit').addEventListener('click', async () => {
      try {
        await API.createSupportTicket({
          subject: document.getElementById('tk-subject').value,
          description: document.getElementById('tk-desc').value,
          category: document.getElementById('tk-category').value,
          priority: document.getElementById('tk-priority').value,
        });
        App.closeModal();
        App.toast('Support ticket submitted', 'success');
        App.navigate('support');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async viewTicket(ticketId) {
    try {
      const { data: t } = await API.getSupportTicket(ticketId);
      const isAdmin = API.user?.role === 'admin';
      App.openModal(`Ticket: ${t.subject}`, `
        <div class="detail-grid" style="grid-template-columns: repeat(2, 1fr); margin-bottom:16px">
          <div class="detail-item"><span class="detail-label">Status</span><span>${App.badge(t.status)}</span></div>
          <div class="detail-item"><span class="detail-label">Priority</span><span>${App.badge(t.priority)}</span></div>
          <div class="detail-item"><span class="detail-label">Category</span><span>${App.badge(t.category)}</span></div>
          <div class="detail-item"><span class="detail-label">Created</span><span>${App.formatDate(t.created_at)}</span></div>
        </div>
        <div style="margin-bottom:16px">
          <strong>Description:</strong>
          <p style="margin-top:8px;white-space:pre-wrap;color:var(--text-secondary)">${t.description}</p>
        </div>
        ${t.admin_notes ? `<div style="margin-bottom:16px;padding:12px;background:var(--bg);border-radius:6px">
          <strong>Admin Response:</strong>
          <p style="margin-top:8px;white-space:pre-wrap">${t.admin_notes}</p>
        </div>` : ''}
        ${isAdmin ? `
          <div style="border-top:1px solid var(--border);padding-top:16px;margin-top:16px">
            <div class="form-row">
              <div class="form-group"><label>Update Status</label>
                <select id="tv-status">
                  <option value="open" ${t.status==='open'?'selected':''}>Open</option>
                  <option value="in_progress" ${t.status==='in_progress'?'selected':''}>In Progress</option>
                  <option value="waiting" ${t.status==='waiting'?'selected':''}>Waiting</option>
                  <option value="resolved" ${t.status==='resolved'?'selected':''}>Resolved</option>
                  <option value="closed" ${t.status==='closed'?'selected':''}>Closed</option>
                </select>
              </div>
              <div class="form-group"><label>Priority</label>
                <select id="tv-priority">
                  <option value="low" ${t.priority==='low'?'selected':''}>Low</option>
                  <option value="medium" ${t.priority==='medium'?'selected':''}>Medium</option>
                  <option value="high" ${t.priority==='high'?'selected':''}>High</option>
                  <option value="urgent" ${t.priority==='urgent'?'selected':''}>Urgent</option>
                </select>
              </div>
            </div>
            <div class="form-group"><label>Admin Notes</label><textarea id="tv-notes" rows="3">${t.admin_notes || ''}</textarea></div>
          </div>
        ` : ''}
      `, isAdmin ? '<button class="btn btn-primary" id="tv-save">Save Changes</button>' : '');
      if (isAdmin) {
        document.getElementById('tv-save').addEventListener('click', async () => {
          try {
            await API.updateSupportTicket(ticketId, {
              status: document.getElementById('tv-status').value,
              priority: document.getElementById('tv-priority').value,
              admin_notes: document.getElementById('tv-notes').value,
            });
            App.closeModal();
            App.toast('Ticket updated', 'success');
            App.navigate('support');
          } catch (err) { App.toast(err.message, 'error'); }
        });
      }
    } catch (err) { App.toast(err.message, 'error'); }
  },

  // ==================== FEATURE REQUESTS ====================
  async featureRequests() {
    let data = { data: [] };
    try { data = await API.getFeatureRequests({ sort: 'votes' }); } catch (e) { /* empty */ }

    const isAdmin = API.user?.role === 'admin';
    const categoryLabels = {
      governance: 'Governance', compliance: 'Compliance', reporting: 'Reporting',
      monitoring: 'Monitoring', integration: 'Integration', general: 'General',
    };

    return `
      <div class="page-header">
        <div><h2>Feature Requests</h2><p>Suggest and vote on platform improvements</p></div>
        <button class="btn btn-primary" id="btn-add-feature">+ Suggest Feature</button>
      </div>
      <div class="btn-group" style="margin-bottom:16px">
        <button class="btn btn-sm btn-outline fr-sort active" onclick="Pages.sortFeatureRequests('votes')">Most Voted</button>
        <button class="btn btn-sm btn-outline fr-sort" onclick="Pages.sortFeatureRequests('recent')">Most Recent</button>
      </div>
      <div id="fr-list">
        ${data.data.length > 0 ? data.data.map(fr => `
          <div class="card fr-card" style="margin-bottom:12px">
            <div style="display:flex;gap:16px;align-items:flex-start">
              <div class="vote-box ${fr.user_voted ? 'voted' : ''}" onclick="Pages.toggleVote('${fr.id}')" title="${fr.user_voted ? 'Remove vote' : 'Upvote'}">
                <span class="vote-arrow">&#9650;</span>
                <span class="vote-count" id="vc-${fr.id}">${fr.vote_count}</span>
              </div>
              <div style="flex:1">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                  <div>
                    <h3 style="margin:0 0 4px">${fr.title}</h3>
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                      <span class="badge badge-info">${categoryLabels[fr.category] || fr.category}</span>
                      ${App.badge(fr.status)}
                      <span style="font-size:11px;color:var(--text-muted)">by ${fr.created_by_name} &middot; ${App.formatDate(fr.created_at)}</span>
                    </div>
                  </div>
                  ${isAdmin ? `<button class="btn btn-sm btn-outline" onclick="Pages.manageFeatureRequest('${fr.id}')">Manage</button>` : ''}
                </div>
                <p style="margin:8px 0 0;color:var(--text-secondary);font-size:13px">${fr.description}</p>
                ${fr.admin_response ? `<div style="margin-top:8px;padding:8px 12px;background:var(--bg);border-radius:6px;font-size:13px">
                  <strong>Official Response:</strong> ${fr.admin_response}
                </div>` : ''}
              </div>
            </div>
          </div>
        `).join('') : '<div class="card"><div class="empty-state"><p>No feature requests yet. Be the first to suggest an improvement!</p></div></div>'}
      </div>`;
  },

  showFeatureForm() {
    App.openModal('Suggest a Feature', `
      <form id="feature-form">
        <div class="form-group"><label>Title *</label><input type="text" id="fr-title" required placeholder="Brief feature summary"></div>
        <div class="form-group"><label>Category</label>
          <select id="fr-category">
            <option value="general">General</option>
            <option value="governance">Governance</option>
            <option value="compliance">Compliance</option>
            <option value="reporting">Reporting</option>
            <option value="monitoring">Monitoring</option>
            <option value="integration">Integration</option>
          </select>
        </div>
        <div class="form-group"><label>Description *</label><textarea id="fr-desc" required rows="5" placeholder="Describe the feature you'd like to see, why it would be valuable, and any specific requirements..."></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="fr-submit">Submit Feature Request</button>');
    document.getElementById('fr-submit').addEventListener('click', async () => {
      try {
        await API.createFeatureRequest({
          title: document.getElementById('fr-title').value,
          description: document.getElementById('fr-desc').value,
          category: document.getElementById('fr-category').value,
        });
        App.closeModal();
        App.toast('Feature request submitted', 'success');
        App.navigate('feature-requests');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async toggleVote(featureId) {
    try {
      const result = await API.voteFeatureRequest(featureId);
      const countEl = document.getElementById(`vc-${featureId}`);
      if (countEl) countEl.textContent = result.data.vote_count;
      const box = countEl?.closest('.vote-box');
      if (box) box.classList.toggle('voted', result.voted);
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async sortFeatureRequests(sort) {
    document.querySelectorAll('.fr-sort').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    try {
      const data = await API.getFeatureRequests({ sort });
      App.navigate('feature-requests');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async manageFeatureRequest(frId) {
    try {
      const data = await API.getFeatureRequests();
      const fr = data.data.find(f => f.id === frId);
      if (!fr) return;
      App.openModal(`Manage: ${fr.title}`, `
        <div class="form-group"><label>Status</label>
          <select id="mfr-status">
            <option value="submitted" ${fr.status==='submitted'?'selected':''}>Submitted</option>
            <option value="under_review" ${fr.status==='under_review'?'selected':''}>Under Review</option>
            <option value="planned" ${fr.status==='planned'?'selected':''}>Planned</option>
            <option value="in_progress" ${fr.status==='in_progress'?'selected':''}>In Progress</option>
            <option value="completed" ${fr.status==='completed'?'selected':''}>Completed</option>
            <option value="declined" ${fr.status==='declined'?'selected':''}>Declined</option>
          </select>
        </div>
        <div class="form-group"><label>Official Response</label><textarea id="mfr-response" rows="3">${fr.admin_response || ''}</textarea></div>
      `, '<button class="btn btn-primary" id="mfr-save">Save</button>');
      document.getElementById('mfr-save').addEventListener('click', async () => {
        try {
          await API.updateFeatureRequest(frId, {
            status: document.getElementById('mfr-status').value,
            admin_response: document.getElementById('mfr-response').value,
          });
          App.closeModal();
          App.toast('Feature request updated', 'success');
          App.navigate('feature-requests');
        } catch (err) { App.toast(err.message, 'error'); }
      });
    } catch (err) { App.toast(err.message, 'error'); }
  },

  // ==================== NOTIFICATIONS ====================
  async showNotifications() {
    try {
      const data = await API.getNotifications({ limit: '30' });
      App.openModal('Notifications', `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <span style="font-size:13px;color:var(--text-muted)">${data.unread_count} unread</span>
          ${data.unread_count > 0 ? `<button class="btn btn-sm btn-outline" onclick="Pages.markAllRead()">Mark All Read</button>` : ''}
        </div>
        <div class="notif-list">
          ${data.data.length > 0 ? data.data.map(n => `
            <div class="notif-item ${n.read ? '' : 'unread'}" onclick="Pages.readNotification('${n.id}')">
              <div class="notif-icon notif-${n.type}">${n.type === 'success' ? '&#10003;' : n.type === 'warning' ? '&#9888;' : n.type === 'danger' ? '&#10007;' : '&#9432;'}</div>
              <div class="notif-content">
                <strong>${n.title}</strong>
                <p style="margin:2px 0 0;font-size:12px;color:var(--text-secondary)">${n.message}</p>
                <span style="font-size:11px;color:var(--text-muted)">${App.formatDate(n.created_at)}</span>
              </div>
            </div>
          `).join('') : '<p style="text-align:center;color:var(--text-muted);padding:20px">No notifications</p>'}
        </div>
      `, '');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async readNotification(id) {
    try {
      await API.markNotificationRead(id);
      const items = document.querySelectorAll('.notif-item');
      items.forEach(el => { if (el.getAttribute('onclick')?.includes(id)) el.classList.remove('unread'); });
      App.pollNotifications();
    } catch (e) { /* ignore */ }
  },

  async markAllRead() {
    try {
      await API.markAllNotificationsRead();
      App.closeModal();
      App.pollNotifications();
      App.toast('All notifications marked as read', 'success');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  // ==================== TRAINING ====================
  async training() {
    let modules = { data: [] };
    let progress = { data: { total_modules: 0, completed_modules: 0, completion_percentage: 0, average_score: 0, completions: [] } };
    try {
      [modules, progress] = await Promise.all([
        API.getTrainingModules(),
        API.getTrainingProgress(),
      ]);
    } catch (e) { /* empty */ }

    const p = progress.data;
    const categoryLabels = { platform: 'Platform', governance: 'Governance', compliance: 'Compliance', regulatory: 'Regulatory' };

    return `
      <div class="page-header">
        <div><h2>Training Center</h2><p>Complete training modules to build your AI governance expertise</p></div>
      </div>
      <div class="stats-row" style="grid-template-columns: repeat(4, 1fr)">
        <div class="stat-card info"><div class="stat-value">${p.total_modules}</div><div class="stat-label">Total Modules</div></div>
        <div class="stat-card success"><div class="stat-value">${p.completed_modules}</div><div class="stat-label">Completed</div></div>
        <div class="stat-card warning"><div class="stat-value">${p.completion_percentage}%</div><div class="stat-label">Progress</div></div>
        <div class="stat-card"><div class="stat-value">${p.average_score || '—'}</div><div class="stat-label">Avg Score</div></div>
      </div>
      <div class="onboarding-progress-bar" style="margin-bottom:24px">
        <div class="onboarding-track"><div class="onboarding-fill" style="width:${p.completion_percentage}%"></div></div>
        <span class="onboarding-pct">${p.completion_percentage}%</span>
      </div>
      <div class="training-modules">
        ${modules.data.map(m => `
          <div class="card training-card" style="margin-bottom:12px">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
              <div style="flex:1">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                  ${m.completed ? '<span style="color:var(--success);font-size:18px">&#10003;</span>' : '<span style="color:var(--text-muted);font-size:18px">&#9675;</span>'}
                  <h3 style="margin:0">${m.title}</h3>
                </div>
                <p style="color:var(--text-secondary);font-size:13px;margin:4px 0">${m.description}</p>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px">
                  <span class="badge badge-info">${categoryLabels[m.category] || m.category}</span>
                  <span style="font-size:11px;color:var(--text-muted)">${m.duration_minutes} min</span>
                  ${m.completed ? `<span style="font-size:11px;color:var(--success)">Completed ${App.formatDate(m.completion_data?.completed_at)}</span>` : ''}
                </div>
              </div>
              <button class="btn btn-sm ${m.completed ? 'btn-outline' : 'btn-primary'}" onclick="Pages.viewTrainingModule('${m.id}')">
                ${m.completed ? 'Review' : 'Start'}
              </button>
            </div>
          </div>
        `).join('')}
      </div>`;
  },

  async viewTrainingModule(moduleId) {
    try {
      const { data: m } = await API.getTrainingModule(moduleId);
      const contentHtml = m.content.split('\\n').map(line => {
        const formatted = line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        if (line.startsWith('- ')) return `<li>${formatted.slice(2)}</li>`;
        return formatted ? `<p>${formatted}</p>` : '';
      }).join('');

      App.openModal(m.title, `
        <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
          <span class="badge badge-info">${m.category}</span>
          <span style="font-size:12px;color:var(--text-muted)">${m.duration_minutes} minutes</span>
          ${m.completed ? '<span class="badge badge-low">Completed</span>' : ''}
        </div>
        <div class="kb-body" style="max-height:400px;overflow-y:auto;padding-right:8px">
          ${contentHtml}
        </div>
      `, m.completed ? '' :
        '<button class="btn btn-primary" id="tm-complete">Mark as Completed</button>');

      if (!m.completed) {
        document.getElementById('tm-complete')?.addEventListener('click', async () => {
          try {
            await API.completeTrainingModule(moduleId, { score: 100 });
            App.closeModal();
            App.toast('Module completed!', 'success');
            App.navigate('training');
          } catch (err) { App.toast(err.message, 'error'); }
        });
      }
    } catch (err) { App.toast(err.message, 'error'); }
  },

  // ==================== OPS DASHBOARD ====================
  async opsDashboard() {
    let metrics = { data: { totals: {}, activity_7d: [], users_by_role: [], assets_by_risk: [], active_users_30d: 0 } };
    let health = { data: { health_score: 0, health_grade: 'F', coverage: {}, alerts: [], overdue_assessments: 0, critical_incidents: 0 } };
    try {
      [metrics, health] = await Promise.all([
        API.getOpsMetrics(),
        API.getTenantHealth(),
      ]);
    } catch (e) { /* empty */ }

    const t = metrics.data.totals;
    const h = health.data;
    const gradeColors = { A: 'var(--success)', B: 'var(--accent)', C: 'var(--warning)', D: '#f97316', F: 'var(--danger)' };

    return `
      <div class="page-header">
        <div><h2>Operations Dashboard</h2><p>Platform health, usage metrics, and governance coverage</p></div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="border-left:4px solid ${gradeColors[h.health_grade] || 'var(--border)'}">
          <div class="stat-value" style="font-size:36px;color:${gradeColors[h.health_grade]}">${h.health_grade}</div>
          <div class="stat-label">Health Grade (${h.health_score}/100)</div>
        </div>
        <div class="stat-card info"><div class="stat-value">${t.users || 0}</div><div class="stat-label">Active Users</div></div>
        <div class="stat-card success"><div class="stat-value">${t.assets || 0}</div><div class="stat-label">AI Assets</div></div>
        <div class="stat-card warning"><div class="stat-value">${t.open_incidents || 0}</div><div class="stat-label">Open Incidents</div></div>
      </div>
      ${h.alerts.length > 0 ? `
      <div class="card" style="margin-bottom:16px;border-left:4px solid var(--warning)">
        <div class="card-header"><h3>Alerts</h3></div>
        ${h.alerts.map(a => `
          <div class="alert-item">
            <div class="alert-severity ${a.type}"></div>
            <div class="alert-text">${a.message}</div>
          </div>
        `).join('')}
      </div>` : ''}
      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:16px">
        <div class="card">
          <div class="card-header"><h3>Governance Coverage</h3></div>
          <div style="padding:8px 0">
            ${Object.entries(h.coverage).map(([key, val]) => `
              <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
                <span style="font-size:13px">${key.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase())}</span>
                <span style="font-size:14px;font-weight:700;color:${val ? 'var(--success)' : 'var(--danger)'}">${val ? '&#10003;' : '&#10007;'}</span>
              </div>
            `).join('')}
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h3>Platform Totals</h3></div>
          <div style="padding:8px 0">
            ${[
              ['Risk Assessments', t.risk_assessments],
              ['Impact Assessments', t.impact_assessments],
              ['Vendor Assessments', t.vendors],
              ['Evidence Records', t.evidence],
              ['Support Tickets', t.tickets],
              ['Open Tickets', t.open_tickets],
              ['Audit Log Entries', t.audit_entries],
            ].map(([label, val]) => `
              <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
                <span style="font-size:13px">${label}</span><span style="font-weight:700">${val || 0}</span>
              </div>
            `).join('')}
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h3>Users by Role</h3></div>
          ${metrics.data.users_by_role.map(r => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
              <span style="font-size:13px">${App.badge(r.role)}</span><span style="font-weight:700">${r.count}</span>
            </div>
          `).join('')}
        </div>
        <div class="card">
          <div class="card-header"><h3>Assets by Risk Tier</h3></div>
          ${metrics.data.assets_by_risk.map(r => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
              <span>${App.badge(r.risk_tier)}</span><span style="font-weight:700">${r.count}</span>
            </div>
          `).join('')}
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><h3>Audit-Ready Reports</h3></div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px">
          <div class="export-card card" style="text-align:center;padding:16px;cursor:pointer" onclick="Pages.openAuditReport('all')">
            <div style="font-size:28px">&#9744;</div><strong>Full Compliance Pack</strong>
            <p style="font-size:12px;color:var(--text-secondary)">All frameworks</p>
          </div>
          <div class="export-card card" style="text-align:center;padding:16px;cursor:pointer" onclick="Pages.openAuditReport('nist')">
            <div style="font-size:28px">&#9878;</div><strong>NIST AI RMF Pack</strong>
            <p style="font-size:12px;color:var(--text-secondary)">NIST controls only</p>
          </div>
          <div class="export-card card" style="text-align:center;padding:16px;cursor:pointer" onclick="Pages.openAuditReport('hipaa')">
            <div style="font-size:28px">&#9829;</div><strong>HIPAA Pack</strong>
            <p style="font-size:12px;color:var(--text-secondary)">HIPAA controls only</p>
          </div>
        </div>
      </div>`;
  },

  openAuditReport(framework) {
    const url = framework === 'all'
      ? '/api/v1/reports/audit-pack'
      : `/api/v1/reports/audit-pack?framework=${framework}`;
    const win = window.open('', '_blank');
    fetch(url, { headers: { 'Authorization': `Bearer ${API.accessToken}` } })
      .then(r => r.text())
      .then(html => { win.document.write(html); win.document.close(); })
      .catch(() => { win.close(); App.toast('Failed to generate report', 'error'); });
  },

  openAssetProfile(assetId) {
    const url = `/api/v1/reports/asset-profile/${assetId}`;
    const win = window.open('', '_blank');
    fetch(url, { headers: { 'Authorization': `Bearer ${API.accessToken}` } })
      .then(r => r.text())
      .then(html => { win.document.write(html); win.document.close(); })
      .catch(() => { win.close(); App.toast('Failed to generate report', 'error'); });
  },

  // ==================== CONTEXTUAL HELP ====================
  showHelp(topic) {
    const helpContent = {
      risk_scores: '<h4>Risk Scoring Guide</h4><p>Rate each dimension from 1 (low risk) to 5 (critical risk):</p><ul><li><strong>Patient Safety (25%)</strong> - Could incorrect output harm patients? Score 5 if errors could cause mortality.</li><li><strong>Bias/Fairness (20%)</strong> - Does the system perform equitably across demographic groups?</li><li><strong>Data Privacy (15%)</strong> - How much PHI is accessed? What are de-identification measures?</li><li><strong>Clinical Validity (15%)</strong> - Is there peer-reviewed evidence supporting the AI\'s claims?</li><li><strong>Cybersecurity (15%)</strong> - What is the attack surface? Model poisoning risk?</li><li><strong>Regulatory (10%)</strong> - Are there compliance gaps with FDA, HIPAA, state laws?</li></ul>',
      asset_categories: '<h4>AI Asset Categories</h4><ul><li><strong>Clinical Decision Support</strong> - Tools that assist clinicians in making care decisions</li><li><strong>Diagnostic Imaging</strong> - AI-powered radiology, pathology, or other imaging analysis</li><li><strong>Predictive Analytics</strong> - Patient risk prediction, readmission models, sepsis alerts</li><li><strong>NLP Extraction</strong> - Natural language processing for clinical notes, coding</li><li><strong>Operational</strong> - Scheduling, resource optimization, supply chain</li><li><strong>Administrative</strong> - Prior auth, claims processing, documentation</li><li><strong>Revenue Cycle</strong> - Coding optimization, denial prevention, payment prediction</li></ul>',
      risk_tiers: '<h4>Risk Tier Definitions</h4><ul><li><strong>Critical</strong> - Direct life-safety impact. Requires Board-level oversight, continuous monitoring, and annual third-party audit.</li><li><strong>High</strong> - Significant clinical or privacy impact. Requires executive sponsor, quarterly reviews, and bias testing.</li><li><strong>Moderate</strong> - Indirect clinical impact or operational significance. Requires designated owner and semi-annual review.</li><li><strong>Low</strong> - Administrative or minimal clinical impact. Standard documentation and annual review.</li></ul>',
      vendor_scoring: '<h4>Vendor Scoring Methodology</h4><p>Each dimension is rated 1-5 and weighted:</p><ul><li>Transparency: 15%</li><li>Bias Testing: 25%</li><li>Security: 25%</li><li>Data Practices: 20%</li><li>Contractual: 15%</li></ul><p>Overall score (0-100): Below 40 = Rejected, 40-60 = Conditional, Above 60 = Approved</p>',
    };
    const content = helpContent[topic] || '<p>No help available for this topic.</p>';
    App.openModal('Help', `<div class="kb-body">${content}</div>`, '');
  },

  // ==================== PAGE EVENT BINDINGS ====================
  bindPageEvents(page) {
    switch (page) {
      case 'ai-assets':
        document.getElementById('btn-add-asset')?.addEventListener('click', () => this.showAssetForm());
        break;
      case 'risk-assessments':
        document.getElementById('btn-add-risk')?.addEventListener('click', () => this.showRiskForm());
        break;
      case 'vendors':
        document.getElementById('btn-add-vendor')?.addEventListener('click', () => this.showVendorForm());
        break;
      case 'maturity':
        document.getElementById('btn-add-maturity')?.addEventListener('click', () => this.showMaturityForm());
        break;
      case 'incidents':
        document.getElementById('btn-add-incident')?.addEventListener('click', () => this.showIncidentForm());
        break;
      case 'impact-assessments':
        document.getElementById('btn-add-aia')?.addEventListener('click', () => this.showImpactForm());
        break;
      case 'users':
        document.getElementById('btn-add-user')?.addEventListener('click', () => this.showUserForm());
        break;
      case 'support':
        document.getElementById('btn-add-ticket')?.addEventListener('click', () => this.showTicketForm());
        break;
      case 'feature-requests':
        document.getElementById('btn-add-feature')?.addEventListener('click', () => this.showFeatureForm());
        break;
    }
  },

  // ==================== FORM MODALS ====================
  showAssetForm() {
    App.openModal('Register AI Asset', `
      <form id="asset-form">
        <div class="form-group"><label>System Name *</label><input type="text" id="af-name" required></div>
        <div class="form-row">
          <div class="form-group"><label>Vendor</label><input type="text" id="af-vendor" placeholder="Leave blank for internal"></div>
          <div class="form-group"><label>Version</label><input type="text" id="af-version"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Category * <button type="button" class="help-btn-inline" onclick="Pages.showHelp('asset_categories')" title="Category guide">?</button></label>
            <select id="af-category">
              <option value="clinical_decision_support">Clinical Decision Support</option>
              <option value="diagnostic_imaging">Diagnostic Imaging</option>
              <option value="predictive_analytics">Predictive Analytics</option>
              <option value="nlp_extraction">NLP Extraction</option>
              <option value="operational">Operational</option>
              <option value="administrative">Administrative</option>
              <option value="revenue_cycle">Revenue Cycle</option>
              <option value="other">Other</option>
            </select>
          </div>
          <div class="form-group"><label>Risk Tier <button type="button" class="help-btn-inline" onclick="Pages.showHelp('risk_tiers')" title="Risk tier guide">?</button></label>
            <select id="af-risk"><option value="low">Low</option><option value="moderate" selected>Moderate</option><option value="high">High</option><option value="critical">Critical</option></select>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>FDA Classification</label><input type="text" id="af-fda" placeholder="e.g., 510(k), None"></div>
          <div class="form-group"><label>Department</label><input type="text" id="af-dept"></div>
        </div>
        <div class="form-group"><label>PHI Access</label>
          <select id="af-phi"><option value="0">No</option><option value="1">Yes</option></select>
        </div>
        <div class="form-group"><label>Description</label><textarea id="af-desc"></textarea></div>
        <div class="form-group"><label>Intended Use</label><textarea id="af-use"></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="af-submit">Register Asset</button>');
    document.getElementById('af-submit').addEventListener('click', async () => {
      try {
        await API.createAsset({
          name: document.getElementById('af-name').value,
          vendor: document.getElementById('af-vendor').value || null,
          version: document.getElementById('af-version').value || null,
          category: document.getElementById('af-category').value,
          risk_tier: document.getElementById('af-risk').value,
          fda_classification: document.getElementById('af-fda').value || null,
          department: document.getElementById('af-dept').value || null,
          phi_access: document.getElementById('af-phi').value === '1',
          description: document.getElementById('af-desc').value || null,
          intended_use: document.getElementById('af-use').value || null,
        });
        App.closeModal();
        App.toast('AI asset registered successfully', 'success');
        App.navigate('ai-assets');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  showRiskForm() {
    App.openModal('New Risk Assessment', `
      <form id="risk-form">
        <div class="form-group"><label>AI Asset ID *</label><input type="text" id="rf-asset" required placeholder="Asset UUID"></div>
        <div class="form-group"><label>Assessment Type *</label>
          <select id="rf-type"><option value="initial">Initial</option><option value="periodic">Periodic</option><option value="triggered">Triggered</option><option value="pre_deployment">Pre-Deployment</option></select>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <strong>Risk Dimensions</strong>
          <button type="button" class="btn btn-sm btn-outline help-btn" onclick="Pages.showHelp('risk_scores')" title="Scoring guide">? Help</button>
        </div>
        <div class="score-grid">
          <div class="score-item"><label>Patient Safety (1-5) <span class="tooltip-icon" title="Weight: 25%. Score 5 if errors could cause mortality.">&#9432;</span></label><input type="number" id="rf-safety" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Bias/Fairness (1-5) <span class="tooltip-icon" title="Weight: 20%. Risk of disparate impact across demographic groups.">&#9432;</span></label><input type="number" id="rf-bias" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Data Privacy (1-5) <span class="tooltip-icon" title="Weight: 15%. PHI exposure risk and de-identification effectiveness.">&#9432;</span></label><input type="number" id="rf-privacy" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Clinical Validity (1-5) <span class="tooltip-icon" title="Weight: 15%. Scientific evidence supporting the AI's claims.">&#9432;</span></label><input type="number" id="rf-clinical" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Cybersecurity (1-5) <span class="tooltip-icon" title="Weight: 15%. Attack surface, model poisoning risk, API security.">&#9432;</span></label><input type="number" id="rf-cyber" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Regulatory (1-5) <span class="tooltip-icon" title="Weight: 10%. Compliance gaps with FDA, HIPAA, state laws.">&#9432;</span></label><input type="number" id="rf-reg" min="1" max="5" value="3"></div>
        </div>
        <div class="form-group" style="margin-top:12px"><label>Recommendations</label><textarea id="rf-recs"></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="rf-submit">Create Assessment</button>');
    document.getElementById('rf-submit').addEventListener('click', async () => {
      try {
        await API.createRiskAssessment({
          ai_asset_id: document.getElementById('rf-asset').value,
          assessment_type: document.getElementById('rf-type').value,
          patient_safety_score: parseInt(document.getElementById('rf-safety').value),
          bias_fairness_score: parseInt(document.getElementById('rf-bias').value),
          data_privacy_score: parseInt(document.getElementById('rf-privacy').value),
          clinical_validity_score: parseInt(document.getElementById('rf-clinical').value),
          cybersecurity_score: parseInt(document.getElementById('rf-cyber').value),
          regulatory_score: parseInt(document.getElementById('rf-reg').value),
          recommendations: document.getElementById('rf-recs').value || null,
        });
        App.closeModal();
        App.toast('Risk assessment created', 'success');
        App.navigate('risk-assessments');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  showVendorForm() {
    App.openModal('New Vendor Assessment', `
      <form id="vendor-form">
        <div class="form-row">
          <div class="form-group"><label>Vendor Name *</label><input type="text" id="vf-vendor" required></div>
          <div class="form-group"><label>Product Name *</label><input type="text" id="vf-product" required></div>
        </div>
        <div class="form-group"><label>Training Data Provenance</label><textarea id="vf-provenance"></textarea></div>
        <div class="form-group"><label>Validation Methodology</label><textarea id="vf-validation"></textarea></div>
        <div class="score-grid" style="margin-top:12px">
          <div class="score-item"><label>Transparency (1-5)</label><input type="number" id="vf-transparency" min="1" max="5"></div>
          <div class="score-item"><label>Bias Testing (1-5)</label><input type="number" id="vf-bias" min="1" max="5"></div>
          <div class="score-item"><label>Security (1-5)</label><input type="number" id="vf-security" min="1" max="5"></div>
          <div class="score-item"><label>Data Practices (1-5)</label><input type="number" id="vf-data" min="1" max="5"></div>
          <div class="score-item"><label>Contractual (1-5)</label><input type="number" id="vf-contractual" min="1" max="5"></div>
        </div>
      </form>
    `, '<button class="btn btn-primary" id="vf-submit">Create Assessment</button>');
    document.getElementById('vf-submit').addEventListener('click', async () => {
      try {
        await API.createVendorAssessment({
          vendor_name: document.getElementById('vf-vendor').value,
          product_name: document.getElementById('vf-product').value,
          training_data_provenance: document.getElementById('vf-provenance').value || null,
          validation_methodology: document.getElementById('vf-validation').value || null,
          transparency_score: parseInt(document.getElementById('vf-transparency').value) || null,
          bias_testing_score: parseInt(document.getElementById('vf-bias').value) || null,
          security_score: parseInt(document.getElementById('vf-security').value) || null,
          data_practices_score: parseInt(document.getElementById('vf-data').value) || null,
          contractual_score: parseInt(document.getElementById('vf-contractual').value) || null,
        });
        App.closeModal();
        App.toast('Vendor assessment created', 'success');
        App.navigate('vendors');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  showMaturityForm() {
    App.openModal('New Maturity Assessment', `
      <form id="maturity-form">
        <p style="margin-bottom:16px;color:var(--text-secondary)">Rate each domain on a scale of 1-5 (Initial to Optimized)</p>
        <div class="score-grid">
          <div class="score-item"><label>Governance Structure</label><input type="number" id="mf-gov" min="1" max="5" value="1"></div>
          <div class="score-item"><label>AI Inventory</label><input type="number" id="mf-inv" min="1" max="5" value="1"></div>
          <div class="score-item"><label>Risk Assessment</label><input type="number" id="mf-risk" min="1" max="5" value="1"></div>
          <div class="score-item"><label>Policy & Compliance</label><input type="number" id="mf-policy" min="1" max="5" value="1"></div>
          <div class="score-item"><label>Monitoring</label><input type="number" id="mf-mon" min="1" max="5" value="1"></div>
          <div class="score-item"><label>Vendor Management</label><input type="number" id="mf-vendor" min="1" max="5" value="1"></div>
          <div class="score-item"><label>Transparency</label><input type="number" id="mf-trans" min="1" max="5" value="1"></div>
        </div>
      </form>
    `, '<button class="btn btn-primary" id="mf-submit">Create Assessment</button>');
    document.getElementById('mf-submit').addEventListener('click', async () => {
      try {
        await API.createMaturityAssessment({
          governance_structure_score: parseInt(document.getElementById('mf-gov').value),
          ai_inventory_score: parseInt(document.getElementById('mf-inv').value),
          risk_assessment_score: parseInt(document.getElementById('mf-risk').value),
          policy_compliance_score: parseInt(document.getElementById('mf-policy').value),
          monitoring_performance_score: parseInt(document.getElementById('mf-mon').value),
          vendor_management_score: parseInt(document.getElementById('mf-vendor').value),
          transparency_score: parseInt(document.getElementById('mf-trans').value),
        });
        App.closeModal();
        App.toast('Maturity assessment created', 'success');
        App.navigate('maturity');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  showIncidentForm() {
    App.openModal('Report AI Incident', `
      <form id="incident-form">
        <div class="form-group"><label>AI Asset ID *</label><input type="text" id="if-asset" required placeholder="Asset UUID"></div>
        <div class="form-group"><label>Title *</label><input type="text" id="if-title" required></div>
        <div class="form-row">
          <div class="form-group"><label>Incident Type *</label>
            <select id="if-type">
              <option value="patient_safety">Patient Safety</option>
              <option value="bias_detected">Bias Detected</option>
              <option value="performance_degradation">Performance Degradation</option>
              <option value="data_breach">Data Breach</option>
              <option value="model_failure">Model Failure</option>
              <option value="regulatory_violation">Regulatory Violation</option>
              <option value="other">Other</option>
            </select>
          </div>
          <div class="form-group"><label>Severity *</label>
            <select id="if-severity"><option value="low">Low</option><option value="moderate">Moderate</option><option value="high">High</option><option value="critical">Critical</option></select>
          </div>
        </div>
        <div class="form-group"><label>Patient Impact</label>
          <select id="if-patient"><option value="0">No</option><option value="1">Yes</option></select>
        </div>
        <div class="form-group"><label>Description *</label><textarea id="if-desc" required></textarea></div>
      </form>
    `, '<button class="btn btn-danger" id="if-submit">Report Incident</button>');
    document.getElementById('if-submit').addEventListener('click', async () => {
      try {
        await API.createIncident({
          ai_asset_id: document.getElementById('if-asset').value,
          title: document.getElementById('if-title').value,
          incident_type: document.getElementById('if-type').value,
          severity: document.getElementById('if-severity').value,
          patient_impact: document.getElementById('if-patient').value === '1',
          description: document.getElementById('if-desc').value,
        });
        App.closeModal();
        App.toast('Incident reported', 'success');
        App.navigate('incidents');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  showImpactForm() {
    App.openModal('New Algorithmic Impact Assessment', `
      <form id="aia-form">
        <div class="form-group"><label>AI Asset ID *</label><input type="text" id="ia-asset" required placeholder="Asset UUID"></div>
        <div class="form-group"><label>Assessment Period</label><input type="text" id="ia-period" placeholder="e.g., Q1 2025"></div>
        <div class="form-group"><label>Demographic Groups Tested</label>
          <textarea id="ia-groups" placeholder="e.g., race, ethnicity, gender, age, socioeconomic status"></textarea>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Drift Detected</label>
            <select id="ia-drift"><option value="0">No</option><option value="1">Yes</option></select>
          </div>
          <div class="form-group"><label>Remediation Required</label>
            <select id="ia-remed"><option value="0">No</option><option value="1">Yes</option></select>
          </div>
        </div>
      </form>
    `, '<button class="btn btn-primary" id="ia-submit">Create Assessment</button>');
    document.getElementById('ia-submit').addEventListener('click', async () => {
      try {
        const groups = document.getElementById('ia-groups').value;
        await API.createImpactAssessment({
          ai_asset_id: document.getElementById('ia-asset').value,
          assessment_period: document.getElementById('ia-period').value || null,
          demographic_groups_tested: groups ? groups.split(',').map(g => g.trim()) : [],
          drift_detected: document.getElementById('ia-drift').value === '1',
          remediation_required: document.getElementById('ia-remed').value === '1',
        });
        App.closeModal();
        App.toast('Impact assessment created', 'success');
        App.navigate('impact-assessments');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  // ==================== USER MANAGEMENT ====================
  async users() {
    let data = { data: [] };
    try { data = await API.getUsers(); } catch (e) { /* empty */ }

    const roleLabels = { admin: 'Admin', governance_lead: 'Governance Lead', reviewer: 'Reviewer', viewer: 'Viewer' };

    return `
      <div class="page-header">
        <div><h2>User Management</h2><p>Manage team members, roles, and access for ${API.tenant?.name || 'your organization'}</p></div>
        <button class="btn btn-primary" id="btn-add-user">+ Add User</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(u => `
                <tr>
                  <td><strong>${u.first_name} ${u.last_name}</strong></td>
                  <td>${u.email}</td>
                  <td>${App.badge(u.role === 'governance_lead' ? 'info' : u.role === 'admin' ? 'critical' : u.role === 'reviewer' ? 'moderate' : 'low')}
                      <span style="margin-left:4px">${roleLabels[u.role] || u.role}</span></td>
                  <td>${App.badge(u.status === 'active' ? 'approved' : u.status === 'locked' ? 'critical' : 'draft')}</td>
                  <td>${u.last_login ? App.formatDate(u.last_login) : 'Never'}</td>
                  <td>
                    <div class="btn-group">
                      <button class="btn btn-sm btn-outline" onclick="Pages.showEditUserForm('${u.id}')">Edit</button>
                      ${u.status === 'locked' ? `<button class="btn btn-sm btn-warning" onclick="Pages.unlockUser('${u.id}')">Unlock</button>` : ''}
                      ${u.id !== API.user?.id ? `<button class="btn btn-sm btn-outline" onclick="Pages.showResetPasswordForm('${u.id}')">Reset PW</button>` : ''}
                    </div>
                  </td>
                </tr>
              `).join('') : '<tr><td colspan="6" class="empty-state">No users found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  showUserForm() {
    App.openModal('Add New User', `
      <form id="user-form">
        <div class="form-row">
          <div class="form-group"><label>First Name *</label><input type="text" id="uf-first" required></div>
          <div class="form-group"><label>Last Name *</label><input type="text" id="uf-last" required></div>
        </div>
        <div class="form-group"><label>Email *</label><input type="email" id="uf-email" required></div>
        <div class="form-group"><label>Password *</label><input type="password" id="uf-password" required minlength="12" placeholder="Min 12 characters"></div>
        <div class="form-group"><label>Role *</label>
          <select id="uf-role">
            <option value="viewer">Viewer - Read-only access</option>
            <option value="reviewer">Reviewer - Can create assessments</option>
            <option value="governance_lead">Governance Lead - Can approve/reject</option>
            <option value="admin">Admin - Full access</option>
          </select>
        </div>
      </form>
    `, '<button class="btn btn-primary" id="uf-submit">Create User</button>');
    document.getElementById('uf-submit').addEventListener('click', async () => {
      try {
        await API.createUser({
          first_name: document.getElementById('uf-first').value,
          last_name: document.getElementById('uf-last').value,
          email: document.getElementById('uf-email').value,
          password: document.getElementById('uf-password').value,
          role: document.getElementById('uf-role').value,
        });
        App.closeModal();
        App.toast('User created successfully', 'success');
        App.navigate('users');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async showEditUserForm(userId) {
    try {
      const { data: u } = await API.getUser(userId);
      App.openModal(`Edit User: ${u.first_name} ${u.last_name}`, `
        <form id="edit-user-form">
          <div class="form-row">
            <div class="form-group"><label>First Name</label><input type="text" id="eu-first" value="${u.first_name}"></div>
            <div class="form-group"><label>Last Name</label><input type="text" id="eu-last" value="${u.last_name}"></div>
          </div>
          <div class="form-group"><label>Email</label><input type="email" id="eu-email" value="${u.email}" disabled></div>
          <div class="form-group"><label>Role</label>
            <select id="eu-role">
              <option value="viewer" ${u.role==='viewer'?'selected':''}>Viewer</option>
              <option value="reviewer" ${u.role==='reviewer'?'selected':''}>Reviewer</option>
              <option value="governance_lead" ${u.role==='governance_lead'?'selected':''}>Governance Lead</option>
              <option value="admin" ${u.role==='admin'?'selected':''}>Admin</option>
            </select>
          </div>
          <div class="form-group"><label>Status</label>
            <select id="eu-status">
              <option value="active" ${u.status==='active'?'selected':''}>Active</option>
              <option value="deactivated" ${u.status==='deactivated'?'selected':''}>Deactivated</option>
            </select>
          </div>
        </form>
      `, `<button class="btn btn-primary" id="eu-submit">Save Changes</button>
          ${u.id !== API.user?.id ? `<button class="btn btn-danger" id="eu-deactivate">Deactivate</button>` : ''}`);
      document.getElementById('eu-submit').addEventListener('click', async () => {
        try {
          await API.updateUser(userId, {
            first_name: document.getElementById('eu-first').value,
            last_name: document.getElementById('eu-last').value,
            role: document.getElementById('eu-role').value,
            status: document.getElementById('eu-status').value,
          });
          App.closeModal();
          App.toast('User updated', 'success');
          App.navigate('users');
        } catch (err) { App.toast(err.message, 'error'); }
      });
      document.getElementById('eu-deactivate')?.addEventListener('click', async () => {
        if (confirm('Deactivate this user? They will no longer be able to sign in.')) {
          try {
            await API.deactivateUser(userId);
            App.closeModal();
            App.toast('User deactivated', 'success');
            App.navigate('users');
          } catch (err) { App.toast(err.message, 'error'); }
        }
      });
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async unlockUser(userId) {
    try {
      await API.unlockUser(userId);
      App.toast('User account unlocked', 'success');
      App.navigate('users');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  showResetPasswordForm(userId) {
    App.openModal('Reset User Password', `
      <form id="reset-pw-form">
        <div class="form-group"><label>New Password *</label><input type="password" id="rp-password" required minlength="12" placeholder="Min 12 characters"></div>
        <div class="form-group"><label>Confirm Password *</label><input type="password" id="rp-confirm" required minlength="12"></div>
      </form>
    `, '<button class="btn btn-primary" id="rp-submit">Reset Password</button>');
    document.getElementById('rp-submit').addEventListener('click', async () => {
      const pw = document.getElementById('rp-password').value;
      const confirm = document.getElementById('rp-confirm').value;
      if (pw !== confirm) { App.toast('Passwords do not match', 'error'); return; }
      try {
        await API.resetUserPassword(userId, { new_password: pw });
        App.closeModal();
        App.toast('Password reset successfully', 'success');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  // ==================== AUDIT LOG ====================
  async auditLog() {
    let data = { data: [] };
    try { data = await API.getAuditLog({ limit: 200 }); } catch (e) { /* empty */ }

    const actionIcons = {
      create: '+', update: '~', approve: '\u2713', reject: '\u2717',
      delete: '\u2715', decommission: '\u2715', login: '\u2192', register: '\u2605',
      deactivate: '\u2715', unlock: '\u2192', reset_password: '\u21BB',
    };

    return `
      <div class="page-header">
        <div><h2>Audit Log</h2><p>Immutable record of all governance activities</p></div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('')">All</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('ai_asset')">Assets</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('risk_assessment')">Risk</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('user')">Users</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('incident')">Incidents</button>
        </div>
      </div>
      <div class="card">
        <div class="table-container">
          <table id="audit-table">
            <thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Entity Type</th><th>Entity ID</th><th>Details</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(a => `
                <tr data-entity-type="${a.entity_type}">
                  <td style="white-space:nowrap">${App.formatDate(a.created_at)}</td>
                  <td>${a.user_name || 'System'}<br><span style="font-size:11px;color:var(--text-muted)">${a.user_email || ''}</span></td>
                  <td><span style="font-weight:700;margin-right:4px">${actionIcons[a.action] || '?'}</span> ${a.action}</td>
                  <td>${(a.entity_type || '').replace(/_/g, ' ')}</td>
                  <td style="font-family:monospace;font-size:11px">${a.entity_id ? a.entity_id.slice(0, 8) + '...' : '-'}</td>
                  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.details && a.details !== '{}' ? a.details : '-'}</td>
                </tr>
              `).join('') : '<tr><td colspan="6" class="empty-state">No audit records found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  async filterAuditLog(entityType) {
    try {
      const params = entityType ? { entity_type: entityType, limit: 200 } : { limit: 200 };
      const data = await API.getAuditLog(params);
      const rows = document.querySelectorAll('#audit-table tbody tr');
      if (entityType) {
        rows.forEach(row => {
          row.style.display = row.dataset.entityType === entityType ? '' : 'none';
        });
      } else {
        rows.forEach(row => { row.style.display = ''; });
      }
    } catch (err) { App.toast(err.message, 'error'); }
  },

  // ==================== REPORTS & EXPORT ====================
  async reports() {
    let compReport = { report: { summary_by_family: {}, controls: [] } };
    let execReport = { report: {} };
    try {
      [compReport, execReport] = await Promise.all([
        API.getComplianceReport(),
        API.getExecutiveReport(),
      ]);
    } catch (e) { /* use defaults */ }

    const families = Object.entries(compReport.report.summary_by_family || {});

    return `
      <div class="page-header">
        <div><h2>Reports & Exports</h2><p>Generate compliance reports and export governance data</p></div>
      </div>

      <div class="card-grid grid-3" style="margin-bottom:24px">
        <div class="card export-card">
          <div class="card-header"><h3>AI Asset Registry</h3></div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px">Export all registered AI systems with risk tiers, status, and ownership.</p>
          <button class="btn btn-primary" onclick="Pages.downloadExport('assets', 'ai-assets.csv')">Export CSV</button>
        </div>
        <div class="card export-card">
          <div class="card-header"><h3>Risk Assessments</h3></div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px">Export all risk assessments with 6-dimension scores and risk levels.</p>
          <button class="btn btn-primary" onclick="Pages.downloadExport('risk-assessments', 'risk-assessments.csv')">Export CSV</button>
        </div>
        <div class="card export-card">
          <div class="card-header"><h3>Compliance Status</h3></div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px">Export compliance control implementations with framework mappings.</p>
          <button class="btn btn-primary" onclick="Pages.downloadExport('compliance', 'compliance-status.csv')">Export CSV</button>
        </div>
        <div class="card export-card">
          <div class="card-header"><h3>Vendor Assessments</h3></div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px">Export vendor due diligence assessments and scores.</p>
          <button class="btn btn-primary" onclick="Pages.downloadExport('vendor-assessments', 'vendor-assessments.csv')">Export CSV</button>
        </div>
        <div class="card export-card">
          <div class="card-header"><h3>Incidents</h3></div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px">Export all AI incidents with severity, status, and resolution data.</p>
          <button class="btn btn-primary" onclick="Pages.downloadExport('incidents', 'incidents.csv')">Export CSV</button>
        </div>
        <div class="card export-card">
          <div class="card-header"><h3>Evidence Records</h3></div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px">Export all evidence documentation linked to governance activities.</p>
          <button class="btn btn-primary" onclick="Pages.downloadExport('evidence', 'evidence.csv')">Export CSV</button>
        </div>
      </div>

      <div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <h3>Compliance Summary Report</h3>
          <button class="btn btn-sm btn-outline" onclick="Pages.printReport()">Print / Save as PDF</button>
        </div>
        <div id="printable-report">
          <p style="color:var(--text-secondary);margin-bottom:16px">Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
          <table>
            <thead><tr><th>Family</th><th>Total Controls</th><th>Implemented</th><th>Partial</th><th>Planned</th><th>Gap</th></tr></thead>
            <tbody>
              ${families.length > 0 ? families.map(([family, s]) => `<tr>
                <td><strong>${family}</strong></td><td>${s.total}</td>
                <td><span class="badge badge-approved">${s.implemented}</span></td>
                <td><span class="badge badge-moderate">${s.partial}</span></td>
                <td><span class="badge badge-info">${s.planned}</span></td>
                <td><span class="badge badge-draft">${s.gap}</span></td>
              </tr>`).join('') : '<tr><td colspan="6" class="empty-state">No compliance data available</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h3>Executive Summary</h3></div>
        ${execReport.report.maturity_assessment ? `
          <div style="margin-bottom:16px">
            <strong>Overall Maturity Score:</strong> ${execReport.report.maturity_assessment.overall_maturity_score?.toFixed(1) || 'N/A'}/5.0
          </div>
        ` : '<p style="color:var(--text-secondary)">No maturity assessment available.</p>'}
        ${(execReport.report.recent_assessments || []).length > 0 ? `
          <h4 style="margin-top:16px;margin-bottom:8px">Recent Risk Assessments</h4>
          <table>
            <thead><tr><th>AI System</th><th>Risk Level</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
              ${execReport.report.recent_assessments.map(r => `<tr>
                <td>${r.asset_name}</td><td>${App.badge(r.overall_risk_level)}</td>
                <td>${App.badge(r.status)}</td><td>${App.formatDate(r.created_at)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        ` : ''}
        ${(execReport.report.open_incidents || []).length > 0 ? `
          <h4 style="margin-top:16px;margin-bottom:8px">Open Incidents</h4>
          <table>
            <thead><tr><th>Title</th><th>AI System</th><th>Severity</th><th>Status</th></tr></thead>
            <tbody>
              ${execReport.report.open_incidents.map(i => `<tr>
                <td>${i.title}</td><td>${i.asset_name}</td>
                <td>${App.badge(i.severity)}</td><td>${App.badge(i.status)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        ` : ''}
      </div>
    `;
  },

  async downloadExport(type, filename) {
    try {
      const response = await fetch(`/api/v1/export/${type}`, {
        headers: { 'Authorization': `Bearer ${API.accessToken}` },
      });
      if (!response.ok) throw new Error('Export failed');
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      a.click(); URL.revokeObjectURL(url);
      App.toast('Export downloaded', 'success');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  printReport() {
    const content = document.getElementById('printable-report');
    if (!content) return;
    const win = window.open('', '_blank');
    win.document.write(`
      <html><head><title>Compliance Report - ForgeAI Govern</title>
      <style>
        body { font-family: -apple-system, sans-serif; padding: 40px; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px; }
        th, td { padding: 8px 12px; text-align: left; border: 1px solid #ddd; }
        th { background: #f5f5f5; font-weight: 600; }
        h1 { font-size: 20px; margin-bottom: 4px; }
        .badge { padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 600; }
      </style>
      </head><body>
        <h1>ForgeAI Govern&trade; - AI Governance Compliance Report</h1>
        <p>Organization: ${API.tenant?.name || ''}</p>
        ${content.innerHTML}
      </body></html>
    `);
    win.document.close();
    win.print();
  },

  // ==================== EXPORT HELPERS ====================
  exportTableToCSV(tableId, filename) {
    const table = document.getElementById(tableId) || document.querySelector('table');
    if (!table) return;
    const rows = [];
    table.querySelectorAll('tr').forEach(tr => {
      const cells = [];
      tr.querySelectorAll('th, td').forEach(td => {
        cells.push('"' + td.textContent.replace(/"/g, '""').trim() + '"');
      });
      rows.push(cells.join(','));
    });
    const csv = rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename || 'export.csv';
    a.click(); URL.revokeObjectURL(url);
  },
};
