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
    try { stats = await API.getDashboardStats(); } catch (e) { /* use defaults */ }
    const d = stats.data;
    const total = d.ai_portfolio.total_assets;
    const risk = d.ai_portfolio.risk_distribution;
    const comp = d.compliance;

    return `
      <div class="page-header">
        <div><h2>AI Governance Dashboard</h2><p>Portfolio overview and compliance status for ${API.tenant?.name || 'your organization'}</p></div>
      </div>
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
          <div class="form-group"><label>Category *</label>
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
          <div class="form-group"><label>Risk Tier</label>
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
        <div class="score-grid">
          <div class="score-item"><label>Patient Safety (1-5)</label><input type="number" id="rf-safety" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Bias/Fairness (1-5)</label><input type="number" id="rf-bias" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Data Privacy (1-5)</label><input type="number" id="rf-privacy" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Clinical Validity (1-5)</label><input type="number" id="rf-clinical" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Cybersecurity (1-5)</label><input type="number" id="rf-cyber" min="1" max="5" value="3"></div>
          <div class="score-item"><label>Regulatory (1-5)</label><input type="number" id="rf-reg" min="1" max="5" value="3"></div>
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
