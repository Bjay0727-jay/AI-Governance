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
  async viewAsset(id) {
    try {
      const { data } = await API.getAsset(id);
      App.openModal(`AI Asset: ${data.name}`, `
        <div class="form-row" style="margin-bottom:12px">
          <div><strong>Vendor:</strong> ${data.vendor || 'Internal'}</div>
          <div><strong>Version:</strong> ${data.version || 'N/A'}</div>
        </div>
        <div class="form-row" style="margin-bottom:12px">
          <div><strong>Category:</strong> ${data.category.replace(/_/g, ' ')}</div>
          <div><strong>Risk Tier:</strong> ${App.badge(data.risk_tier)}</div>
        </div>
        <div class="form-row" style="margin-bottom:12px">
          <div><strong>Status:</strong> ${App.badge(data.deployment_status)}</div>
          <div><strong>PHI Access:</strong> ${data.phi_access ? 'Yes' : 'No'}</div>
        </div>
        <div class="form-row" style="margin-bottom:12px">
          <div><strong>FDA Classification:</strong> ${data.fda_classification || 'N/A'}</div>
          <div><strong>Department:</strong> ${data.department || 'N/A'}</div>
        </div>
        <div style="margin-bottom:12px"><strong>Description:</strong><br>${data.description || 'No description'}</div>
        <div style="margin-bottom:12px"><strong>Intended Use:</strong><br>${data.intended_use || 'Not specified'}</div>
        <div><strong>Known Limitations:</strong><br>${data.known_limitations || 'Not documented'}</div>
        <hr style="margin:16px 0">
        <div class="form-row">
          <div><strong>Risk Assessments:</strong> ${data.risk_assessment_count || 0}</div>
          <div><strong>Impact Assessments:</strong> ${data.impact_assessment_count || 0}</div>
        </div>
        <div style="margin-top:8px"><strong>Latest Risk Level:</strong> ${data.latest_risk_level ? App.badge(data.latest_risk_level) : 'Not assessed'}</div>
      `);
    } catch (err) {
      App.toast('Error loading asset details', 'error');
    }
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
};
