export const governance = {
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
};
