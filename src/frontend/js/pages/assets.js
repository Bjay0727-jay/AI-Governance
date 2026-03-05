export const assets = {
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
};
