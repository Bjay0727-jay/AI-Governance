export const risk = {
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
};
