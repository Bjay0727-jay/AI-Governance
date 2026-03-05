export const impact = {
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
