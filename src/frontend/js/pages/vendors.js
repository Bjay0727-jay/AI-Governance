export const vendors = {
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
};
