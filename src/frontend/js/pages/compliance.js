export const compliance = {
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
};
