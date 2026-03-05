export const reports = {
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
