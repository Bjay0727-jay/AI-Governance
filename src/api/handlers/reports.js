/**
 * ForgeAI Govern™ - Audit-Ready Report Handlers
 *
 * HTML compliance audit packages and asset profile reports
 * suitable for FDA submissions, HIPAA audits, and internal governance reviews.
 */

import { errorResponse, htmlResponse } from '../utils.js';

export class ReportHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async auditPack(ctx) {
    const tid = ctx.user.tenant_id;
    const framework = ctx.url.searchParams.get('framework');

    let controlWhere = '';
    if (framework) {
      const frameworkMap = { nist: 'nist_ai_rmf_ref', fda: 'fda_samd_ref', hipaa: 'hipaa_ref', onc: 'onc_hti1_ref' };
      const col = frameworkMap[framework.toLowerCase()];
      if (col) controlWhere = ` AND c.${col} IS NOT NULL AND c.${col} != ''`;
    }

    const controls = await this.db.prepare(
      `SELECT c.control_id, c.family, c.title, c.description, c.nist_ai_rmf_ref, c.fda_samd_ref, c.hipaa_ref, c.onc_hti1_ref,
        ci.implementation_status, ci.implementation_details, ci.last_reviewed,
        u.first_name || ' ' || u.last_name as responsible_party_name
       FROM compliance_controls c
       LEFT JOIN control_implementations ci ON c.id = ci.control_id AND ci.tenant_id = ?
       LEFT JOIN users u ON ci.responsible_party = u.id
       WHERE 1=1 ${controlWhere}
       ORDER BY c.family, c.control_id`
    ).bind(tid).all();

    const tenant = await this.db.prepare('SELECT * FROM tenants WHERE id = ?').bind(tid).first();
    const assetCount = await this.db.prepare('SELECT COUNT(*) as c FROM ai_assets WHERE tenant_id = ?').bind(tid).first();
    const implemented = controls.results.filter(c => c.implementation_status === 'implemented').length;
    const partial = controls.results.filter(c => c.implementation_status === 'partially_implemented').length;
    const total = controls.results.length;
    const compliancePct = total > 0 ? Math.round(((implemented + partial * 0.5) / total) * 100) : 0;

    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Compliance Audit Package - ${tenant?.name || 'Organization'}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1a1a2e; line-height: 1.6; }
  h1 { color: #1a1a2e; border-bottom: 3px solid #0D9488; padding-bottom: 12px; }
  h2 { color: #0D9488; margin-top: 30px; }
  .meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin: 20px 0; }
  .meta-item { padding: 12px; background: #f8fafc; border-radius: 6px; }
  .meta-label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: #64748b; }
  .meta-value { font-size: 18px; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }
  th { background: #0F2A4A; color: white; padding: 10px 12px; text-align: left; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  tr:nth-child(even) { background: #f8fafc; }
  .status-implemented { color: #16a34a; font-weight: 600; }
  .status-partially_implemented { color: #d97706; font-weight: 600; }
  .status-planned { color: #0D9488; font-weight: 600; }
  .status-gap { color: #dc2626; font-weight: 600; }
  .summary { background: #f0fdfa; padding: 20px; border-radius: 8px; margin: 20px 0; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; }
  @media print { body { margin: 20px; } }
</style></head><body>
<h1>Compliance Audit Package</h1>
<p><strong>${tenant?.name || 'Organization'}</strong> | Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })} | ForgeAI Govern&trade;</p>
<div class="meta">
  <div class="meta-item"><div class="meta-label">Overall Compliance</div><div class="meta-value">${compliancePct}%</div></div>
  <div class="meta-item"><div class="meta-label">Controls Assessed</div><div class="meta-value">${total}</div></div>
  <div class="meta-item"><div class="meta-label">AI Assets Governed</div><div class="meta-value">${assetCount.c}</div></div>
  <div class="meta-item"><div class="meta-label">Framework</div><div class="meta-value">${framework ? framework.toUpperCase() : 'All Frameworks'}</div></div>
</div>
<div class="summary">
  <strong>Summary:</strong> ${implemented} controls implemented, ${partial} partially implemented, ${total - implemented - partial} gaps identified out of ${total} total controls.
</div>
<h2>Control Implementation Status</h2>
<table><thead><tr><th>Control ID</th><th>Family</th><th>Title</th><th>Status</th><th>Responsible Party</th><th>Last Reviewed</th><th>NIST Ref</th><th>FDA Ref</th></tr></thead><tbody>
${controls.results.map(c => `<tr>
  <td><strong>${c.control_id}</strong></td><td>${c.family}</td><td>${c.title}</td>
  <td class="status-${c.implementation_status || 'gap'}">${(c.implementation_status || 'NOT IMPLEMENTED').replace(/_/g, ' ').toUpperCase()}</td>
  <td>${c.responsible_party_name || '\u2014'}</td><td>${c.last_reviewed ? new Date(c.last_reviewed).toLocaleDateString() : '\u2014'}</td>
  <td>${c.nist_ai_rmf_ref || '\u2014'}</td><td>${c.fda_samd_ref || '\u2014'}</td>
</tr>`).join('')}
</tbody></table>
<div class="footer">
  <p>This report was generated by ForgeAI Govern&trade; Healthcare AI Governance Platform. It represents the compliance status as of the generation date and should be reviewed by authorized personnel before submission to auditors or regulatory bodies.</p>
  <p>Frameworks covered: NIST AI RMF 1.0, FDA SaMD, ONC HTI-1, HIPAA, State AI Laws</p>
</div>
</body></html>`;

    return htmlResponse(html);
  }

  async assetProfile(ctx, id) {
    const tid = ctx.user.tenant_id;
    const asset = await this.db.prepare(
      `SELECT a.*, u.first_name || ' ' || u.last_name as owner_name
       FROM ai_assets a LEFT JOIN users u ON a.owner_user_id = u.id
       WHERE a.id = ? AND a.tenant_id = ?`
    ).bind(id, tid).first();
    if (!asset) return errorResponse('Asset not found', 404);

    const [risks, impacts, incidents, evidence, tenant] = await Promise.all([
      this.db.prepare(`SELECT r.*, u.first_name || ' ' || u.last_name as assessor_name FROM risk_assessments r JOIN users u ON r.assessor_id = u.id WHERE r.ai_asset_id = ? AND r.tenant_id = ? ORDER BY r.created_at DESC`).bind(id, tid).all(),
      this.db.prepare('SELECT * FROM impact_assessments WHERE ai_asset_id = ? AND tenant_id = ? ORDER BY created_at DESC').bind(id, tid).all(),
      this.db.prepare('SELECT * FROM incidents WHERE ai_asset_id = ? AND tenant_id = ? ORDER BY created_at DESC').bind(id, tid).all(),
      this.db.prepare("SELECT * FROM evidence WHERE entity_type = 'ai_asset' AND entity_id = ? AND tenant_id = ? ORDER BY created_at DESC").bind(id, tid).all(),
      this.db.prepare('SELECT name FROM tenants WHERE id = ?').bind(tid).first(),
    ]);

    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>AI Asset Profile - ${asset.name}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1a1a2e; line-height: 1.6; }
  h1 { color: #1a1a2e; border-bottom: 3px solid #0D9488; padding-bottom: 12px; }
  h2 { color: #0D9488; margin-top: 30px; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 16px 0; }
  .field { padding: 10px; background: #f8fafc; border-radius: 6px; }
  .field-label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: #64748b; }
  .field-value { font-size: 14px; font-weight: 500; margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
  th { background: #0F2A4A; color: white; padding: 8px 10px; text-align: left; }
  td { padding: 6px 10px; border-bottom: 1px solid #e2e8f0; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-critical { background: #fef2f2; color: #dc2626; }
  .badge-high { background: #fff7ed; color: #ea580c; }
  .badge-moderate { background: #fefce8; color: #ca8a04; }
  .badge-low { background: #f0fdf4; color: #16a34a; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; }
  @media print { body { margin: 20px; } }
</style></head><body>
<h1>AI Asset Profile: ${asset.name}</h1>
<p><strong>${tenant?.name || 'Organization'}</strong> | Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })} | ForgeAI Govern&trade;</p>
<div class="grid">
  <div class="field"><div class="field-label">Vendor</div><div class="field-value">${asset.vendor || 'Internal'}</div></div>
  <div class="field"><div class="field-label">Version</div><div class="field-value">${asset.version || 'N/A'}</div></div>
  <div class="field"><div class="field-label">Category</div><div class="field-value">${(asset.category || '').replace(/_/g, ' ')}</div></div>
  <div class="field"><div class="field-label">Risk Tier</div><div class="field-value"><span class="badge badge-${asset.risk_tier}">${asset.risk_tier?.toUpperCase()}</span></div></div>
  <div class="field"><div class="field-label">Deployment Status</div><div class="field-value">${(asset.deployment_status || '').replace(/_/g, ' ')}</div></div>
  <div class="field"><div class="field-label">PHI Access</div><div class="field-value">${asset.phi_access ? 'Yes' : 'No'}</div></div>
  <div class="field"><div class="field-label">Owner</div><div class="field-value">${asset.owner_name || 'Unassigned'}</div></div>
  <div class="field"><div class="field-label">Department</div><div class="field-value">${asset.department || 'N/A'}</div></div>
  <div class="field"><div class="field-label">FDA Classification</div><div class="field-value">${asset.fda_classification || 'None'}</div></div>
</div>
${asset.description ? `<p><strong>Description:</strong> ${asset.description}</p>` : ''}
${asset.intended_use ? `<p><strong>Intended Use:</strong> ${asset.intended_use}</p>` : ''}
<h2>Risk Assessment History (${risks.results.length})</h2>
${risks.results.length > 0 ? `<table><thead><tr><th>Date</th><th>Type</th><th>Assessor</th><th>Overall Risk</th><th>Patient Safety</th><th>Bias</th><th>Privacy</th><th>Clinical</th><th>Cyber</th><th>Regulatory</th><th>Status</th></tr></thead><tbody>
${risks.results.map(r => `<tr><td>${new Date(r.created_at).toLocaleDateString()}</td><td>${r.assessment_type}</td><td>${r.assessor_name}</td>
<td><span class="badge badge-${r.overall_risk_level}">${r.overall_risk_level?.toUpperCase()}</span></td>
<td>${r.patient_safety_score || '\u2014'}</td><td>${r.bias_fairness_score || '\u2014'}</td><td>${r.data_privacy_score || '\u2014'}</td>
<td>${r.clinical_validity_score || '\u2014'}</td><td>${r.cybersecurity_score || '\u2014'}</td><td>${r.regulatory_score || '\u2014'}</td>
<td>${r.status}</td></tr>`).join('')}
</tbody></table>` : '<p>No risk assessments recorded.</p>'}
<h2>Impact Assessments (${impacts.results.length})</h2>
${impacts.results.length > 0 ? `<table><thead><tr><th>Period</th><th>Drift</th><th>Remediation</th><th>Status</th><th>Date</th></tr></thead><tbody>
${impacts.results.map(ia => `<tr><td>${ia.assessment_period || 'N/A'}</td><td>${ia.drift_detected ? 'Yes' : 'No'}</td>
<td>${ia.remediation_status || 'N/A'}</td><td>${ia.status}</td><td>${new Date(ia.created_at).toLocaleDateString()}</td></tr>`).join('')}
</tbody></table>` : '<p>No impact assessments recorded.</p>'}
<h2>Incident History (${incidents.results.length})</h2>
${incidents.results.length > 0 ? `<table><thead><tr><th>Title</th><th>Type</th><th>Severity</th><th>Status</th><th>Patient Impact</th><th>Date</th></tr></thead><tbody>
${incidents.results.map(i => `<tr><td>${i.title}</td><td>${i.incident_type.replace(/_/g, ' ')}</td>
<td><span class="badge badge-${i.severity}">${i.severity.toUpperCase()}</span></td><td>${i.status}</td>
<td>${i.patient_impact ? 'Yes' : 'No'}</td><td>${new Date(i.created_at).toLocaleDateString()}</td></tr>`).join('')}
</tbody></table>` : '<p>No incidents recorded.</p>'}
<h2>Evidence (${evidence.results.length})</h2>
${evidence.results.length > 0 ? `<table><thead><tr><th>Title</th><th>Type</th><th>Description</th><th>Date</th></tr></thead><tbody>
${evidence.results.map(e => `<tr><td>${e.title}</td><td>${e.evidence_type}</td><td>${e.description || '\u2014'}</td><td>${new Date(e.created_at).toLocaleDateString()}</td></tr>`).join('')}
</tbody></table>` : '<p>No evidence linked to this asset.</p>'}
<div class="footer">
  <p>Generated by ForgeAI Govern&trade; Healthcare AI Governance Platform. This profile is suitable for FDA submissions, Joint Commission reviews, and internal governance audits.</p>
</div>
</body></html>`;

    return htmlResponse(html);
  }
}
