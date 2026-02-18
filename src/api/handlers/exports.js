/**
 * ForgeAI Govern™ - CSV Export Handlers
 *
 * Data export endpoints for assets, assessments, compliance, vendors, incidents, and evidence.
 */

import { csvResponse } from '../utils.js';

export class ExportHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async exportAssets(ctx) {
    const results = await this.db.prepare(
      `SELECT a.*, u1.first_name || ' ' || u1.last_name as owner_name
       FROM ai_assets a LEFT JOIN users u1 ON a.owner_user_id = u1.id
       WHERE a.tenant_id = ? ORDER BY a.name`
    ).bind(ctx.user.tenant_id).all();

    return csvResponse(results.results, [
      { key: 'name', label: 'Name' }, { key: 'vendor', label: 'Vendor' }, { key: 'version', label: 'Version' },
      { key: 'category', label: 'Category' }, { key: 'risk_tier', label: 'Risk Tier' },
      { key: 'deployment_status', label: 'Status' }, { key: 'phi_access', label: 'PHI Access' },
      { key: 'department', label: 'Department' }, { key: 'owner_name', label: 'Owner' },
      { key: 'fda_classification', label: 'FDA Classification' }, { key: 'created_at', label: 'Created' },
    ], 'ai-assets.csv');
  }

  async exportRiskAssessments(ctx) {
    const results = await this.db.prepare(
      `SELECT r.*, a.name as asset_name, u.first_name || ' ' || u.last_name as assessor_name
       FROM risk_assessments r JOIN ai_assets a ON r.ai_asset_id = a.id JOIN users u ON r.assessor_id = u.id
       WHERE r.tenant_id = ? ORDER BY r.created_at DESC`
    ).bind(ctx.user.tenant_id).all();

    return csvResponse(results.results, [
      { key: 'asset_name', label: 'AI System' }, { key: 'assessment_type', label: 'Type' },
      { key: 'patient_safety_score', label: 'Patient Safety' }, { key: 'bias_fairness_score', label: 'Bias/Fairness' },
      { key: 'data_privacy_score', label: 'Data Privacy' }, { key: 'clinical_validity_score', label: 'Clinical Validity' },
      { key: 'cybersecurity_score', label: 'Cybersecurity' }, { key: 'regulatory_score', label: 'Regulatory' },
      { key: 'overall_risk_level', label: 'Overall Risk' }, { key: 'status', label: 'Status' },
      { key: 'assessor_name', label: 'Assessor' }, { key: 'created_at', label: 'Date' },
    ], 'risk-assessments.csv');
  }

  async exportCompliance(ctx) {
    const results = await this.db.prepare(
      `SELECT cc.control_id, cc.family, cc.title, cc.nist_ai_rmf_ref, cc.fda_samd_ref, cc.onc_hti1_ref, cc.hipaa_ref,
        ci.implementation_status
       FROM compliance_controls cc
       LEFT JOIN control_implementations ci ON cc.id = ci.control_id AND ci.tenant_id = ?
       ORDER BY cc.family, cc.control_id`
    ).bind(ctx.user.tenant_id).all();

    return csvResponse(results.results, [
      { key: 'control_id', label: 'Control ID' }, { key: 'family', label: 'Family' }, { key: 'title', label: 'Title' },
      { key: 'implementation_status', label: 'Status' }, { key: 'nist_ai_rmf_ref', label: 'NIST AI RMF' },
      { key: 'fda_samd_ref', label: 'FDA SaMD' }, { key: 'onc_hti1_ref', label: 'ONC HTI-1' }, { key: 'hipaa_ref', label: 'HIPAA' },
    ], 'compliance-status.csv');
  }

  async exportVendors(ctx) {
    const results = await this.db.prepare(
      `SELECT va.*, u.first_name || ' ' || u.last_name as assessor_name FROM vendor_assessments va
       LEFT JOIN users u ON va.assessed_by = u.id WHERE va.tenant_id = ? ORDER BY va.created_at DESC`
    ).bind(ctx.user.tenant_id).all();

    return csvResponse(results.results, [
      { key: 'vendor_name', label: 'Vendor' }, { key: 'product_name', label: 'Product' },
      { key: 'transparency_score', label: 'Transparency' }, { key: 'bias_testing_score', label: 'Bias Testing' },
      { key: 'security_score', label: 'Security' }, { key: 'data_practices_score', label: 'Data Practices' },
      { key: 'contractual_score', label: 'Contractual' }, { key: 'overall_risk_score', label: 'Overall Score' },
      { key: 'recommendation', label: 'Recommendation' }, { key: 'assessor_name', label: 'Assessor' },
      { key: 'assessed_at', label: 'Date' },
    ], 'vendor-assessments.csv');
  }

  async exportIncidents(ctx) {
    const results = await this.db.prepare(
      `SELECT i.*, a.name as asset_name, u.first_name || ' ' || u.last_name as reporter_name
       FROM incidents i JOIN ai_assets a ON i.ai_asset_id = a.id JOIN users u ON i.reported_by = u.id
       WHERE i.tenant_id = ? ORDER BY i.created_at DESC`
    ).bind(ctx.user.tenant_id).all();

    return csvResponse(results.results, [
      { key: 'title', label: 'Title' }, { key: 'asset_name', label: 'AI System' },
      { key: 'incident_type', label: 'Type' }, { key: 'severity', label: 'Severity' },
      { key: 'patient_impact', label: 'Patient Impact' }, { key: 'status', label: 'Status' },
      { key: 'root_cause', label: 'Root Cause' }, { key: 'corrective_actions', label: 'Corrective Actions' },
      { key: 'reporter_name', label: 'Reporter' }, { key: 'created_at', label: 'Reported' },
      { key: 'resolved_at', label: 'Resolved' },
    ], 'incidents.csv');
  }

  async exportEvidence(ctx) {
    const results = await this.db.prepare(
      `SELECT e.*, u.first_name || ' ' || u.last_name as uploaded_by_name
       FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id
       WHERE e.tenant_id = ? ORDER BY e.created_at DESC`
    ).bind(ctx.user.tenant_id).all();

    return csvResponse(results.results, [
      { key: 'title', label: 'Title' }, { key: 'evidence_type', label: 'Type' },
      { key: 'entity_type', label: 'Entity Type' }, { key: 'entity_id', label: 'Entity ID' },
      { key: 'description', label: 'Description' }, { key: 'url', label: 'URL' },
      { key: 'uploaded_by_name', label: 'Uploaded By' }, { key: 'created_at', label: 'Date' },
    ], 'evidence.csv');
  }
}
