/**
 * ForgeAI Govern™ - Demo Data Seed Script
 *
 * Populates the platform with realistic healthcare AI systems,
 * risk assessments, and monitoring data for demonstration.
 * Run: npm run seed
 */

const crypto = require('crypto');
const { createDatabase } = require('../src/local/db-adapter');

const uuid = () => crypto.randomUUID();

console.log('ForgeAI Govern™ - Demo Data Seeding');
console.log('====================================\n');

const db = createDatabase();

// --- Create Demo Tenant ---
const tenantId = uuid();
db.prepare(
  `INSERT OR IGNORE INTO tenants (id, name, slug, plan, hipaa_baa_signed, status)
   VALUES (?, 'Memorial Health System', 'memorial-health', 'professional', 1, 'active')`
).bind(tenantId).run();
console.log('Created tenant: Memorial Health System');

// --- Create Demo Admin User ---
// Password: "DemoAdmin2025!" — hashed with simple PBKDF2 placeholder
// In production, the auth module handles proper hashing
const userId = uuid();
const reviewerId = uuid();
const viewerId = uuid();

// Simple hash for demo (the real auth uses PBKDF2 via Web Crypto)
const demoHash = '100000:' + '0'.repeat(64) + ':' + crypto.createHash('sha256').update('DemoAdmin2025!').digest('hex');

db.prepare(
  `INSERT OR IGNORE INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
   VALUES (?, ?, 'admin@memorialhealth.org', ?, 'Sarah', 'Chen', 'admin', 'active')`
).bind(userId, tenantId, demoHash).run();

db.prepare(
  `INSERT OR IGNORE INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
   VALUES (?, ?, 'jthompson@memorialhealth.org', ?, 'James', 'Thompson', 'governance_lead', 'active')`
).bind(reviewerId, tenantId, demoHash).run();

db.prepare(
  `INSERT OR IGNORE INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
   VALUES (?, ?, 'mgarcia@memorialhealth.org', ?, 'Maria', 'Garcia', 'reviewer', 'active')`
).bind(viewerId, tenantId, demoHash).run();

console.log('Created users: Sarah Chen (Admin), James Thompson (Governance Lead), Maria Garcia (Reviewer)');

// --- Create Demo AI Assets ---
const assets = [
  {
    id: uuid(), name: 'SepsisAlert AI', vendor: 'Epic Systems', version: '4.2.1',
    category: 'clinical_decision_support', risk_tier: 'critical',
    fda_classification: 'Class II - 510(k)', phi_access: 1,
    deployment_status: 'deployed', department: 'Emergency Medicine',
    description: 'Real-time sepsis prediction model integrated into Epic EHR that monitors vital signs, lab results, and clinical notes to generate early warning alerts for clinicians.',
    intended_use: 'Early identification of patients at risk for sepsis in emergency department and inpatient settings.',
    data_sources: '["EHR vitals","Lab results","Clinical notes","Medication orders"]',
    phi_data_types: '["demographics","diagnoses","vitals","lab_results","medications"]',
  },
  {
    id: uuid(), name: 'ChestView DX', vendor: 'Aidoc Medical', version: '3.1.0',
    category: 'diagnostic_imaging', risk_tier: 'high',
    fda_classification: 'Class II - 510(k) K203868', phi_access: 1,
    deployment_status: 'deployed', department: 'Radiology',
    description: 'FDA-cleared AI algorithm for detecting pulmonary embolism, aortic dissection, and cervical spine fractures on CT imaging.',
    intended_use: 'Automated prioritization of critical findings in radiology workflow to reduce time-to-diagnosis.',
    data_sources: '["PACS imaging","DICOM headers"]',
    phi_data_types: '["demographics","imaging","diagnoses"]',
  },
  {
    id: uuid(), name: 'ReadmitPredict', vendor: 'Internal (Data Science)', version: '2.0.3',
    category: 'predictive_analytics', risk_tier: 'high',
    fda_classification: 'None - Internal Model', phi_access: 1,
    deployment_status: 'deployed', department: 'Care Management',
    description: 'Internally developed 30-day readmission risk prediction model using gradient boosted trees on EHR data.',
    intended_use: 'Identify high-risk patients for targeted transitional care interventions to reduce 30-day readmissions.',
    data_sources: '["EHR demographics","Claims history","Social determinants","Prior admissions"]',
    phi_data_types: '["demographics","diagnoses","claims","social_determinants"]',
  },
  {
    id: uuid(), name: 'NoteScribe NLP', vendor: 'Nuance/Microsoft', version: '2024.3',
    category: 'nlp_extraction', risk_tier: 'moderate',
    fda_classification: 'None', phi_access: 1,
    deployment_status: 'deployed', department: 'Health Information Management',
    description: 'Natural language processing engine that extracts structured clinical data from unstructured physician notes for coding and quality reporting.',
    intended_use: 'Automated extraction of diagnoses, procedures, and quality measures from clinical documentation.',
    data_sources: '["Clinical notes","Discharge summaries","Operative reports"]',
    phi_data_types: '["demographics","diagnoses","procedures","clinical_notes"]',
  },
  {
    id: uuid(), name: 'StaffOptimizer', vendor: 'Qventus', version: '5.1',
    category: 'operational', risk_tier: 'low',
    fda_classification: 'None', phi_access: 0,
    deployment_status: 'deployed', department: 'Nursing Administration',
    description: 'AI-powered nurse staffing and scheduling optimization platform using demand forecasting models.',
    intended_use: 'Optimize nurse scheduling based on predicted patient volumes and acuity levels.',
    data_sources: '["Census data","Staffing records","Historical volumes"]',
    phi_data_types: '[]',
  },
  {
    id: uuid(), name: 'ClaimsCoder AI', vendor: 'Optum/Change Healthcare', version: '8.2',
    category: 'revenue_cycle', risk_tier: 'moderate',
    fda_classification: 'None', phi_access: 1,
    deployment_status: 'deployed', department: 'Revenue Cycle',
    description: 'Automated medical coding assistant that suggests ICD-10 and CPT codes from clinical documentation.',
    intended_use: 'Assist certified coders in assigning accurate diagnosis and procedure codes to improve coding accuracy and throughput.',
    data_sources: '["Clinical notes","Charge capture","Encounter records"]',
    phi_data_types: '["demographics","diagnoses","procedures","claims"]',
  },
  {
    id: uuid(), name: 'DermaScreen AI', vendor: 'SkinVision', version: '1.4.0',
    category: 'diagnostic_imaging', risk_tier: 'high',
    fda_classification: 'Pending 510(k)', phi_access: 1,
    deployment_status: 'validating', department: 'Dermatology',
    description: 'Skin lesion classification model using convolutional neural networks for melanoma risk assessment.',
    intended_use: 'Assist dermatologists in triaging skin lesion images for further biopsy evaluation.',
    data_sources: '["Dermoscopy images","Patient demographics"]',
    phi_data_types: '["demographics","imaging"]',
  },
  {
    id: uuid(), name: 'FallRisk Predictor', vendor: 'Internal (Clinical Informatics)', version: '1.1.0',
    category: 'clinical_decision_support', risk_tier: 'moderate',
    fda_classification: 'None - Internal Model', phi_access: 1,
    deployment_status: 'proposed', department: 'Nursing',
    description: 'Machine learning model that predicts inpatient fall risk using mobility assessments, medication profiles, and cognitive status.',
    intended_use: 'Supplement Morse Fall Scale with ML-based risk stratification for targeted fall prevention interventions.',
    data_sources: '["EHR assessments","Medication records","Mobility data"]',
    phi_data_types: '["demographics","medications","assessments"]',
  },
];

for (const a of assets) {
  db.prepare(
    `INSERT INTO ai_assets (id, tenant_id, name, vendor, version, category, risk_tier,
      fda_classification, phi_access, deployment_status, department, description,
      intended_use, data_sources, phi_data_types, owner_user_id, clinical_champion_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    a.id, tenantId, a.name, a.vendor, a.version, a.category, a.risk_tier,
    a.fda_classification, a.phi_access ? 1 : 0, a.deployment_status, a.department,
    a.description, a.intended_use, a.data_sources, a.phi_data_types,
    userId, reviewerId
  ).run();
}
console.log(`Registered ${assets.length} AI assets`);

// --- Create Risk Assessments ---
const riskAssessments = [
  { asset: assets[0], safety: 5, bias: 4, privacy: 4, clinical: 3, cyber: 3, reg: 3, overall: 'critical', status: 'approved' },
  { asset: assets[1], safety: 4, bias: 3, privacy: 3, clinical: 2, cyber: 2, reg: 2, overall: 'high', status: 'approved' },
  { asset: assets[2], safety: 3, bias: 4, privacy: 3, clinical: 3, cyber: 3, reg: 3, overall: 'high', status: 'approved' },
  { asset: assets[3], safety: 2, bias: 2, privacy: 3, clinical: 2, cyber: 2, reg: 2, overall: 'moderate', status: 'approved' },
  { asset: assets[4], safety: 1, bias: 1, privacy: 1, clinical: 1, cyber: 2, reg: 1, overall: 'low', status: 'approved' },
  { asset: assets[5], safety: 2, bias: 3, privacy: 3, clinical: 2, cyber: 2, reg: 2, overall: 'moderate', status: 'approved' },
  { asset: assets[6], safety: 4, bias: 3, privacy: 3, clinical: 4, cyber: 2, reg: 4, overall: 'high', status: 'in_review' },
  { asset: assets[7], safety: 3, bias: 3, privacy: 2, clinical: 3, cyber: 2, reg: 2, overall: 'moderate', status: 'draft' },
];

for (const r of riskAssessments) {
  db.prepare(
    `INSERT INTO risk_assessments (id, tenant_id, ai_asset_id, assessment_type, assessor_id,
      patient_safety_score, bias_fairness_score, data_privacy_score, clinical_validity_score,
      cybersecurity_score, regulatory_score, overall_risk_level, status, approved_by, completed_at,
      findings, recommendations)
     VALUES (?, ?, ?, 'initial', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)`
  ).bind(
    uuid(), tenantId, r.asset.id, reviewerId,
    r.safety, r.bias, r.privacy, r.clinical, r.cyber, r.reg,
    r.overall, r.status, r.status === 'approved' ? userId : null,
    JSON.stringify({ patient_safety: `Score: ${r.safety}/5`, bias_fairness: `Score: ${r.bias}/5` }),
    `Risk level: ${r.overall}. ${r.overall === 'critical' ? 'Requires quarterly reassessment and continuous monitoring.' : 'Standard governance controls apply.'}`
  ).run();
}
console.log(`Created ${riskAssessments.length} risk assessments`);

// --- Create Monitoring Metrics ---
const deployedAssets = assets.filter(a => a.deployment_status === 'deployed');
const metricTypes = ['accuracy', 'precision', 'recall', 'f1_score', 'bias_index', 'drift_score'];

let metricCount = 0;
for (const asset of deployedAssets) {
  for (const mtype of metricTypes) {
    // Generate 5 data points per metric
    for (let i = 0; i < 5; i++) {
      const baseValue = mtype === 'bias_index' ? 0.15 : mtype === 'drift_score' ? 0.05 : 0.88;
      const value = +(baseValue + (Math.random() - 0.5) * 0.1).toFixed(4);
      const thresholdMin = mtype === 'bias_index' ? null : 0.80;
      const thresholdMax = mtype === 'bias_index' ? 0.25 : mtype === 'drift_score' ? 0.15 : null;
      const alert = (thresholdMin && value < thresholdMin) || (thresholdMax && value > thresholdMax);

      db.prepare(
        `INSERT INTO monitoring_metrics (id, tenant_id, ai_asset_id, metric_type, metric_value,
          threshold_min, threshold_max, alert_triggered, alert_severity, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ? || ' days'))`
      ).bind(
        uuid(), tenantId, asset.id, mtype, value,
        thresholdMin, thresholdMax, alert ? 1 : 0,
        alert ? 'warning' : null, String(-i * 7)
      ).run();
      metricCount++;
    }
  }
}
console.log(`Recorded ${metricCount} monitoring metrics`);

// --- Create Sample Incidents ---
db.prepare(
  `INSERT INTO incidents (id, tenant_id, ai_asset_id, reported_by, incident_type, severity,
    title, description, patient_impact, status)
   VALUES (?, ?, ?, ?, 'bias_detected', 'high',
    'Readmission model shows disparate performance across racial groups',
    'Quarterly AIA revealed that ReadmitPredict shows 12% lower recall for Black patients compared to White patients (0.71 vs 0.83). Disparate impact ratio of 0.86 is above 0.8 threshold but trending downward. Initiated investigation into training data representation.',
    0, 'investigating')`
).bind(uuid(), tenantId, assets[2].id, viewerId).run();

db.prepare(
  `INSERT INTO incidents (id, tenant_id, ai_asset_id, reported_by, incident_type, severity,
    title, description, patient_impact, status)
   VALUES (?, ?, ?, ?, 'performance_degradation', 'moderate',
    'SepsisAlert false positive rate increased 15% over baseline',
    'Monitoring dashboard detected a sustained increase in false positive alerts over the past 3 weeks. FP rate rose from 8.2% baseline to 9.4%. Likely caused by seasonal flu volume changes. Drift score approaching threshold.',
    0, 'mitigating')`
).bind(uuid(), tenantId, assets[0].id, reviewerId).run();

console.log('Created 2 sample incidents');

// --- Create Maturity Assessment ---
db.prepare(
  `INSERT INTO maturity_assessments (id, tenant_id, assessor_id, assessment_date,
    governance_structure_score, ai_inventory_score, risk_assessment_score,
    policy_compliance_score, monitoring_performance_score, vendor_management_score,
    transparency_score, overall_maturity_score, domain_findings,
    immediate_actions, near_term_actions, strategic_actions, status)
   VALUES (?, ?, ?, datetime('now'), 3, 3, 2, 2, 2, 2, 1, 2.15, ?, ?, ?, ?, 'final')`
).bind(
  uuid(), tenantId, userId,
  JSON.stringify({
    governance_structure: 'Committee established with quarterly meetings. Charter documented. Needs budget formalization.',
    ai_inventory: 'Registry exists but missing embedded vendor AI. Quarterly review cycle started.',
    risk_assessment: 'Initial assessments completed for deployed systems. No pre-deployment gate yet.',
    policy_compliance: 'AI acceptable use policy drafted. Multi-framework mapping incomplete.',
    monitoring_performance: 'Basic dashboards for critical systems. No automated drift detection.',
    vendor_management: 'Using general IT vendor process. No AI-specific questionnaire.',
    transparency: 'No clinician-facing explanations. No patient notification process.',
  }),
  JSON.stringify([
    'Complete AI inventory including embedded vendor AI features',
    'Finalize and publish AI acceptable use policy',
    'Implement pre-deployment risk assessment gate for new AI systems',
  ]),
  JSON.stringify([
    'Deploy AI-specific vendor assessment questionnaire',
    'Establish automated monitoring for all high/critical risk AI systems',
    'Develop multi-framework compliance crosswalk (NIST AI RMF + HIPAA + state laws)',
    'Launch clinician AI training program',
  ]),
  JSON.stringify([
    'Achieve Level 3 (Defined) maturity across all domains',
    'Implement automated bias monitoring with demographic dashboards',
    'Integrate AI governance reporting into enterprise risk management',
    'Evaluate dedicated CAIO role for growing AI portfolio',
  ])
).run();
console.log('Created maturity assessment (Overall: 2.15 - Developing)');

// --- Create Control Implementations ---
const controls = db.prepare('SELECT id, control_id FROM compliance_controls').all();
let implCount = 0;
for (const ctrl of controls.results) {
  const statuses = ['implemented', 'partially_implemented', 'planned', 'not_applicable'];
  // Weight toward planned/partial for realistic demo
  const weights = [0.2, 0.3, 0.4, 0.1];
  const rand = Math.random();
  let cumulative = 0;
  let status = 'planned';
  for (let i = 0; i < weights.length; i++) {
    cumulative += weights[i];
    if (rand < cumulative) { status = statuses[i]; break; }
  }

  db.prepare(
    `INSERT OR IGNORE INTO control_implementations (id, tenant_id, ai_asset_id, control_id,
      implementation_status, responsible_party)
     VALUES (?, ?, NULL, ?, ?, ?)`
  ).bind(uuid(), tenantId, ctrl.id, status, userId).run();
  implCount++;
}
console.log(`Created ${implCount} control implementation records`);

// --- Create Vendor Assessments ---
const vendorAssessments = [
  { vendor: 'Epic Systems', product: 'SepsisAlert AI Module', transparency: 4, bias: 3, security: 5, data: 4, contractual: 5, score: 84, rec: 'approved' },
  { vendor: 'Aidoc Medical', product: 'ChestView DX', transparency: 4, bias: 4, security: 4, data: 4, contractual: 4, score: 80, rec: 'approved' },
  { vendor: 'Nuance/Microsoft', product: 'NoteScribe NLP Engine', transparency: 3, bias: 3, security: 5, data: 4, contractual: 4, score: 76, rec: 'approved' },
  { vendor: 'Qventus', product: 'StaffOptimizer Platform', transparency: 3, bias: 2, security: 3, data: 3, contractual: 3, score: 56, rec: 'conditional' },
  { vendor: 'SkinVision', product: 'DermaScreen AI', transparency: 2, bias: 2, security: 3, data: 2, contractual: 2, score: 44, rec: 'conditional' },
];

for (const v of vendorAssessments) {
  db.prepare(
    `INSERT INTO vendor_assessments (id, tenant_id, vendor_name, product_name,
      transparency_score, bias_testing_score, security_score, data_practices_score,
      contractual_score, overall_risk_score, recommendation, assessed_by, assessed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
  ).bind(
    uuid(), tenantId, v.vendor, v.product,
    v.transparency, v.bias, v.security, v.data, v.contractual,
    v.score, v.rec, reviewerId
  ).run();
}
console.log(`Created ${vendorAssessments.length} vendor assessments`);

db.close();

console.log('\n====================================');
console.log('Demo data seeded successfully!');
console.log('Run "npm start" to launch the platform.');
console.log('\nDemo login:');
console.log('  Email:    admin@memorialhealth.org');
console.log('  Password: DemoAdmin2025!');
console.log('  (Note: use the registration form for full auth flow)');
console.log('====================================\n');
