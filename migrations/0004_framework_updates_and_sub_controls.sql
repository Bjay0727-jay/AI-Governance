-- ============================================================================
-- Migration 0004: Framework Updates + Sub-Controls for Inheritance
-- ============================================================================

-- Track regulatory framework updates and their acknowledgment
CREATE TABLE IF NOT EXISTS framework_updates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  framework_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  effective_date TEXT,
  impact_level TEXT DEFAULT 'medium' CHECK (impact_level IN ('low', 'medium', 'high', 'critical')),
  affected_controls TEXT DEFAULT '[]',
  status TEXT DEFAULT 'pending_review' CHECK (status IN ('pending_review', 'acknowledged', 'action_required', 'resolved')),
  created_by TEXT REFERENCES users(id),
  acknowledged_by TEXT REFERENCES users(id),
  acknowledged_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_framework_updates_tenant ON framework_updates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_framework_updates_status ON framework_updates(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_framework_updates_framework ON framework_updates(framework_id);

-- Add parent_control_id to compliance_controls for sub-control hierarchy
ALTER TABLE compliance_controls ADD COLUMN parent_control_id TEXT REFERENCES compliance_controls(id);

-- ============================================================================
-- Sub-controls for NIST AI RMF (expanding to full coverage)
-- ============================================================================

-- GOVERN sub-controls
INSERT OR IGNORE INTO compliance_controls (id, control_id, family, title, description, nist_ai_rmf_ref, parent_control_id, risk_tiers, category, guidance, evidence_requirements)
VALUES
('c001-1', 'GOV-1.1', 'Govern', 'AI Governance Charter',
 'Formalize AI governance charter defining scope, authority, decision rights, and escalation paths for the governance committee.',
 'GOVERN 1.1', 'c001', '["critical","high","moderate","low"]', 'Organizational',
 'Document charter with explicit authority over AI procurement, deployment, and monitoring decisions.',
 'Signed charter, board approval records'),

('c001-2', 'GOV-1.2', 'Govern', 'Governance Meeting Cadence',
 'Establish and maintain regular governance committee meeting schedule with documented agendas and minutes.',
 'GOVERN 1.1', 'c001', '["critical","high","moderate","low"]', 'Organizational',
 'Minimum quarterly meetings for moderate risk; monthly for critical/high risk portfolio.',
 'Meeting schedules, agendas, minutes, attendance records'),

('c002-1', 'GOV-2.1', 'Govern', 'AI Acceptable Use Policy',
 'Define acceptable use policies for AI systems covering appropriate clinical use, prohibited uses, and user responsibilities.',
 'GOVERN 1.2', 'c002', '["critical","high","moderate","low"]', 'Policy',
 'Cover clinical decision support, autonomous actions, data usage, and user override requirements.',
 'Published AUP, acknowledgment records'),

('c002-2', 'GOV-2.2', 'Govern', 'AI Procurement Policy',
 'Establish AI-specific procurement requirements including vendor assessment, bias testing mandates, and contractual provisions.',
 'GOVERN 1.2', 'c002', '["critical","high","moderate","low"]', 'Policy',
 'Require AI-specific vendor questionnaires and minimum scoring thresholds before approval.',
 'Procurement policy, vendor questionnaire template'),

('c006-1', 'GOV-6.1', 'Govern', 'Annual Governance Training',
 'Deliver annual AI governance training to all governance committee members and AI system owners.',
 'GOVERN 4.1', 'c006', '["critical","high","moderate","low"]', 'Training',
 'Include NIST AI RMF overview, organizational policies, and role-specific responsibilities.',
 'Training materials, completion certificates, assessment scores'),

('c006-2', 'GOV-6.2', 'Govern', 'Clinician AI Awareness Training',
 'Train clinical staff on appropriate use of AI tools, override procedures, and incident reporting.',
 'GOVERN 4.2', 'c006', '["critical","high","moderate"]', 'Training',
 'Focus on clinical workflow integration, understanding AI limitations, and when to override.',
 'Training modules, completion tracking, competency assessments'),

-- MAP sub-controls
('c010-1', 'MAP-1.1', 'Map', 'Quarterly Inventory Review',
 'Conduct quarterly reviews of AI asset inventory to identify new, changed, or deprecated systems.',
 'MAP 1.1', 'c010', '["critical","high","moderate","low"]', 'Inventory',
 'Review includes embedded vendor AI, shadow AI, and research AI transitioning to clinical use.',
 'Quarterly review records, change logs'),

('c010-2', 'MAP-1.2', 'Map', 'Shadow AI Detection',
 'Implement processes to detect and catalog unauthorized or unregistered AI tools in use across the organization.',
 'MAP 1.1', 'c010', '["critical","high","moderate"]', 'Inventory',
 'Partner with IT security and procurement to identify AI tools acquired outside governance processes.',
 'Detection procedures, discovery logs, remediation records'),

('c012-1', 'MAP-3.1', 'Map', 'PHI Data Flow Mapping',
 'Create and maintain data flow diagrams showing how PHI moves through AI systems including ingestion, processing, storage, and output.',
 'MAP 2.1', 'c012', '["critical","high","moderate"]', 'Data Governance',
 'Update data flow diagrams whenever system configurations change. Include third-party data flows.',
 'Data flow diagrams, update logs'),

-- MEASURE sub-controls
('c020-1', 'MEA-1.1', 'Measure', 'Multi-Dimensional Risk Scoring',
 'Apply standardized 6-dimension risk scoring across patient safety, bias, privacy, clinical validity, cybersecurity, and regulatory compliance.',
 'MEASURE 1.1', 'c020', '["critical","high","moderate"]', 'Risk Assessment',
 'Score each dimension 1-5. Weight patient safety and bias higher for healthcare context.',
 'Scoring rubric, completed assessments with dimension scores'),

('c020-2', 'MEA-1.2', 'Measure', 'Governance Committee Risk Approval',
 'Require governance committee review and approval for all high and critical risk AI deployments.',
 'MEASURE 1.1', 'c020', '["critical","high"]', 'Risk Assessment',
 'Committee must formally approve before production deployment. Document dissenting opinions.',
 'Approval records, committee vote records, dissent documentation'),

('c021-1', 'MEA-2.1', 'Measure', 'Demographic Performance Testing',
 'Test AI system performance disaggregated across protected demographic categories using local population data.',
 'MEASURE 2.1', 'c021', '["critical","high"]', 'Bias & Fairness',
 'Test across race, ethnicity, gender, age, insurance status, and language. Document methodology.',
 'Disaggregated performance reports, methodology documentation'),

('c021-2', 'MEA-2.2', 'Measure', 'Disparate Impact Remediation',
 'Require remediation plans when disparate impact ratio falls below 0.8 for any protected group.',
 'MEASURE 2.1', 'c021', '["critical","high"]', 'Bias & Fairness',
 'Implement remediation within 90 days of detection. Re-test to confirm remediation effectiveness.',
 'Remediation plans, re-test results, timeline documentation'),

('c023-1', 'MEA-4.1', 'Measure', 'Automated Performance Dashboards',
 'Deploy automated monitoring dashboards tracking key performance indicators for each deployed AI system.',
 'MEASURE 2.3', 'c023', '["critical","high","moderate"]', 'Monitoring',
 'Track accuracy, precision, recall, AUC-ROC, and domain-specific clinical metrics.',
 'Dashboard configurations, metric definitions, screenshot evidence'),

('c023-2', 'MEA-4.2', 'Measure', 'Alert Threshold Configuration',
 'Define and implement alerting thresholds for each monitored metric with appropriate severity levels and escalation paths.',
 'MEASURE 2.3', 'c023', '["critical","high","moderate"]', 'Monitoring',
 'Set thresholds proportional to risk tier. Critical systems require tighter thresholds.',
 'Threshold configurations, escalation procedures, alert history'),

-- MANAGE sub-controls
('c030-1', 'MAN-1.1', 'Manage', 'Vendor AI Questionnaire',
 'Administer standardized AI-specific vendor questionnaire covering training data, bias testing, update practices, and security.',
 'MANAGE 1.1', 'c030', '["critical","high","moderate"]', 'Vendor Management',
 'Use 5-dimension scoring across transparency, bias testing, security, data practices, and contractual provisions.',
 'Completed questionnaires, scoring records'),

('c030-2', 'MAN-1.2', 'Manage', 'Vendor Contract AI Provisions',
 'Ensure vendor contracts include AI-specific provisions for model updates, bias disclosure, incident response, and BAA coverage.',
 'MANAGE 1.1', 'c030', '["critical","high","moderate"]', 'Vendor Management',
 'Require right to audit, performance guarantees, bias testing obligations, and timely incident notification.',
 'Contract excerpts, legal review records'),

('c032-1', 'MAN-3.1', 'Manage', 'AI Incident Severity Classification',
 'Define severity classification for AI incidents: critical (auto-suspend), high (24hr response), medium (72hr response), low (next review).',
 'MANAGE 3.1', 'c032', '["critical","high","moderate","low"]', 'Incident Response',
 'Critical patient safety events trigger automatic AI system suspension pending investigation.',
 'Severity matrix, auto-suspension procedures'),

('c032-2', 'MAN-3.2', 'Manage', 'Post-Incident Review Process',
 'Conduct root cause analysis and post-incident reviews for all high and critical AI incidents within 14 days.',
 'MANAGE 3.1', 'c032', '["critical","high"]', 'Incident Response',
 'Document root cause, contributing factors, corrective actions, and lessons learned.',
 'Post-incident reports, corrective action plans'),

('c035-1', 'MAN-6.1', 'Manage', 'Clinician-Facing AI Explanations',
 'Provide clinician-appropriate explanations of AI outputs proportional to system risk tier and clinical impact.',
 'MANAGE 4.2', 'c035', '["critical","high"]', 'Transparency',
 'Include confidence indicators, key contributing factors, and known limitations in clinical interfaces.',
 'Explanation documentation, UI screenshots, clinician feedback'),

('c035-2', 'MAN-6.2', 'Manage', 'Patient AI Notification',
 'Implement patient notification when AI substantially influences clinical decisions per state law requirements.',
 'MANAGE 4.2', 'c035', '["critical","high"]', 'Transparency',
 'Design notifications that are comprehensible to patients. Document notification method and content.',
 'Notification templates, delivery records, patient feedback');
