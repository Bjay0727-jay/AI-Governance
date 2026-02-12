-- ============================================================================
-- ForgeAI Govern™ - Compliance Control Catalog Seed Data
-- Multi-Framework Mappings: NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, State Laws
-- ============================================================================

-- ============================================================================
-- GOVERN FUNCTION - Organizational governance structures and policies
-- ============================================================================
INSERT INTO compliance_controls (id, control_id, family, title, description, nist_ai_rmf_ref, fda_samd_ref, onc_hti1_ref, hipaa_ref, state_law_refs, joint_commission_ref, risk_tiers, category, guidance, evidence_requirements)
VALUES
('c001', 'GOV-1', 'Govern', 'AI Governance Committee',
 'Establish a cross-functional AI governance committee with defined charter, membership, meeting cadence, and decision authority. Committee must include CISO, CMIO, Compliance, Legal, and clinical representation.',
 'GOVERN 1.1', 'QMS Requirements', NULL, '164.308(a)(2)', '{"colorado": "SB 21-169 Sec 3", "connecticut": "SB 1103 Sec 2"}', 'LD.04.04.01',
 '["critical","high","moderate","low"]', 'Organizational', 'Form committee with quarterly meetings minimum. Document charter with scope, authority, and escalation paths.', 'Committee charter, meeting minutes, membership roster'),

('c002', 'GOV-2', 'Govern', 'AI Governance Policy Framework',
 'Develop and maintain comprehensive AI governance policies including acceptable use, risk assessment, procurement, and lifecycle management policies.',
 'GOVERN 1.2', 'Design Controls', NULL, '164.316(a)', '{"colorado": "SB 21-169 Sec 4", "california": "AB-2013"}', NULL,
 '["critical","high","moderate","low"]', 'Policy', 'Create foundational policy set reviewed annually. Align with NIST AI RMF governance functions.', 'Published policies, review records, distribution evidence'),

('c003', 'GOV-3', 'Govern', 'Roles and Responsibilities',
 'Define clear roles and responsibilities for AI governance including AI system owners, clinical champions, governance leads, and executive sponsors.',
 'GOVERN 1.3', NULL, NULL, '164.308(a)(2)', '{}', NULL,
 '["critical","high","moderate","low"]', 'Organizational', 'Document RACI matrix for all governance activities. Assign system owners for every AI asset.', 'RACI matrix, role descriptions, assignment records'),

('c004', 'GOV-4', 'Govern', 'Executive Reporting',
 'Establish regular reporting on AI governance activities, risk posture, and compliance status to board and executive leadership.',
 'GOVERN 1.4', NULL, NULL, '164.308(a)(1)(ii)(D)', '{}', 'LD.04.04.05',
 '["critical","high","moderate","low"]', 'Reporting', 'Provide quarterly executive reports and annual board-level AI governance briefings.', 'Executive reports, board presentations, dashboard screenshots'),

('c005', 'GOV-5', 'Govern', 'Budget and Resource Allocation',
 'Allocate dedicated budget and staffing resources for AI governance program operations.',
 'GOVERN 1.5', NULL, NULL, NULL, '{}', NULL,
 '["critical","high","moderate"]', 'Organizational', 'Secure annual budget for governance platform, assessments, training, and staffing.', 'Budget documents, staffing plans'),

('c006', 'GOV-6', 'Govern', 'Training and Awareness',
 'Implement role-based AI governance training program for governance committee members, AI system owners, clinicians, and procurement staff.',
 'GOVERN 4.1', NULL, NULL, '164.308(a)(5)', '{"colorado": "SB 21-169 Sec 5"}', NULL,
 '["critical","high","moderate","low"]', 'Training', 'Deliver annual training with role-specific modules. Track completion rates.', 'Training materials, completion records, assessment results'),

-- ============================================================================
-- MAP FUNCTION - AI system categorization and context mapping
-- ============================================================================
('c010', 'MAP-1', 'Map', 'AI Asset Inventory',
 'Maintain a comprehensive, current registry of all AI and ML systems deployed across the organization including vendor, internal, and embedded AI capabilities.',
 'MAP 1.1', 'Device Registration', 'HTI-1 §170.315(b)(11)', '164.310(d)(1)', '{"connecticut": "SB 1103 Sec 3"}', NULL,
 '["critical","high","moderate","low"]', 'Inventory', 'Conduct quarterly inventory reviews. Include embedded vendor AI in EHR systems.', 'AI asset registry, quarterly review records'),

('c011', 'MAP-2', 'Map', 'Risk Tier Classification',
 'Classify all AI systems into risk tiers (critical, high, moderate, low) based on patient safety impact, clinical influence, PHI access, and regulatory classification.',
 'MAP 1.2', 'Risk Classification', NULL, NULL, '{"colorado": "SB 21-169 Sec 3(b)"}', NULL,
 '["critical","high","moderate","low"]', 'Classification', 'Apply tiered classification using multi-dimensional risk scoring. Document rationale for each classification.', 'Classification criteria, individual asset classifications'),

('c012', 'MAP-3', 'Map', 'Data Source Documentation',
 'Document all data sources consumed by each AI system including EHR data, imaging, claims, and external data feeds. Map PHI data flows.',
 'MAP 2.1', NULL, 'HTI-1 §170.315(b)(11)(ii)', '164.308(a)(1)(ii)(A)', '{}', NULL,
 '["critical","high","moderate"]', 'Data Governance', 'Create data flow diagrams for each AI system. Identify all PHI touchpoints.', 'Data flow diagrams, data source inventories'),

('c013', 'MAP-4', 'Map', 'Regulatory Mapping',
 'Map applicable federal, state, and accreditation requirements to each AI system based on its classification, function, and deployment context.',
 'MAP 3.1', 'Regulatory Requirements', 'HTI-1 §170.315(b)(11)', '164.308(a)(1)(ii)(B)', '{"colorado": "SB 21-169", "california": "AB-2013"}', NULL,
 '["critical","high","moderate","low"]', 'Compliance', 'Maintain regulatory crosswalk updated with each new regulation. Map at both portfolio and individual system level.', 'Regulatory crosswalk matrix, per-system regulatory profiles'),

('c014', 'MAP-5', 'Map', 'Intended Use Documentation',
 'Document the intended use, target population, clinical context, and known limitations for each AI system per ONC HTI-1 transparency requirements.',
 'MAP 2.2', 'Indications for Use', 'HTI-1 §170.315(b)(11)(iii)', NULL, '{}', NULL,
 '["critical","high","moderate"]', 'Documentation', 'Obtain and review vendor-provided intended use statements. Document local use cases.', 'Intended use statements, limitation documentation'),

-- ============================================================================
-- MEASURE FUNCTION - Risk assessment and performance measurement
-- ============================================================================
('c020', 'MEA-1', 'Measure', 'Pre-Deployment Risk Assessment',
 'Conduct structured multi-dimensional risk assessment before any new AI system deployment. Assess patient safety, bias, privacy, clinical validity, cybersecurity, and regulatory dimensions.',
 'MEASURE 1.1', 'Clinical Evaluation', 'HTI-1 §170.315(b)(11)(iv)', '164.308(a)(1)(ii)(A)', '{"colorado": "SB 21-169 Sec 4(a)"}', NULL,
 '["critical","high","moderate"]', 'Risk Assessment', 'Use standardized risk assessment template scoring each dimension 1-5. Require governance committee approval for high/critical systems.', 'Completed risk assessments, approval records'),

('c021', 'MEA-2', 'Measure', 'Algorithmic Impact Assessment',
 'Conduct algorithmic impact assessments evaluating bias across protected demographic categories including race, ethnicity, gender, age, and socioeconomic status.',
 'MEASURE 2.1', 'Performance Testing', 'HTI-1 §170.315(b)(11)(v)', NULL, '{"colorado": "SB 21-169 Sec 4(b)", "nyc": "Local Law 144"}', NULL,
 '["critical","high"]', 'Bias & Fairness', 'Test disaggregated performance across demographics. Calculate disparate impact ratios. Require remediation when ratio falls below 0.8.', 'AIA reports, demographic performance data, remediation plans'),

('c022', 'MEA-3', 'Measure', 'Performance Baseline Establishment',
 'Establish and document baseline performance metrics for each AI system including accuracy, precision, recall, F1, and AUC-ROC using local patient population data.',
 'MEASURE 2.2', 'Analytical Validation', 'HTI-1 §170.315(b)(11)(iv)', NULL, '{}', NULL,
 '["critical","high","moderate"]', 'Validation', 'Validate vendor-reported performance with local data. Document any performance gaps.', 'Baseline performance reports, local validation studies'),

('c023', 'MEA-4', 'Measure', 'Continuous Performance Monitoring',
 'Implement continuous monitoring of deployed AI systems tracking accuracy, precision, bias indicators, and drift metrics against established baselines.',
 'MEASURE 2.3', 'Post-Market Surveillance', NULL, NULL, '{}', NULL,
 '["critical","high","moderate"]', 'Monitoring', 'Deploy automated monitoring dashboards. Set alerting thresholds. Review metrics monthly for high-risk systems.', 'Monitoring dashboards, alert configurations, monthly reports'),

('c024', 'MEA-5', 'Measure', 'Drift Detection and Response',
 'Implement model drift detection capabilities and define response procedures when AI system performance degrades below acceptable thresholds.',
 'MEASURE 3.1', 'Change Control', NULL, NULL, '{}', NULL,
 '["critical","high"]', 'Monitoring', 'Monitor data drift and concept drift. Define threshold boundaries and escalation procedures.', 'Drift detection configurations, response procedures, incident records'),

('c025', 'MEA-6', 'Measure', 'Periodic Risk Reassessment',
 'Conduct periodic risk reassessments for all deployed AI systems on a schedule determined by risk tier: annually for low, semi-annually for moderate, quarterly for high/critical.',
 'MEASURE 1.2', 'Periodic Review', NULL, '164.308(a)(8)', '{}', NULL,
 '["critical","high","moderate","low"]', 'Risk Assessment', 'Maintain reassessment schedule. Document any risk tier changes and triggering factors.', 'Reassessment schedule, completed periodic assessments'),

-- ============================================================================
-- MANAGE FUNCTION - Risk mitigation and ongoing management
-- ============================================================================
('c030', 'MAN-1', 'Manage', 'Vendor AI Due Diligence',
 'Conduct AI-specific vendor due diligence assessing training data provenance, bias testing results, model update practices, security controls, and contractual provisions.',
 'MANAGE 1.1', 'Supplier Controls', NULL, '164.308(b)(1)', '{}', NULL,
 '["critical","high","moderate"]', 'Vendor Management', 'Use standardized vendor questionnaire. Score vendors across 5 dimensions. Require minimum thresholds for approval.', 'Vendor assessments, questionnaire responses, scoring records'),

('c031', 'MAN-2', 'Manage', 'Change Control for AI Updates',
 'Implement change control processes for AI system updates, retraining events, and version changes. Require re-validation proportional to change significance.',
 'MANAGE 2.1', 'Change Control Plan', NULL, NULL, '{}', NULL,
 '["critical","high","moderate"]', 'Lifecycle', 'Document all AI system changes. Require regression testing for updates to high-risk systems.', 'Change control records, re-validation reports, approval records'),

('c032', 'MAN-3', 'Manage', 'Incident Response for AI',
 'Define and implement AI-specific incident response procedures covering patient safety events, bias detection, performance failures, and regulatory violations.',
 'MANAGE 3.1', 'Complaint Handling', NULL, '164.308(a)(6)', '{}', 'PI.01.01.01',
 '["critical","high","moderate","low"]', 'Incident Response', 'Integrate AI incidents into existing incident management. Define severity levels and auto-suspension criteria for critical patient safety events.', 'IR procedures, incident records, post-incident reports'),

('c033', 'MAN-4', 'Manage', 'Remediation Management',
 'Establish and track remediation plans for identified governance gaps, failed assessments, and compliance deficiencies with defined timelines and accountability.',
 'MANAGE 4.1', 'CAPA', NULL, '164.308(a)(1)(ii)(D)', '{}', NULL,
 '["critical","high","moderate","low"]', 'Remediation', 'Track all remediation actions to closure. Escalate overdue items to governance committee.', 'Remediation plans, tracking records, closure evidence'),

('c034', 'MAN-5', 'Manage', 'Decommissioning Procedures',
 'Define procedures for safe decommissioning of AI systems including transition planning, data retention, workflow impact assessment, and stakeholder notification.',
 'MANAGE 2.2', NULL, NULL, '164.310(d)(2)', '{}', NULL,
 '["critical","high","moderate"]', 'Lifecycle', 'Create decommissioning checklist. Ensure clinical workflows have alternatives before removing AI tools.', 'Decommissioning plans, transition records, notification logs'),

('c035', 'MAN-6', 'Manage', 'Transparency and Explainability',
 'Implement transparency controls ensuring clinicians understand AI outputs, patients are notified when AI influences care, and regulators receive required documentation.',
 'MANAGE 4.2', 'Labeling', 'HTI-1 §170.315(b)(11)(i)', NULL, '{"colorado": "SB 21-169 Sec 6", "california": "AB-2013 Sec 3"}', NULL,
 '["critical","high"]', 'Transparency', 'Provide clinician-facing explanations proportional to risk tier. Document patient notification approach.', 'Explainability documentation, notification records, clinician training materials'),

('c036', 'MAN-7', 'Manage', 'Audit Trail and Documentation',
 'Maintain comprehensive audit trails for all AI governance activities supporting regulatory compliance, accountability, and defensibility.',
 'MANAGE 4.3', 'Record Keeping', NULL, '164.312(b)', '{}', NULL,
 '["critical","high","moderate","low"]', 'Audit', 'Log all governance actions with immutable timestamps. Retain records per regulatory requirements (minimum 6 years for HIPAA).', 'Audit log exports, retention policy, access records'),

('c037', 'MAN-8', 'Manage', 'Data Privacy Controls for AI',
 'Implement and verify data privacy controls for AI systems that access PHI including data minimization, de-identification, access controls, and BAA coverage.',
 'MANAGE 1.2', NULL, NULL, '164.502(b)', '{}', NULL,
 '["critical","high","moderate"]', 'Privacy', 'Ensure all AI vendors with PHI access have BAAs. Implement minimum necessary standard for AI data access.', 'BAAs, data access records, privacy impact assessments'),

('c038', 'MAN-9', 'Manage', 'Clinical Integration Governance',
 'Govern the integration of AI outputs into clinical workflows ensuring appropriate human oversight, override capabilities, and clinical decision authority.',
 'MANAGE 3.2', 'Clinical Workflow', NULL, NULL, '{}', 'PC.01.02.07',
 '["critical","high"]', 'Clinical', 'Ensure all clinical AI has human override capability. Document workflow integration and clinical authority boundaries.', 'Workflow documentation, override capability testing, clinical authority guidelines');
