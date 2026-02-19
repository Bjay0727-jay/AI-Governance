-- ============================================================================
-- ForgeAI Govern™ - Healthcare AI Governance Platform
-- Initial Migration v1.0
-- Aligned with: NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, State AI Laws
-- ============================================================================

-- ============================================================================
-- TENANTS - Healthcare organizations using the platform
-- ============================================================================
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    plan TEXT NOT NULL DEFAULT 'trial' CHECK (plan IN ('trial', 'starter', 'professional', 'enterprise')),
    settings TEXT DEFAULT '{}',  -- JSON: org-specific config
    hipaa_baa_signed INTEGER NOT NULL DEFAULT 0,
    data_residency TEXT NOT NULL DEFAULT 'us',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'inactive')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);

-- ============================================================================
-- USERS - Multi-role accounts with tenant-scoped access
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,  -- PBKDF2-SHA256, 100k iterations
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'governance_lead', 'reviewer', 'viewer')),
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret TEXT,  -- TOTP secret (encrypted at rest)
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_login TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'locked', 'deactivated')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(tenant_id, email);
CREATE INDEX idx_users_role ON users(tenant_id, role);

-- ============================================================================
-- AI ASSETS - Central registry of all AI/ML systems
-- ============================================================================
CREATE TABLE IF NOT EXISTS ai_assets (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    vendor TEXT,
    version TEXT,
    category TEXT NOT NULL CHECK (category IN (
        'clinical_decision_support', 'diagnostic_imaging', 'predictive_analytics',
        'nlp_extraction', 'operational', 'administrative', 'revenue_cycle', 'other'
    )),
    risk_tier TEXT NOT NULL DEFAULT 'moderate' CHECK (risk_tier IN ('critical', 'high', 'moderate', 'low')),
    fda_classification TEXT,  -- e.g., '510(k)', 'De Novo', 'PMA', 'None'
    fda_clearance_number TEXT,
    data_sources TEXT DEFAULT '[]',  -- JSON array: EHR, imaging, claims, etc.
    phi_access INTEGER NOT NULL DEFAULT 0,
    phi_data_types TEXT DEFAULT '[]',  -- JSON array: demographics, diagnoses, medications, etc.
    deployment_status TEXT NOT NULL DEFAULT 'proposed' CHECK (deployment_status IN (
        'proposed', 'validating', 'deployed', 'monitoring', 'suspended', 'decommissioned'
    )),
    deployment_date TEXT,
    owner_user_id TEXT REFERENCES users(id),
    clinical_champion_id TEXT REFERENCES users(id),
    department TEXT,
    description TEXT,
    intended_use TEXT,
    known_limitations TEXT,
    training_data_description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_ai_assets_tenant ON ai_assets(tenant_id);
CREATE INDEX idx_ai_assets_risk ON ai_assets(tenant_id, risk_tier);
CREATE INDEX idx_ai_assets_status ON ai_assets(tenant_id, deployment_status);
CREATE INDEX idx_ai_assets_category ON ai_assets(tenant_id, category);
CREATE INDEX idx_ai_assets_owner ON ai_assets(owner_user_id);

-- ============================================================================
-- RISK ASSESSMENTS - Structured multi-dimensional risk evaluation
-- ============================================================================
CREATE TABLE IF NOT EXISTS risk_assessments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ai_asset_id TEXT NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
    assessment_type TEXT NOT NULL CHECK (assessment_type IN (
        'initial', 'periodic', 'triggered', 'pre_deployment'
    )),
    assessor_id TEXT NOT NULL REFERENCES users(id),
    -- Risk dimension scores (1-5 scale)
    patient_safety_score INTEGER CHECK (patient_safety_score BETWEEN 1 AND 5),
    bias_fairness_score INTEGER CHECK (bias_fairness_score BETWEEN 1 AND 5),
    data_privacy_score INTEGER CHECK (data_privacy_score BETWEEN 1 AND 5),
    clinical_validity_score INTEGER CHECK (clinical_validity_score BETWEEN 1 AND 5),
    cybersecurity_score INTEGER CHECK (cybersecurity_score BETWEEN 1 AND 5),
    regulatory_score INTEGER CHECK (regulatory_score BETWEEN 1 AND 5),
    -- Computed overall risk
    overall_risk_level TEXT CHECK (overall_risk_level IN ('critical', 'high', 'moderate', 'low')),
    findings TEXT DEFAULT '{}',  -- JSON: detailed findings per dimension
    recommendations TEXT,
    mitigation_plan TEXT,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'in_review', 'approved', 'rejected')),
    approved_by TEXT REFERENCES users(id),
    review_notes TEXT,
    completed_at TEXT,
    next_review_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_risk_assessments_tenant ON risk_assessments(tenant_id);
CREATE INDEX idx_risk_assessments_asset ON risk_assessments(ai_asset_id);
CREATE INDEX idx_risk_assessments_status ON risk_assessments(tenant_id, status);

-- ============================================================================
-- ALGORITHMIC IMPACT ASSESSMENTS - Bias and fairness evaluations
-- ============================================================================
CREATE TABLE IF NOT EXISTS impact_assessments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ai_asset_id TEXT NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
    assessor_id TEXT NOT NULL REFERENCES users(id),
    assessment_period TEXT,  -- e.g., 'Q1 2025'
    -- Demographic testing
    demographic_groups_tested TEXT DEFAULT '[]',  -- JSON: race, ethnicity, gender, age, SES
    performance_by_group TEXT DEFAULT '{}',  -- JSON: disaggregated metrics per group
    -- Bias indicators
    bias_indicators TEXT DEFAULT '{}',  -- JSON: statistical parity, equal opportunity, etc.
    disparate_impact_ratio REAL,  -- < 0.8 indicates potential disparate impact
    -- Drift detection
    drift_detected INTEGER NOT NULL DEFAULT 0,
    drift_details TEXT DEFAULT '{}',  -- JSON: drift analysis
    drift_score REAL,
    -- Clinical outcomes
    clinical_outcomes TEXT DEFAULT '{}',  -- JSON: outcome correlation data
    -- Remediation
    remediation_required INTEGER NOT NULL DEFAULT 0,
    remediation_plan TEXT,
    remediation_status TEXT CHECK (remediation_status IN ('not_needed', 'planned', 'in_progress', 'completed')),
    -- Status
    status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN (
        'scheduled', 'in_progress', 'completed', 'overdue'
    )),
    completed_at TEXT,
    next_assessment_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_impact_assessments_tenant ON impact_assessments(tenant_id);
CREATE INDEX idx_impact_assessments_asset ON impact_assessments(ai_asset_id);
CREATE INDEX idx_impact_assessments_status ON impact_assessments(tenant_id, status);

-- ============================================================================
-- COMPLIANCE CONTROLS - Multi-framework governance control catalog
-- ============================================================================
CREATE TABLE IF NOT EXISTS compliance_controls (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    control_id TEXT NOT NULL UNIQUE,  -- e.g., 'GOV-1', 'MAP-2.1'
    family TEXT NOT NULL CHECK (family IN ('Govern', 'Map', 'Measure', 'Manage')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    -- Cross-framework mappings
    nist_ai_rmf_ref TEXT,
    fda_samd_ref TEXT,
    onc_hti1_ref TEXT,
    hipaa_ref TEXT,
    state_law_refs TEXT DEFAULT '{}',  -- JSON: state -> regulation mapping
    joint_commission_ref TEXT,
    -- Applicability
    risk_tiers TEXT DEFAULT '["critical","high","moderate","low"]',  -- JSON array
    category TEXT,
    guidance TEXT,  -- Implementation guidance
    evidence_requirements TEXT,  -- What evidence satisfies this control
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_controls_family ON compliance_controls(family);
CREATE INDEX idx_controls_control_id ON compliance_controls(control_id);

-- ============================================================================
-- CONTROL IMPLEMENTATIONS - Per-tenant, per-asset control status
-- ============================================================================
CREATE TABLE IF NOT EXISTS control_implementations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ai_asset_id TEXT REFERENCES ai_assets(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL REFERENCES compliance_controls(id),
    implementation_status TEXT NOT NULL DEFAULT 'planned' CHECK (implementation_status IN (
        'implemented', 'partially_implemented', 'planned', 'not_applicable'
    )),
    implementation_details TEXT,
    evidence_ids TEXT DEFAULT '[]',  -- JSON: R2 object references
    responsible_party TEXT REFERENCES users(id),
    last_reviewed TEXT,
    next_review TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tenant_id, ai_asset_id, control_id)
);

CREATE INDEX idx_implementations_tenant ON control_implementations(tenant_id);
CREATE INDEX idx_implementations_asset ON control_implementations(ai_asset_id);
CREATE INDEX idx_implementations_status ON control_implementations(tenant_id, implementation_status);

-- ============================================================================
-- VENDOR ASSESSMENTS - Third-party AI due diligence
-- ============================================================================
CREATE TABLE IF NOT EXISTS vendor_assessments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vendor_name TEXT NOT NULL,
    product_name TEXT NOT NULL,
    ai_asset_id TEXT REFERENCES ai_assets(id),
    -- Assessment dimensions
    training_data_provenance TEXT,
    training_data_representativeness TEXT,
    bias_testing_results TEXT DEFAULT '{}',  -- JSON
    validation_methodology TEXT,
    model_update_practices TEXT,
    data_security_controls TEXT DEFAULT '{}',  -- JSON
    privacy_controls TEXT DEFAULT '{}',  -- JSON
    contractual_provisions TEXT DEFAULT '{}',  -- JSON: audit rights, SLAs, performance guarantees
    incident_response_capability TEXT,
    -- Scoring
    transparency_score INTEGER CHECK (transparency_score BETWEEN 1 AND 5),
    bias_testing_score INTEGER CHECK (bias_testing_score BETWEEN 1 AND 5),
    security_score INTEGER CHECK (security_score BETWEEN 1 AND 5),
    data_practices_score INTEGER CHECK (data_practices_score BETWEEN 1 AND 5),
    contractual_score INTEGER CHECK (contractual_score BETWEEN 1 AND 5),
    overall_risk_score INTEGER CHECK (overall_risk_score BETWEEN 1 AND 100),
    -- Decision
    recommendation TEXT CHECK (recommendation IN ('approved', 'conditional', 'rejected', 'pending')),
    conditions TEXT,  -- If conditional, what must be met
    assessed_by TEXT REFERENCES users(id),
    assessed_at TEXT,
    next_reassessment TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_vendor_assessments_tenant ON vendor_assessments(tenant_id);
CREATE INDEX idx_vendor_assessments_vendor ON vendor_assessments(tenant_id, vendor_name);

-- ============================================================================
-- MONITORING METRICS - Time-series AI performance and bias data
-- ============================================================================
CREATE TABLE IF NOT EXISTS monitoring_metrics (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ai_asset_id TEXT NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
    metric_type TEXT NOT NULL CHECK (metric_type IN (
        'accuracy', 'precision', 'recall', 'f1_score', 'auc_roc',
        'bias_index', 'drift_score', 'false_positive_rate', 'false_negative_rate',
        'disparate_impact', 'latency', 'availability', 'error_rate'
    )),
    metric_value REAL NOT NULL,
    threshold_min REAL,
    threshold_max REAL,
    alert_triggered INTEGER NOT NULL DEFAULT 0,
    alert_severity TEXT CHECK (alert_severity IN ('info', 'warning', 'critical')),
    demographic_group TEXT,  -- If bias metric, which group
    metadata TEXT DEFAULT '{}',  -- JSON: additional context
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_metrics_tenant_asset ON monitoring_metrics(tenant_id, ai_asset_id);
CREATE INDEX idx_metrics_type ON monitoring_metrics(ai_asset_id, metric_type);
CREATE INDEX idx_metrics_time ON monitoring_metrics(ai_asset_id, recorded_at);
CREATE INDEX idx_metrics_alerts ON monitoring_metrics(tenant_id, alert_triggered);

-- ============================================================================
-- GOVERNANCE MATURITY ASSESSMENTS - 7-domain maturity scoring
-- ============================================================================
CREATE TABLE IF NOT EXISTS maturity_assessments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessor_id TEXT NOT NULL REFERENCES users(id),
    assessment_date TEXT NOT NULL DEFAULT (datetime('now')),
    -- Domain scores (1-5 maturity levels)
    governance_structure_score INTEGER CHECK (governance_structure_score BETWEEN 1 AND 5),
    ai_inventory_score INTEGER CHECK (ai_inventory_score BETWEEN 1 AND 5),
    risk_assessment_score INTEGER CHECK (risk_assessment_score BETWEEN 1 AND 5),
    policy_compliance_score INTEGER CHECK (policy_compliance_score BETWEEN 1 AND 5),
    monitoring_performance_score INTEGER CHECK (monitoring_performance_score BETWEEN 1 AND 5),
    vendor_management_score INTEGER CHECK (vendor_management_score BETWEEN 1 AND 5),
    transparency_score INTEGER CHECK (transparency_score BETWEEN 1 AND 5),
    -- Overall
    overall_maturity_score REAL,  -- Weighted average
    -- Detailed findings per domain
    domain_findings TEXT DEFAULT '{}',  -- JSON
    -- Recommendations
    immediate_actions TEXT DEFAULT '[]',  -- JSON: 30-day actions
    near_term_actions TEXT DEFAULT '[]',  -- JSON: 60-90 day actions
    strategic_actions TEXT DEFAULT '[]',  -- JSON: 6-12 month actions
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'final', 'archived')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_maturity_tenant ON maturity_assessments(tenant_id);

-- ============================================================================
-- AUDIT LOG - Immutable audit trail for all governance activities
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,  -- create, update, approve, reject, delete, login, etc.
    entity_type TEXT NOT NULL,  -- ai_asset, risk_assessment, etc.
    entity_id TEXT,
    details TEXT DEFAULT '{}',  -- JSON: before/after values
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_time ON audit_log(tenant_id, created_at);

-- ============================================================================
-- INCIDENTS - AI-related incident tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ai_asset_id TEXT NOT NULL REFERENCES ai_assets(id),
    reported_by TEXT NOT NULL REFERENCES users(id),
    incident_type TEXT NOT NULL CHECK (incident_type IN (
        'patient_safety', 'bias_detected', 'performance_degradation',
        'data_breach', 'model_failure', 'regulatory_violation', 'other'
    )),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'moderate', 'low')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    patient_impact INTEGER NOT NULL DEFAULT 0,
    root_cause TEXT,
    corrective_actions TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
        'open', 'investigating', 'mitigating', 'resolved', 'closed'
    )),
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_incidents_tenant ON incidents(tenant_id);
CREATE INDEX idx_incidents_asset ON incidents(ai_asset_id);
CREATE INDEX idx_incidents_status ON incidents(tenant_id, status);
CREATE INDEX idx_incidents_severity ON incidents(tenant_id, severity);

-- ============================================================================
-- EVIDENCE - Documentation and evidence linked to governance entities
-- ============================================================================
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,  -- ai_asset, risk_assessment, impact_assessment, vendor_assessment, control_implementation
    entity_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence_type TEXT NOT NULL DEFAULT 'document' CHECK (evidence_type IN (
        'document', 'link', 'screenshot', 'test_result', 'policy', 'audit_report', 'certification', 'other'
    )),
    url TEXT,
    uploaded_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_evidence_entity ON evidence(entity_type, entity_id);
CREATE INDEX idx_evidence_tenant ON evidence(tenant_id);

-- ============================================================================
-- SUPPORT TICKETS - Customer self-service portal
-- ============================================================================
CREATE TABLE IF NOT EXISTS support_tickets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL REFERENCES users(id),
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general' CHECK (category IN (
        'general', 'technical', 'compliance', 'billing', 'feature_request', 'bug_report'
    )),
    priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
        'open', 'in_progress', 'waiting', 'resolved', 'closed'
    )),
    admin_notes TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_tickets_tenant ON support_tickets(tenant_id);
CREATE INDEX idx_tickets_status ON support_tickets(tenant_id, status);
CREATE INDEX idx_tickets_created_by ON support_tickets(created_by);

-- ============================================================================
-- FEATURE REQUESTS - Community feedback and voting
-- ============================================================================
CREATE TABLE IF NOT EXISTS feature_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general' CHECK (category IN (
        'governance', 'compliance', 'reporting', 'monitoring', 'integration', 'general'
    )),
    status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN (
        'submitted', 'under_review', 'planned', 'in_progress', 'completed', 'declined'
    )),
    vote_count INTEGER NOT NULL DEFAULT 0,
    admin_response TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_feature_requests_tenant ON feature_requests(tenant_id);
CREATE INDEX idx_feature_requests_status ON feature_requests(status);

-- ============================================================================
-- FEATURE REQUEST VOTES - Track user votes on feature requests
-- ============================================================================
CREATE TABLE IF NOT EXISTS feature_request_votes (
    id TEXT PRIMARY KEY,
    feature_request_id TEXT NOT NULL REFERENCES feature_requests(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(feature_request_id, user_id)
);

CREATE INDEX idx_votes_request ON feature_request_votes(feature_request_id);
CREATE INDEX idx_votes_user ON feature_request_votes(user_id);

-- ============================================================================
-- NOTIFICATIONS - In-app notification system
-- ============================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    type TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_notif_user ON notifications(user_id, read);
CREATE INDEX idx_notif_tenant ON notifications(tenant_id);

-- ============================================================================
-- TRAINING - Employee training modules and completion tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS training_modules (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    target_roles TEXT DEFAULT '[]',
    content TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 30,
    passing_score INTEGER NOT NULL DEFAULT 80,
    sort_order INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS training_completions (
    id TEXT PRIMARY KEY,
    module_id TEXT NOT NULL REFERENCES training_modules(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    score INTEGER,
    status TEXT NOT NULL DEFAULT 'completed',
    completed_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(module_id, user_id)
);

CREATE INDEX idx_training_completions_user ON training_completions(user_id);
CREATE INDEX idx_training_completions_module ON training_completions(module_id);

-- ============================================================================
-- SEED DATA: Compliance Control Catalog
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

-- ============================================================================
-- SEED DATA: Training Modules
-- ============================================================================

-- Training Modules Seed Data
INSERT INTO training_modules (id, title, description, category, target_roles, content, duration_minutes, passing_score, sort_order) VALUES
('tm-platform-basics', 'ForgeAI Govern Platform Basics', 'Introduction to the platform interface, navigation, and core concepts.', 'platform', '["admin","governance_lead","reviewer","viewer"]', 'This module covers:\n\n1. Platform Overview: ForgeAI Govern is a healthcare AI governance platform.\n2. Navigation: sidebar access to all modules.\n3. Roles: Admin, Governance Lead, Reviewer, Viewer.\n4. Key Workflows: Register > Assess > Map > Monitor > Report.', 15, 80, 1),
('tm-risk-assessment', 'Conducting AI Risk Assessments', 'Learn the 6-dimension weighted risk scoring methodology for healthcare AI systems.', 'governance', '["admin","governance_lead","reviewer"]', 'This module covers the ForgeAI 6-dimension risk model:\n\n1. Patient Safety (25%)\n2. Bias and Fairness (20%)\n3. Data Privacy (15%)\n4. Clinical Validity (15%)\n5. Cybersecurity (15%)\n6. Regulatory (10%)', 30, 80, 2),
('tm-compliance-mapping', 'Compliance Control Mapping', 'Map and implement controls across NIST AI RMF, FDA SaMD, ONC HTI-1, and HIPAA.', 'compliance', '["admin","governance_lead","reviewer"]', 'This module covers compliance mapping across 4 frameworks with 39 controls.', 45, 80, 3),
('tm-vendor-diligence', 'AI Vendor Due Diligence', 'Evaluate third-party AI vendors using the 5-dimension scoring framework.', 'governance', '["admin","governance_lead"]', 'Vendor assessment dimensions: Transparency, Bias Testing, Security, Data Practices, Contractual.', 30, 80, 4),
('tm-incident-response', 'AI Incident Response', 'Procedures for reporting, investigating, and resolving AI-related incidents.', 'governance', '["admin","governance_lead","reviewer"]', 'Incident response procedure: Report, Investigate, Remediate, Resolve, Update.', 20, 80, 5),
('tm-hipaa-ai', 'HIPAA Compliance for AI Systems', 'Essential HIPAA requirements when AI systems access Protected Health Information.', 'regulatory', '["admin","governance_lead","reviewer","viewer"]', 'HIPAA requirements for AI: Privacy Rule, Security Rule, Breach Notification, BAAs, Risk Analysis.', 25, 80, 6);
