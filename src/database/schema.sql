-- ============================================================================
-- ForgeAI Govern™ - Healthcare AI Governance Platform
-- Database Schema v1.0
-- Aligned with: NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, State AI Laws
-- ============================================================================

-- Enable WAL mode for better concurrent read performance
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

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
