-- ============================================================================
-- ForgeAI Govern™ - Evidence, Audit, and Compliance Enhancements
-- Migration 0003: R2 file upload support, audit hash chaining, state law controls
-- ============================================================================

-- Add file storage columns to evidence table for R2-backed uploads
ALTER TABLE evidence ADD COLUMN file_key TEXT;           -- R2 object key
ALTER TABLE evidence ADD COLUMN file_name TEXT;          -- Original filename
ALTER TABLE evidence ADD COLUMN file_size INTEGER;       -- Size in bytes
ALTER TABLE evidence ADD COLUMN file_type TEXT;          -- MIME type
ALTER TABLE evidence ADD COLUMN sha256_hash TEXT;        -- Content-addressable integrity hash
ALTER TABLE evidence ADD COLUMN retention_expires_at TEXT; -- Configurable retention TTL

-- Add hash chaining columns to audit_log for tamper-proofing
ALTER TABLE audit_log ADD COLUMN previous_hash TEXT;     -- SHA-256 of prior entry
ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;        -- SHA-256 of this entry (id + action + entity + details + previous_hash)
ALTER TABLE audit_log ADD COLUMN data_classification TEXT DEFAULT 'standard'; -- standard, phi, sensitive

-- Add BAA acknowledgment tracking to tenants
ALTER TABLE tenants ADD COLUMN hipaa_baa_signed_at TEXT;
ALTER TABLE tenants ADD COLUMN hipaa_baa_signed_by TEXT;

-- ============================================================================
-- State Law Controls - Colorado, California, Connecticut, NYC, Illinois
-- ============================================================================
INSERT INTO compliance_controls (id, control_id, family, title, description, nist_ai_rmf_ref, fda_samd_ref, onc_hti1_ref, hipaa_ref, state_law_refs, joint_commission_ref, risk_tiers, category, guidance, evidence_requirements)
VALUES
('c040', 'STATE-1', 'Govern', 'Colorado AI Act Compliance',
 'Implement requirements of Colorado SB 21-169 including algorithmic impact assessments, bias testing, consumer notification, and governance documentation for high-risk AI systems.',
 'GOVERN 1.2', NULL, NULL, NULL, '{"colorado": "SB 21-169 Sec 3-7"}', NULL,
 '["critical","high"]', 'State Compliance', 'Identify all AI systems subject to Colorado AI Act. Conduct required impact assessments and maintain documentation. Implement consumer notification procedures.', 'Impact assessment reports, consumer notification records, governance documentation'),

('c041', 'STATE-2', 'Govern', 'California AI Transparency',
 'Comply with California AI transparency requirements (AB-2013) including automated decision-making disclosures, transparency reports, and consumer rights procedures.',
 'MANAGE 4.2', NULL, NULL, NULL, '{"california": "AB-2013 Sec 2-4"}', NULL,
 '["critical","high","moderate"]', 'State Compliance', 'Document AI decision-making processes. Provide required disclosures. Maintain transparency reports as specified by regulation.', 'Transparency reports, disclosure records, consumer notification logs'),

('c042', 'STATE-3', 'Govern', 'Connecticut AI Inventory Requirements',
 'Comply with Connecticut SB 1103 inventory and impact assessment requirements for automated systems used in consequential decisions.',
 'MAP 1.1', NULL, NULL, NULL, '{"connecticut": "SB 1103 Sec 2-4"}', NULL,
 '["critical","high","moderate"]', 'State Compliance', 'Maintain complete AI system inventory per Connecticut requirements. Conduct impact assessments for systems making consequential decisions.', 'AI inventory reports, impact assessments, compliance documentation'),

('c043', 'STATE-4', 'Manage', 'NYC Local Law 144 Bias Audits',
 'Conduct annual bias audits for automated employment decision tools as required by NYC Local Law 144. Publish audit results and provide required notices.',
 'MEASURE 2.1', NULL, NULL, NULL, '{"nyc": "Local Law 144 Sec 1-5"}', NULL,
 '["critical","high"]', 'State Compliance', 'Engage independent auditor for annual bias audit. Publish summary results on public website. Provide candidate/employee notices.', 'Annual bias audit reports, publication evidence, notice records'),

('c044', 'STATE-5', 'Manage', 'Illinois AI Video Interview Act',
 'Comply with Illinois AI Video Interview Act requirements including obtaining consent, providing explanations, and limiting data retention for AI-analyzed video interviews.',
 NULL, NULL, NULL, NULL, '{"illinois": "AIVI Act Sec 5-20"}', NULL,
 '["critical","high"]', 'State Compliance', 'Obtain informed consent before AI analysis. Provide explanation of AI use. Implement data retention limits (30 days without consent).', 'Consent records, explanation documentation, data retention logs'),

('c045', 'STATE-6', 'Govern', 'Multi-State Jurisdiction Management',
 'Maintain jurisdiction tracking to identify which state AI regulations apply based on organizational operating locations and affected populations.',
 'MAP 3.1', NULL, NULL, NULL, '{"colorado": "SB 21-169", "california": "AB-2013", "connecticut": "SB 1103", "illinois": "AIVI Act", "nyc": "Local Law 144"}', NULL,
 '["critical","high","moderate","low"]', 'State Compliance', 'Map organizational presence to applicable state regulations. Review quarterly for new legislation. Enable/disable state overlays based on jurisdiction.', 'Jurisdiction map, regulatory applicability matrix, quarterly review records');
