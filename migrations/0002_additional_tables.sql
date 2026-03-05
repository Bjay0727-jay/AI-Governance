-- ============================================================================
-- ForgeAI Govern™ - Migration 0002: Additional Tables
-- Evidence, Support Tickets, Feature Requests, Notifications, Training
-- ============================================================================

-- ============================================================================
-- EVIDENCE - Audit evidence attachments linked to governance entities
-- ============================================================================
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence_type TEXT NOT NULL DEFAULT 'document',
    url TEXT,
    uploaded_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant ON evidence(tenant_id);

-- ============================================================================
-- SUPPORT TICKETS - In-platform support requests
-- ============================================================================
CREATE TABLE IF NOT EXISTS support_tickets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL REFERENCES users(id),
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    priority TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    admin_notes TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tickets_tenant ON support_tickets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_tickets_created_by ON support_tickets(created_by);

-- ============================================================================
-- FEATURE REQUESTS & VOTES - Community feature voting
-- ============================================================================
CREATE TABLE IF NOT EXISTS feature_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    status TEXT NOT NULL DEFAULT 'submitted',
    vote_count INTEGER NOT NULL DEFAULT 0,
    admin_response TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_feature_requests_tenant ON feature_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feature_requests_status ON feature_requests(status);

CREATE TABLE IF NOT EXISTS feature_request_votes (
    id TEXT PRIMARY KEY,
    feature_request_id TEXT NOT NULL REFERENCES feature_requests(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(feature_request_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_votes_request ON feature_request_votes(feature_request_id);
CREATE INDEX IF NOT EXISTS idx_votes_user ON feature_request_votes(user_id);

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
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read);
CREATE INDEX IF NOT EXISTS idx_notif_tenant ON notifications(tenant_id);

-- ============================================================================
-- TRAINING - Compliance training modules and completion tracking
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
CREATE INDEX IF NOT EXISTS idx_training_completions_user ON training_completions(user_id);
CREATE INDEX IF NOT EXISTS idx_training_completions_module ON training_completions(module_id);
