/**
 * ForgeAI Govern™ - Local Express Server
 *
 * Thin Express wrapper that delegates all API handling to the shared
 * Workers-compatible Router (src/api/router.js), eliminating code duplication.
 *
 * Usage: npm start
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { createDatabase } = require('./src/local/db-adapter');
const { createRouterMiddleware } = require('./src/shared/express-adapter');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = (() => {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (process.env.NODE_ENV === 'test') return 'test-secret-' + crypto.randomBytes(16).toString('hex');
  // Local development: generate a random secret per-run (not hardcoded, not committed to source)
  const secret = crypto.randomBytes(32).toString('hex');
  console.warn('WARNING: JWT_SECRET not set. Generated ephemeral secret for this session. Set JWT_SECRET env var for production.');
  return secret;
})();

// --- Initialize Database ---
const db = createDatabase();

// Auto-setup schema if tables don't exist
try {
  db.prepare('SELECT 1 FROM tenants LIMIT 1').first();
} catch {
  console.log('First run detected — initializing database...');
  const schema = fs.readFileSync(path.join(__dirname, 'src', 'database', 'schema.sql'), 'utf8');
  if (db.db && typeof db.db.exec === 'function') {
    db.db.exec(schema);
  } else {
    db.exec(schema);
  }

  // Seed compliance controls
  const seed = fs.readFileSync(path.join(__dirname, 'src', 'database', 'seed.sql'), 'utf8');
  try {
    if (db.db && typeof db.db.exec === 'function') {
      db.db.exec(seed);
    } else {
      db.exec(seed);
    }
  } catch (e) { /* skip if already seeded */ }
  console.log('Database initialized with schema and compliance controls.\n');
}

// --- Run migrations for additional tables ---
function runMigration(tableName, sql) {
  try {
    db.prepare(`SELECT 1 FROM ${tableName} LIMIT 1`).first();
  } catch {
    if (db.db && typeof db.db.exec === 'function') {
      db.db.exec(sql);
    } else {
      db.exec(sql);
    }
    console.log(`${tableName} table created.\n`);
  }
}

runMigration('evidence', `
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
`);

runMigration('support_tickets', `
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
`);

runMigration('feature_requests', `
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
`);

runMigration('notifications', `
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
`);

runMigration('training_modules', `
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
`);

// Seed training modules if empty
const trainingCount = db.prepare('SELECT COUNT(*) as c FROM training_modules').first().c;
if (trainingCount === 0) {
  const modules = [
    { id: 'tm-platform-basics', title: 'ForgeAI Govern Platform Basics', description: 'Introduction to the platform interface, navigation, and core concepts.', category: 'platform', target_roles: '["admin","governance_lead","reviewer","viewer"]', content: 'This module covers:\\n\\n1. **Platform Overview**: ForgeAI Govern is a healthcare AI governance platform aligned with NIST AI RMF, FDA SaMD, ONC HTI-1, and HIPAA.\\n\\n2. **Navigation**: The sidebar provides access to all modules: Dashboard, AI Assets, Risk Assessments, Impact Assessments, Compliance, Vendors, Monitoring, Maturity, Incidents, Reports, Knowledge Base, and Support.\\n\\n3. **Roles**: Admin (full access), Governance Lead (assessments + assets), Reviewer (review and approve), Viewer (read-only).\\n\\n4. **Key Workflows**: Register AI systems > Assess risks > Map compliance controls > Monitor performance > Report to stakeholders.', duration_minutes: 15, sort_order: 1 },
    { id: 'tm-risk-assessment', title: 'Conducting AI Risk Assessments', description: 'Learn the 6-dimension weighted risk scoring methodology for healthcare AI systems.', category: 'governance', target_roles: '["admin","governance_lead","reviewer"]', content: 'This module covers the ForgeAI 6-dimension risk model:\\n\\n1. **Patient Safety (25%)**: Rate 1-5 based on potential for direct patient harm.\\n2. **Bias & Fairness (20%)**: Disparate impact risk across demographic groups.\\n3. **Data Privacy (15%)**: PHI exposure and de-identification effectiveness.\\n4. **Clinical Validity (15%)**: Scientific evidence supporting AI claims.\\n5. **Cybersecurity (15%)**: Attack surface and adversarial robustness.\\n6. **Regulatory (10%)**: Compliance gaps with FDA, HIPAA, state laws.\\n\\nOverall risk: Critical (>=4.0 or safety=5), High (>=3.0), Moderate (>=2.0), Low (<2.0).', duration_minutes: 30, sort_order: 2 },
    { id: 'tm-compliance-mapping', title: 'Compliance Control Mapping', description: 'Map and implement controls across NIST AI RMF, FDA SaMD, ONC HTI-1, and HIPAA.', category: 'compliance', target_roles: '["admin","governance_lead","reviewer"]', content: 'This module covers compliance mapping:\\n\\n1. **NIST AI RMF**: 4 families (Govern, Map, Measure, Manage) with 39 controls mapped in ForgeAI.\\n2. **FDA SaMD**: Pre-market pathways (510(k), De Novo, PMA) and Predetermined Change Control Plans.\\n3. **ONC HTI-1**: Transparency requirements for Predictive Decision Support Interventions.\\n4. **HIPAA**: Privacy Rule, Security Rule, Breach Notification for AI systems processing PHI.\\n\\nFor each control: document implementation status, assign responsible party, link evidence, schedule reviews.', duration_minutes: 45, sort_order: 3 },
    { id: 'tm-vendor-diligence', title: 'AI Vendor Due Diligence', description: 'Evaluate third-party AI vendors using the 5-dimension scoring framework.', category: 'governance', target_roles: '["admin","governance_lead"]', content: 'Vendor assessment dimensions:\\n\\n1. **Transparency (15%)**: Model architecture disclosure, training data documentation.\\n2. **Bias Testing (25%)**: Demographic testing methodology and results disaggregation.\\n3. **Security (25%)**: SOC 2 compliance, encryption, penetration testing.\\n4. **Data Practices (20%)**: PHI protections, data retention, sub-processor agreements.\\n5. **Contractual (15%)**: Audit rights, SLAs, performance guarantees, exit clauses.\\n\\nScoring: 0-100 scale. Below 40 = Rejected, 40-60 = Conditional, Above 60 = Approved.', duration_minutes: 30, sort_order: 4 },
    { id: 'tm-incident-response', title: 'AI Incident Response', description: 'Procedures for reporting, investigating, and resolving AI-related incidents.', category: 'governance', target_roles: '["admin","governance_lead","reviewer"]', content: 'Incident response procedure:\\n\\n1. **Report**: Document incident type, severity, affected system, patient impact.\\n2. **Auto-Suspension**: Critical patient safety incidents auto-suspend the AI system.\\n3. **Investigate**: Assign team, document root cause analysis.\\n4. **Remediate**: Implement corrective actions with evidence.\\n5. **Resolve**: Close with full audit trail and lessons learned.\\n6. **Update**: Revise risk assessment based on incident findings.\\n\\nSeverity Levels: Critical (life safety), High (24hr response), Moderate (72hr review), Low (tracked).', duration_minutes: 20, sort_order: 5 },
    { id: 'tm-hipaa-ai', title: 'HIPAA Compliance for AI Systems', description: 'Essential HIPAA requirements when AI systems access Protected Health Information.', category: 'regulatory', target_roles: '["admin","governance_lead","reviewer","viewer"]', content: 'HIPAA requirements for AI:\\n\\n1. **Privacy Rule**: Minimum necessary standard for PHI use. De-identify training data via Safe Harbor or Expert Determination.\\n2. **Security Rule**: Administrative, physical, technical safeguards. AI systems need access controls, audit logging, encryption.\\n3. **Breach Notification**: AI data breaches affecting PHI must be reported within 60 days.\\n4. **BAAs**: Required with AI vendors processing PHI.\\n5. **Risk Analysis**: Annual security risk analysis must include AI systems.\\n\\nForgeAI tracks PHI access per AI system and maps HIPAA controls.', duration_minutes: 25, sort_order: 6 },
  ];
  for (const m of modules) {
    try {
      db.prepare(
        `INSERT INTO training_modules (id, title, description, category, target_roles, content, duration_minutes, sort_order)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(m.id, m.title, m.description, m.category, m.target_roles, m.content, m.duration_minutes, m.sort_order).run();
    } catch (e) { /* skip if already seeded */ }
  }
  console.log('Training modules seeded.\n');
}

// --- Migration 0003: Evidence file storage, audit hash chaining, BAA tracking ---
function runColumnMigration(table, column, ddl) {
  try {
    db.prepare(`SELECT ${column} FROM ${table} LIMIT 1`).first();
  } catch {
    const execFn = db.db && typeof db.db.exec === 'function' ? db.db : db;
    execFn.exec(ddl);
    console.log(`Migration: added ${column} to ${table}`);
  }
}

// Evidence file storage columns
runColumnMigration('evidence', 'file_key', 'ALTER TABLE evidence ADD COLUMN file_key TEXT;');
runColumnMigration('evidence', 'file_name', 'ALTER TABLE evidence ADD COLUMN file_name TEXT;');
runColumnMigration('evidence', 'file_size', 'ALTER TABLE evidence ADD COLUMN file_size INTEGER;');
runColumnMigration('evidence', 'file_type', 'ALTER TABLE evidence ADD COLUMN file_type TEXT;');
runColumnMigration('evidence', 'sha256_hash', 'ALTER TABLE evidence ADD COLUMN sha256_hash TEXT;');
runColumnMigration('evidence', 'retention_expires_at', 'ALTER TABLE evidence ADD COLUMN retention_expires_at TEXT;');

// Audit log hash chaining columns
runColumnMigration('audit_log', 'previous_hash', 'ALTER TABLE audit_log ADD COLUMN previous_hash TEXT;');
runColumnMigration('audit_log', 'entry_hash', 'ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;');
runColumnMigration('audit_log', 'data_classification', "ALTER TABLE audit_log ADD COLUMN data_classification TEXT DEFAULT 'standard';");

// BAA tracking on tenants
runColumnMigration('tenants', 'hipaa_baa_signed_at', 'ALTER TABLE tenants ADD COLUMN hipaa_baa_signed_at TEXT;');
runColumnMigration('tenants', 'hipaa_baa_signed_by', 'ALTER TABLE tenants ADD COLUMN hipaa_baa_signed_by TEXT;');

// --- Build Environment Object (mimics Cloudflare env) ---
const env = {
  DB: db,
  JWT_SECRET,
  ENVIRONMENT: process.env.NODE_ENV === 'test' ? 'test' : 'local',
  ALLOWED_ORIGINS: process.env.CORS_ORIGIN || 'http://localhost:3000',
  // SESSION_CACHE is not available in local mode; auth.js handles this gracefully
};

const app = express();

// --- Security Middleware ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const allowedOrigins = process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
      : ['http://localhost:3000'];
    if (allowedOrigins.includes(origin)) {
      return callback(null, origin);
    }
    return callback(new Error('CORS: origin not allowed'));
  },
  credentials: true,
}));

app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));

// Structured request logging for API routes
app.use('/api/', (req, res, next) => {
  const requestId = req.headers['x-request-id'] || crypto.randomBytes(8).toString('hex');
  req.requestId = requestId;
  const start = Date.now();

  res.on('finish', () => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info',
      request_id: requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration_ms: Date.now() - start,
      ip: req.ip,
      user_agent: req.headers['user-agent'] || null,
    };
    if (res.statusCode >= 500) {
      console.error(JSON.stringify(logEntry));
    } else if (process.env.NODE_ENV !== 'test') {
      console.log(JSON.stringify(logEntry));
    }
  });

  res.setHeader('X-Request-ID', requestId);
  next();
});

// Global rate limiter: 200 requests per minute per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});
app.use('/api/', globalLimiter);

// Auth rate limiter: 10 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later' },
});
app.use('/api/v1/auth/login', authLimiter);
app.use('/api/v1/auth/register', authLimiter);

// Serve static frontend
app.use(express.static(path.join(__dirname, 'src', 'frontend')));

// --- Health Check (Express-level, fast path before Router) ---
app.get('/api/v1/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '1.0.0',
    mode: 'local',
    timestamp: new Date().toISOString(),
    jwt_configured: !!process.env.JWT_SECRET,
  });
});

// --- Delegate ALL API routes to the shared Workers Router ---
// This eliminates ~1,500 lines of duplicated handler code.
// The Workers Router (src/api/router.js) handles auth, CSRF, routing, and responses.
const apiRouter = createRouterMiddleware(async (routerEnv) => {
  const { Router } = await import('./src/api/router.js');
  return new Router(routerEnv);
}, env);

app.use('/api/', apiRouter);

// --- SPA fallback ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'frontend', 'index.html'));
});

// --- Utilities for test compatibility ---
// Tests use createToken to fabricate tokens for specific roles.
function createToken(payload, expiresIn) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = { ...payload, iat: now, exp: now + expiresIn };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
  const signingInput = `${headerB64}.${payloadB64}`;

  const signature = crypto.createHmac('sha256', JWT_SECRET).update(signingInput).digest('base64url');
  return `${headerB64}.${payloadB64}.${signature}`;
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(32);
    crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      resolve(`100000:${salt.toString('hex')}:${derivedKey.toString('hex')}`);
    });
  });
}

function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    const [iterations, saltHex, hashHex] = storedHash.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    crypto.pbkdf2(password, salt, parseInt(iterations), 32, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString('hex') === hashHex);
    });
  });
}

// --- Export for testing ---
module.exports = { app, db, createToken, hashPassword, verifyPassword, JWT_SECRET };

// --- Start Server ---
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`
  ╔══════════════════════════════════════════════════════╗
  ║   ForgeAI Govern™ - Healthcare AI Governance        ║
  ║   Platform running at http://localhost:${PORT}          ║
  ║                                                      ║
  ║   API:       http://localhost:${PORT}/api/v1/health     ║
  ║   Dashboard: http://localhost:${PORT}                   ║
  ╚══════════════════════════════════════════════════════╝
    `);
  });

  // Graceful shutdown
  process.on('SIGINT', () => { db.close(); process.exit(0); });
  process.on('SIGTERM', () => { db.close(); process.exit(0); });
}
