/**
 * ForgeAI Govern™ - Local Express Server
 *
 * Runs the Healthcare AI Governance Platform locally using
 * Express + better-sqlite3, no Cloudflare account required.
 *
 * Usage: npm start
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createDatabase } = require('./src/local/db-adapter');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'forgeai-local-dev-secret-' + crypto.randomBytes(8).toString('hex');

// --- Initialize Database ---
const db = createDatabase();

// Auto-setup schema if tables don't exist
try {
  db.prepare('SELECT 1 FROM tenants LIMIT 1').first();
} catch {
  console.log('First run detected — initializing database...');
  const schema = fs.readFileSync(path.join(__dirname, 'src', 'database', 'schema.sql'), 'utf8');
  const statements = schema.split(';').map(s => s.trim()).filter(s => s && !s.startsWith('--') && !s.startsWith('PRAGMA'));
  for (const stmt of statements) {
    try { db.exec(stmt + ';'); } catch (e) { /* skip pragma/duplicate errors */ }
  }

  // Seed compliance controls
  const seed = fs.readFileSync(path.join(__dirname, 'src', 'database', 'seed.sql'), 'utf8');
  try { db.exec(seed); } catch (e) { /* skip if already seeded */ }
  console.log('Database initialized with schema and compliance controls.\n');
}

// --- Build Environment Object (mimics Cloudflare env) ---
const env = {
  DB: db,
  JWT_SECRET,
  ENVIRONMENT: 'local',
};

// --- Import Handlers (adapted for CommonJS) ---
// Since the handler files use ES module syntax, we'll create wrapper functions

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Serve static frontend
app.use(express.static(path.join(__dirname, 'src', 'frontend')));

// --- Auth Service (inline for local mode) ---

const PBKDF2_ITERATIONS = 100000;
const ACCESS_TOKEN_EXPIRY = 15 * 60;
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 30;

async function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(32);
    crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, 32, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      resolve(`${PBKDF2_ITERATIONS}:${salt.toString('hex')}:${derivedKey.toString('hex')}`);
    });
  });
}

async function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    const [iterations, saltHex, hashHex] = storedHash.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    crypto.pbkdf2(password, salt, parseInt(iterations), 32, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString('hex') === hashHex);
    });
  });
}

function createToken(payload, expiresIn) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = Buffer.from(JSON.stringify({ ...payload, iat: now, exp: now + expiresIn })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  try {
    const [header, body, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (signature !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function authenticate(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return verifyToken(auth.slice(7));
}

function authorize(user, roles) {
  return user && roles.includes(user.role);
}

function auditLog(tenantId, userId, action, entityType, entityId, details = {}) {
  db.prepare(
    `INSERT INTO audit_log (id, tenant_id, user_id, action, entity_type, entity_id, details, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), tenantId, userId, action, entityType, entityId, JSON.stringify(details), 'local').run();
}

// --- Auth Middleware ---
function requireAuth(req, res, next) {
  const user = authenticate(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  req.user = user;
  next();
}

// --- Health Check ---
app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'healthy', version: '1.0.0', mode: 'local', timestamp: new Date().toISOString() });
});

// ==================== AUTH ROUTES ====================

app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { organization_name, email, password, first_name, last_name } = req.body;
    if (!organization_name || !email || !password || !first_name || !last_name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });

    const tenantId = crypto.randomUUID();
    const userId = crypto.randomUUID();
    const slug = organization_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50);
    const passwordHash = await hashPassword(password);

    db.prepare(`INSERT INTO tenants (id, name, slug, plan, status) VALUES (?, ?, ?, 'trial', 'active')`)
      .bind(tenantId, organization_name, slug).run();
    db.prepare(`INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) VALUES (?, ?, ?, ?, ?, ?, 'admin', 'active')`)
      .bind(userId, tenantId, email, passwordHash, first_name, last_name).run();

    const accessToken = createToken({ user_id: userId, tenant_id: tenantId, role: 'admin' }, ACCESS_TOKEN_EXPIRY);
    const refreshToken = createToken({ user_id: userId, tenant_id: tenantId, type: 'refresh' }, REFRESH_TOKEN_EXPIRY);
    auditLog(tenantId, userId, 'register', 'tenant', tenantId, { organization: organization_name });

    res.status(201).json({
      access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_EXPIRY,
      user: { id: userId, email, first_name, last_name, role: 'admin' },
      tenant: { id: tenantId, name: organization_name, slug },
    });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Organization or email already exists' });
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = db.prepare(
      `SELECT u.*, t.name as tenant_name, t.slug as tenant_slug FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE u.email = ? AND u.status = 'active'`
    ).bind(email).first();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Account locked. Try again later.' });
    }

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      const attempts = user.failed_login_attempts + 1;
      if (attempts >= MAX_LOGIN_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString();
        db.prepare(`UPDATE users SET failed_login_attempts = ?, locked_until = ?, status = 'locked' WHERE id = ?`)
          .bind(attempts, lockUntil, user.id).run();
      } else {
        db.prepare(`UPDATE users SET failed_login_attempts = ? WHERE id = ?`).bind(attempts, user.id).run();
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    db.prepare(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = datetime('now'), status = 'active' WHERE id = ?`)
      .bind(user.id).run();

    const accessToken = createToken({ user_id: user.id, tenant_id: user.tenant_id, role: user.role }, ACCESS_TOKEN_EXPIRY);
    const refreshToken = createToken({ user_id: user.id, tenant_id: user.tenant_id, type: 'refresh' }, REFRESH_TOKEN_EXPIRY);
    auditLog(user.tenant_id, user.id, 'login', 'user', user.id, {});

    res.json({
      access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_EXPIRY,
      user: { id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, role: user.role, mfa_enabled: !!user.mfa_enabled },
      tenant: { id: user.tenant_id, name: user.tenant_name, slug: user.tenant_slug },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/refresh', (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'Refresh token required' });
  const payload = verifyToken(refresh_token);
  if (!payload || payload.type !== 'refresh') return res.status(401).json({ error: 'Invalid refresh token' });

  const user = db.prepare(`SELECT id, tenant_id, role FROM users WHERE id = ? AND status = 'active'`).bind(payload.user_id).first();
  if (!user) return res.status(401).json({ error: 'User not found' });

  const newAccess = createToken({ user_id: user.id, tenant_id: user.tenant_id, role: user.role }, ACCESS_TOKEN_EXPIRY);
  const newRefresh = createToken({ user_id: user.id, tenant_id: user.tenant_id, type: 'refresh' }, REFRESH_TOKEN_EXPIRY);
  res.json({ access_token: newAccess, refresh_token: newRefresh, token_type: 'Bearer', expires_in: ACCESS_TOKEN_EXPIRY });
});

// ==================== AI ASSETS ====================

app.get('/api/v1/ai-assets', requireAuth, (req, res) => {
  const { page = 1, limit = 25, category, risk_tier, status, search } = req.query;
  const offset = (Math.max(1, +page) - 1) * Math.min(100, Math.max(1, +limit));
  const safeLimit = Math.min(100, Math.max(1, +limit));

  let where = 'WHERE a.tenant_id = ?';
  const params = [req.user.tenant_id];
  if (category) { where += ' AND a.category = ?'; params.push(category); }
  if (risk_tier) { where += ' AND a.risk_tier = ?'; params.push(risk_tier); }
  if (status) { where += ' AND a.deployment_status = ?'; params.push(status); }
  if (search) { where += ' AND (a.name LIKE ? OR a.vendor LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

  const total = db.prepare(`SELECT COUNT(*) as total FROM ai_assets a ${where}`).bind(...params).first().total;
  const assets = db.prepare(
    `SELECT a.*, u1.first_name || ' ' || u1.last_name as owner_name, u2.first_name || ' ' || u2.last_name as champion_name
     FROM ai_assets a LEFT JOIN users u1 ON a.owner_user_id = u1.id LEFT JOIN users u2 ON a.clinical_champion_id = u2.id
     ${where} ORDER BY a.updated_at DESC LIMIT ? OFFSET ?`
  ).bind(...params, safeLimit, offset).all();

  res.json({ data: assets.results, pagination: { page: +page, limit: safeLimit, total, pages: Math.ceil(total / safeLimit) } });
});

app.get('/api/v1/ai-assets/:id', requireAuth, (req, res) => {
  const asset = db.prepare(
    `SELECT a.*, u1.first_name || ' ' || u1.last_name as owner_name, u2.first_name || ' ' || u2.last_name as champion_name,
      (SELECT COUNT(*) FROM risk_assessments WHERE ai_asset_id = a.id) as risk_assessment_count,
      (SELECT COUNT(*) FROM impact_assessments WHERE ai_asset_id = a.id) as impact_assessment_count,
      (SELECT overall_risk_level FROM risk_assessments WHERE ai_asset_id = a.id ORDER BY created_at DESC LIMIT 1) as latest_risk_level
     FROM ai_assets a LEFT JOIN users u1 ON a.owner_user_id = u1.id LEFT JOIN users u2 ON a.clinical_champion_id = u2.id
     WHERE a.id = ? AND a.tenant_id = ?`
  ).bind(req.params.id, req.user.tenant_id).first();
  if (!asset) return res.status(404).json({ error: 'AI asset not found' });
  res.json({ data: asset });
});

app.post('/api/v1/ai-assets', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const { name, category } = req.body;
  if (!name || !category) return res.status(400).json({ error: 'Name and category are required' });

  const id = crypto.randomUUID();
  const b = req.body;
  db.prepare(
    `INSERT INTO ai_assets (id, tenant_id, name, vendor, version, category, risk_tier, fda_classification,
      data_sources, phi_access, phi_data_types, deployment_status, owner_user_id, clinical_champion_id,
      department, description, intended_use, known_limitations, training_data_description)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, req.user.tenant_id, name, b.vendor || null, b.version || null, category,
    b.risk_tier || 'moderate', b.fda_classification || null, JSON.stringify(b.data_sources || []),
    b.phi_access ? 1 : 0, JSON.stringify(b.phi_data_types || []), b.deployment_status || 'proposed',
    b.owner_user_id || null, b.clinical_champion_id || null, b.department || null,
    b.description || null, b.intended_use || null, b.known_limitations || null, b.training_data_description || null
  ).run();

  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'ai_asset', id, { name, category });
  const asset = db.prepare('SELECT * FROM ai_assets WHERE id = ?').bind(id).first();
  res.status(201).json({ data: asset, message: 'AI asset registered successfully' });
});

app.put('/api/v1/ai-assets/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM ai_assets WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'AI asset not found' });

  const fields = ['name', 'vendor', 'version', 'category', 'risk_tier', 'fda_classification', 'deployment_status',
    'deployment_date', 'owner_user_id', 'clinical_champion_id', 'department', 'description', 'intended_use', 'known_limitations'];
  const updates = []; const values = [];
  for (const f of fields) { if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(req.body[f]); } }
  if (req.body.phi_access !== undefined) { updates.push('phi_access = ?'); values.push(req.body.phi_access ? 1 : 0); }
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE ai_assets SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...values, req.params.id, req.user.tenant_id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'ai_asset', req.params.id, {});
  const updated = db.prepare('SELECT * FROM ai_assets WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
});

app.delete('/api/v1/ai-assets/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Only admins can decommission' });
  const existing = db.prepare('SELECT * FROM ai_assets WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'AI asset not found' });
  db.prepare(`UPDATE ai_assets SET deployment_status = 'decommissioned', updated_at = datetime('now') WHERE id = ?`).bind(req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'decommission', 'ai_asset', req.params.id, {});
  res.json({ message: 'AI asset decommissioned' });
});

// ==================== RISK ASSESSMENTS ====================

function calculateOverallRisk(scores) {
  const w = { patient_safety: 0.25, bias_fairness: 0.20, data_privacy: 0.15, clinical_validity: 0.15, cybersecurity: 0.15, regulatory: 0.10 };
  const weighted = (scores.patient_safety_score * w.patient_safety) + (scores.bias_fairness_score * w.bias_fairness) +
    (scores.data_privacy_score * w.data_privacy) + (scores.clinical_validity_score * w.clinical_validity) +
    (scores.cybersecurity_score * w.cybersecurity) + (scores.regulatory_score * w.regulatory);
  if (weighted >= 4.0 || scores.patient_safety_score === 5) return 'critical';
  if (weighted >= 3.0) return 'high';
  if (weighted >= 2.0) return 'moderate';
  return 'low';
}

app.get('/api/v1/risk-assessments', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT r.*, a.name as asset_name, a.category as asset_category, a.risk_tier,
      u.first_name || ' ' || u.last_name as assessor_name
     FROM risk_assessments r JOIN ai_assets a ON r.ai_asset_id = a.id JOIN users u ON r.assessor_id = u.id
     WHERE r.tenant_id = ? ORDER BY r.created_at DESC`
  ).bind(req.user.tenant_id).all();
  res.json({ data: results.results });
});

app.post('/api/v1/risk-assessments', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const { ai_asset_id, assessment_type } = req.body;
  if (!ai_asset_id || !assessment_type) return res.status(400).json({ error: 'ai_asset_id and assessment_type required' });

  const asset = db.prepare('SELECT id FROM ai_assets WHERE id = ? AND tenant_id = ?').bind(ai_asset_id, req.user.tenant_id).first();
  if (!asset) return res.status(404).json({ error: 'AI asset not found' });

  const b = req.body;
  const scores = { patient_safety_score: b.patient_safety_score, bias_fairness_score: b.bias_fairness_score,
    data_privacy_score: b.data_privacy_score, clinical_validity_score: b.clinical_validity_score,
    cybersecurity_score: b.cybersecurity_score, regulatory_score: b.regulatory_score };
  const allScored = Object.values(scores).every(s => s >= 1 && s <= 5);
  const overallRisk = allScored ? calculateOverallRisk(scores) : null;

  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO risk_assessments (id, tenant_id, ai_asset_id, assessment_type, assessor_id,
      patient_safety_score, bias_fairness_score, data_privacy_score, clinical_validity_score,
      cybersecurity_score, regulatory_score, overall_risk_level, findings, recommendations, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')`
  ).bind(id, req.user.tenant_id, ai_asset_id, assessment_type, req.user.user_id,
    scores.patient_safety_score || null, scores.bias_fairness_score || null, scores.data_privacy_score || null,
    scores.clinical_validity_score || null, scores.cybersecurity_score || null, scores.regulatory_score || null,
    overallRisk, JSON.stringify(b.findings || {}), b.recommendations || null
  ).run();

  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'risk_assessment', id, { overall_risk_level: overallRisk });
  const assessment = db.prepare('SELECT * FROM risk_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: assessment });
});

app.post('/api/v1/risk-assessments/:id/approve', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM risk_assessments WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const newStatus = req.body.approved ? 'approved' : 'rejected';
  db.prepare(`UPDATE risk_assessments SET status = ?, approved_by = ?, completed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`)
    .bind(newStatus, req.user.user_id, req.params.id).run();
  res.json({ message: `Assessment ${newStatus}` });
});

// ==================== IMPACT ASSESSMENTS ====================

app.get('/api/v1/impact-assessments', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT ia.*, a.name as asset_name, a.category, u.first_name || ' ' || u.last_name as assessor_name
     FROM impact_assessments ia JOIN ai_assets a ON ia.ai_asset_id = a.id JOIN users u ON ia.assessor_id = u.id
     WHERE ia.tenant_id = ? ORDER BY ia.created_at DESC`
  ).bind(req.user.tenant_id).all();
  res.json({ data: results.results });
});

app.post('/api/v1/impact-assessments', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const { ai_asset_id } = req.body;
  if (!ai_asset_id) return res.status(400).json({ error: 'ai_asset_id required' });
  const b = req.body; const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO impact_assessments (id, tenant_id, ai_asset_id, assessor_id, assessment_period,
      demographic_groups_tested, performance_by_group, bias_indicators, drift_detected, drift_details,
      remediation_required, remediation_plan, remediation_status, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, req.user.tenant_id, ai_asset_id, req.user.user_id, b.assessment_period || null,
    JSON.stringify(b.demographic_groups_tested || []), JSON.stringify(b.performance_by_group || {}),
    JSON.stringify(b.bias_indicators || {}), b.drift_detected ? 1 : 0, JSON.stringify(b.drift_details || {}),
    b.remediation_required ? 1 : 0, b.remediation_plan || null, b.remediation_required ? 'planned' : 'not_needed',
    b.status || 'in_progress'
  ).run();
  const aia = db.prepare('SELECT * FROM impact_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: aia });
});

// ==================== COMPLIANCE ====================

app.get('/api/v1/controls', requireAuth, (req, res) => {
  const { family, search } = req.query;
  let where = 'WHERE 1=1'; const params = [];
  if (family) { where += ' AND family = ?'; params.push(family); }
  if (search) { where += ' AND (title LIKE ? OR control_id LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  const controls = db.prepare(`SELECT * FROM compliance_controls ${where} ORDER BY control_id`).bind(...params).all();
  const grouped = { Govern: [], Map: [], Measure: [], Manage: [] };
  for (const c of controls.results) { if (grouped[c.family]) grouped[c.family].push(c); }
  res.json({ data: controls.results, grouped });
});

app.get('/api/v1/controls/:id/frameworks', requireAuth, (req, res) => {
  const ctrl = db.prepare('SELECT * FROM compliance_controls WHERE id = ? OR control_id = ?').bind(req.params.id, req.params.id).first();
  if (!ctrl) return res.status(404).json({ error: 'Control not found' });
  res.json({ data: { control: ctrl, frameworks: { nist_ai_rmf: ctrl.nist_ai_rmf_ref, fda_samd: ctrl.fda_samd_ref, onc_hti1: ctrl.onc_hti1_ref, hipaa: ctrl.hipaa_ref } } });
});

app.get('/api/v1/implementations', requireAuth, (req, res) => {
  const { ai_asset_id, status } = req.query;
  let where = 'WHERE ci.tenant_id = ?'; const params = [req.user.tenant_id];
  if (ai_asset_id) { where += ' AND ci.ai_asset_id = ?'; params.push(ai_asset_id); }
  if (status) { where += ' AND ci.implementation_status = ?'; params.push(status); }
  const results = db.prepare(
    `SELECT ci.*, cc.control_id as control_code, cc.title as control_title, cc.family
     FROM control_implementations ci JOIN compliance_controls cc ON ci.control_id = cc.id
     ${where} ORDER BY cc.control_id`
  ).bind(...params).all();
  const summary = { implemented: 0, partially_implemented: 0, planned: 0, not_applicable: 0, total: results.results.length };
  for (const i of results.results) summary[i.implementation_status]++;
  summary.compliance_percentage = summary.total > 0 ? Math.round(((summary.implemented + summary.not_applicable) / summary.total) * 100) : 0;
  res.json({ data: results.results, summary });
});

app.post('/api/v1/implementations', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const { control_id, implementation_status } = req.body;
  if (!control_id || !implementation_status) return res.status(400).json({ error: 'control_id and implementation_status required' });
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO control_implementations (id, tenant_id, ai_asset_id, control_id, implementation_status, responsible_party) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(id, req.user.tenant_id, req.body.ai_asset_id || null, control_id, implementation_status, req.body.responsible_party || null).run();
  res.status(201).json({ data: { id }, message: 'Control implementation recorded' });
});

// ==================== VENDORS ====================

app.get('/api/v1/vendor-assessments', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT va.*, u.first_name || ' ' || u.last_name as assessor_name FROM vendor_assessments va
     LEFT JOIN users u ON va.assessed_by = u.id WHERE va.tenant_id = ? ORDER BY va.created_at DESC`
  ).bind(req.user.tenant_id).all();
  res.json({ data: results.results });
});

app.post('/api/v1/vendor-assessments', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const { vendor_name, product_name } = req.body;
  if (!vendor_name || !product_name) return res.status(400).json({ error: 'vendor_name and product_name required' });
  const id = crypto.randomUUID(); const b = req.body;
  db.prepare(
    `INSERT INTO vendor_assessments (id, tenant_id, vendor_name, product_name, training_data_provenance,
      validation_methodology, transparency_score, bias_testing_score, security_score, data_practices_score,
      contractual_score, recommendation, assessed_by, assessed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
  ).bind(id, req.user.tenant_id, vendor_name, product_name, b.training_data_provenance || null,
    b.validation_methodology || null, b.transparency_score || null, b.bias_testing_score || null,
    b.security_score || null, b.data_practices_score || null, b.contractual_score || null,
    b.recommendation || 'pending', req.user.user_id
  ).run();
  const va = db.prepare('SELECT * FROM vendor_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: va });
});

app.post('/api/v1/vendor-assessments/:id/score', requireAuth, (req, res) => {
  const va = db.prepare('SELECT * FROM vendor_assessments WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!va) return res.status(404).json({ error: 'Not found' });
  const w = { transparency: 0.15, bias_testing: 0.25, security: 0.25, data_practices: 0.20, contractual: 0.15 };
  const score = Math.round(((va.transparency_score||3)*w.transparency + (va.bias_testing_score||3)*w.bias_testing +
    (va.security_score||3)*w.security + (va.data_practices_score||3)*w.data_practices + (va.contractual_score||3)*w.contractual) * 20);
  const rec = score < 40 ? 'rejected' : score < 60 ? 'conditional' : 'approved';
  db.prepare(`UPDATE vendor_assessments SET overall_risk_score = ?, recommendation = ?, updated_at = datetime('now') WHERE id = ?`).bind(score, rec, req.params.id).run();
  res.json({ data: { overall_risk_score: score, recommendation: rec } });
});

// ==================== MONITORING ====================

app.get('/api/v1/ai-assets/:id/metrics', requireAuth, (req, res) => {
  const { metric_type, limit = 100 } = req.query;
  let where = 'WHERE tenant_id = ? AND ai_asset_id = ?'; const params = [req.user.tenant_id, req.params.id];
  if (metric_type) { where += ' AND metric_type = ?'; params.push(metric_type); }
  const metrics = db.prepare(`SELECT * FROM monitoring_metrics ${where} ORDER BY recorded_at DESC LIMIT ?`).bind(...params, Math.min(+limit, 1000)).all();
  res.json({ data: metrics.results });
});

app.post('/api/v1/monitoring/metrics', requireAuth, (req, res) => {
  const { ai_asset_id, metric_type, metric_value } = req.body;
  if (!ai_asset_id || !metric_type || metric_value === undefined) return res.status(400).json({ error: 'ai_asset_id, metric_type, and metric_value required' });
  let alert = false, severity = null;
  if (req.body.threshold_min && metric_value < req.body.threshold_min) { alert = true; severity = 'warning'; }
  if (req.body.threshold_max && metric_value > req.body.threshold_max) { alert = true; severity = 'warning'; }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO monitoring_metrics (id, tenant_id, ai_asset_id, metric_type, metric_value, threshold_min, threshold_max, alert_triggered, alert_severity, demographic_group, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
  ).bind(id, req.user.tenant_id, ai_asset_id, metric_type, metric_value, req.body.threshold_min || null, req.body.threshold_max || null, alert ? 1 : 0, severity, req.body.demographic_group || null).run();
  res.status(201).json({ data: { id, alert_triggered: alert, alert_severity: severity } });
});

app.get('/api/v1/monitoring/alerts', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT m.*, a.name as asset_name, a.category, a.risk_tier FROM monitoring_metrics m
     JOIN ai_assets a ON m.ai_asset_id = a.id
     WHERE m.tenant_id = ? AND m.alert_triggered = 1 ORDER BY m.recorded_at DESC LIMIT 100`
  ).bind(req.user.tenant_id).all();
  res.json({ data: results.results });
});

// ==================== DASHBOARD ====================

app.get('/api/v1/dashboard/stats', requireAuth, (req, res) => {
  const tid = req.user.tenant_id;
  const total = db.prepare(`SELECT COUNT(*) as total FROM ai_assets WHERE tenant_id = ? AND deployment_status != 'decommissioned'`).bind(tid).first();
  const riskDist = db.prepare(`SELECT risk_tier, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? AND deployment_status != 'decommissioned' GROUP BY risk_tier`).bind(tid).all();
  const statusDist = db.prepare(`SELECT deployment_status, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? GROUP BY deployment_status`).bind(tid).all();
  const categoryDist = db.prepare(`SELECT category, COUNT(*) as count FROM ai_assets WHERE tenant_id = ? AND deployment_status != 'decommissioned' GROUP BY category`).bind(tid).all();
  const assessments = db.prepare(`SELECT status, COUNT(*) as count FROM risk_assessments WHERE tenant_id = ? GROUP BY status`).bind(tid).all();
  const alerts = db.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN alert_severity = 'critical' THEN 1 ELSE 0 END) as critical FROM monitoring_metrics WHERE tenant_id = ? AND alert_triggered = 1 AND recorded_at >= datetime('now', '-30 days')`).bind(tid).first();
  const incidents = db.prepare(`SELECT severity, COUNT(*) as count FROM incidents WHERE tenant_id = ? AND status != 'closed' GROUP BY severity`).bind(tid).all();
  const compliance = db.prepare(`SELECT implementation_status, COUNT(*) as count FROM control_implementations WHERE tenant_id = ? GROUP BY implementation_status`).bind(tid).all();

  const compSummary = {}; let implTotal = 0, implDone = 0;
  for (const r of compliance.results) { compSummary[r.implementation_status] = r.count; implTotal += r.count; if (['implemented', 'not_applicable'].includes(r.implementation_status)) implDone += r.count; }

  res.json({ data: {
    ai_portfolio: { total_assets: total.total, risk_distribution: Object.fromEntries(riskDist.results.map(r => [r.risk_tier, r.count])),
      status_distribution: Object.fromEntries(statusDist.results.map(r => [r.deployment_status, r.count])),
      category_distribution: Object.fromEntries(categoryDist.results.map(r => [r.category, r.count])) },
    risk_assessments: Object.fromEntries(assessments.results.map(r => [r.status, r.count])),
    monitoring: { alerts_last_30_days: alerts.total || 0, critical_alerts: alerts.critical || 0 },
    open_incidents: Object.fromEntries(incidents.results.map(r => [r.severity, r.count])),
    compliance: { ...compSummary, compliance_percentage: implTotal > 0 ? Math.round((implDone / implTotal) * 100) : 0 },
  }});
});

app.get('/api/v1/reports/compliance', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT cc.*, ci.implementation_status FROM compliance_controls cc
     LEFT JOIN control_implementations ci ON cc.id = ci.control_id AND ci.tenant_id = ?
     ORDER BY cc.family, cc.control_id`
  ).bind(req.user.tenant_id).all();
  const byFamily = {};
  for (const r of results.results) {
    if (!byFamily[r.family]) byFamily[r.family] = { total: 0, implemented: 0, partial: 0, planned: 0, gap: 0 };
    byFamily[r.family].total++;
    if (r.implementation_status === 'implemented') byFamily[r.family].implemented++;
    else if (r.implementation_status === 'partially_implemented') byFamily[r.family].partial++;
    else if (r.implementation_status === 'planned') byFamily[r.family].planned++;
    else byFamily[r.family].gap++;
  }
  res.json({ report: { title: 'AI Governance Compliance Report', generated_at: new Date().toISOString(), summary_by_family: byFamily, controls: results.results } });
});

app.get('/api/v1/reports/executive', requireAuth, (req, res) => {
  const tid = req.user.tenant_id;
  const maturity = db.prepare('SELECT * FROM maturity_assessments WHERE tenant_id = ? ORDER BY assessment_date DESC LIMIT 1').bind(tid).first();
  const recentAssessments = db.prepare(
    `SELECT r.*, a.name as asset_name FROM risk_assessments r JOIN ai_assets a ON r.ai_asset_id = a.id WHERE r.tenant_id = ? ORDER BY r.created_at DESC LIMIT 5`
  ).bind(tid).all();
  const openIncidents = db.prepare(
    `SELECT i.*, a.name as asset_name FROM incidents i JOIN ai_assets a ON i.ai_asset_id = a.id WHERE i.tenant_id = ? AND i.status != 'closed' ORDER BY i.created_at DESC LIMIT 5`
  ).bind(tid).all();
  res.json({ report: { title: 'AI Governance Executive Summary', generated_at: new Date().toISOString(),
    maturity_assessment: maturity, recent_assessments: recentAssessments.results, open_incidents: openIncidents.results } });
});

// ==================== MATURITY ====================

app.get('/api/v1/maturity-assessments', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT ma.*, u.first_name || ' ' || u.last_name as assessor_name FROM maturity_assessments ma
     JOIN users u ON ma.assessor_id = u.id WHERE ma.tenant_id = ? ORDER BY ma.assessment_date DESC`
  ).bind(req.user.tenant_id).all();
  res.json({ data: results.results });
});

app.post('/api/v1/maturity-assessments', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const b = req.body;
  const domainWeights = { governance_structure: 0.15, ai_inventory: 0.15, risk_assessment: 0.20, policy_compliance: 0.15, monitoring_performance: 0.15, vendor_management: 0.10, transparency: 0.10 };
  const scoreFields = ['governance_structure_score', 'ai_inventory_score', 'risk_assessment_score', 'policy_compliance_score', 'monitoring_performance_score', 'vendor_management_score', 'transparency_score'];
  const domainKeys = Object.keys(domainWeights);

  let overall = null;
  if (scoreFields.every(f => b[f] >= 1 && b[f] <= 5)) {
    overall = 0;
    for (let i = 0; i < domainKeys.length; i++) overall += b[scoreFields[i]] * domainWeights[domainKeys[i]];
    overall = Math.round(overall * 100) / 100;
  }

  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO maturity_assessments (id, tenant_id, assessor_id, assessment_date, governance_structure_score, ai_inventory_score,
      risk_assessment_score, policy_compliance_score, monitoring_performance_score, vendor_management_score, transparency_score,
      overall_maturity_score, domain_findings, immediate_actions, near_term_actions, strategic_actions, status)
     VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, req.user.tenant_id, req.user.user_id,
    b.governance_structure_score || null, b.ai_inventory_score || null, b.risk_assessment_score || null,
    b.policy_compliance_score || null, b.monitoring_performance_score || null, b.vendor_management_score || null,
    b.transparency_score || null, overall, JSON.stringify(b.domain_findings || {}),
    JSON.stringify(b.immediate_actions || []), JSON.stringify(b.near_term_actions || []),
    JSON.stringify(b.strategic_actions || []), b.status || 'draft'
  ).run();
  const ma = db.prepare('SELECT * FROM maturity_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: ma });
});

// ==================== INCIDENTS ====================

app.get('/api/v1/incidents', requireAuth, (req, res) => {
  const { status, severity } = req.query;
  let where = 'WHERE i.tenant_id = ?'; const params = [req.user.tenant_id];
  if (status) { where += ' AND i.status = ?'; params.push(status); }
  if (severity) { where += ' AND i.severity = ?'; params.push(severity); }
  const results = db.prepare(
    `SELECT i.*, a.name as asset_name, a.category, u.first_name || ' ' || u.last_name as reporter_name
     FROM incidents i JOIN ai_assets a ON i.ai_asset_id = a.id JOIN users u ON i.reported_by = u.id
     ${where} ORDER BY i.created_at DESC`
  ).bind(...params).all();
  res.json({ data: results.results });
});

app.post('/api/v1/incidents', requireAuth, (req, res) => {
  const { ai_asset_id, incident_type, severity, title, description } = req.body;
  if (!ai_asset_id || !incident_type || !severity || !title || !description) {
    return res.status(400).json({ error: 'ai_asset_id, incident_type, severity, title, and description required' });
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO incidents (id, tenant_id, ai_asset_id, reported_by, incident_type, severity, title, description, patient_impact, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`
  ).bind(id, req.user.tenant_id, ai_asset_id, req.user.user_id, incident_type, severity, title, description, req.body.patient_impact ? 1 : 0).run();
  if (severity === 'critical' && incident_type === 'patient_safety') {
    db.prepare(`UPDATE ai_assets SET deployment_status = 'suspended', updated_at = datetime('now') WHERE id = ?`).bind(ai_asset_id).run();
  }
  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'incident', id, { severity, incident_type });
  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').bind(id).first();
  res.status(201).json({ data: incident });
});

app.put('/api/v1/incidents/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM incidents WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const updates = []; const values = [];
  for (const f of ['status', 'root_cause', 'corrective_actions', 'severity']) {
    if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  if (req.body.status === 'resolved' || req.body.status === 'closed') updates.push("resolved_at = datetime('now')");
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");
  db.prepare(`UPDATE incidents SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...values, req.params.id, req.user.tenant_id).run();
  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
});

// --- Catch-all: serve frontend for SPA routes ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'frontend', 'index.html'));
});

// --- Start Server ---
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
