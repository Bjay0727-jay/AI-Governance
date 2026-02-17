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
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { createDatabase } = require('./src/local/db-adapter');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'forgeai-local-dev-secret-' + crypto.randomBytes(8).toString('hex');
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');

// --- Initialize Database ---
const db = createDatabase();

// Auto-setup schema if tables don't exist
try {
  db.prepare('SELECT 1 FROM tenants LIMIT 1').first();
} catch {
  console.log('First run detected — initializing database...');
  const schema = fs.readFileSync(path.join(__dirname, 'src', 'database', 'schema.sql'), 'utf8');
  // Use the underlying SQLite db.exec which supports multi-statement SQL
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

// Ensure evidence table exists (migration for existing databases)
try {
  db.prepare('SELECT 1 FROM evidence LIMIT 1').first();
} catch {
  const evidenceSQL = `
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
  `;
  if (db.db && typeof db.db.exec === 'function') {
    db.db.exec(evidenceSQL);
  } else {
    db.exec(evidenceSQL);
  }
  console.log('Evidence table created.\n');
}

// Ensure support_tickets table exists (migration for existing databases)
try {
  db.prepare('SELECT 1 FROM support_tickets LIMIT 1').first();
} catch {
  const ticketsSQL = `
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
  `;
  if (db.db && typeof db.db.exec === 'function') {
    db.db.exec(ticketsSQL);
  } else {
    db.exec(ticketsSQL);
  }
  console.log('Support tickets table created.\n');
}

// Ensure feature_requests and votes tables exist (migration for existing databases)
try {
  db.prepare('SELECT 1 FROM feature_requests LIMIT 1').first();
} catch {
  const featureSQL = `
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
  `;
  if (db.db && typeof db.db.exec === 'function') {
    db.db.exec(featureSQL);
  } else {
    db.exec(featureSQL);
  }
  console.log('Feature requests tables created.\n');
}

// --- Build Environment Object (mimics Cloudflare env) ---
const env = {
  DB: db,
  JWT_SECRET,
  ENVIRONMENT: 'local',
};

const app = express();

// --- Security Middleware ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || true,
  credentials: true,
}));

app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

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

// --- Input Validation Helpers ---
function sanitizeString(str, maxLength = 500) {
  if (typeof str !== 'string') return str;
  return str.trim().slice(0, maxLength);
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validateScore(score, min = 1, max = 5) {
  const n = parseInt(score);
  return !isNaN(n) && n >= min && n <= max ? n : null;
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

// --- CSRF Token Endpoint ---
app.get('/api/v1/csrf-token', (req, res) => {
  const token = crypto.createHmac('sha256', CSRF_SECRET)
    .update(crypto.randomBytes(16).toString('hex'))
    .digest('hex');
  res.json({ csrf_token: token });
});

// ==================== AUTH ROUTES ====================

app.post('/api/v1/auth/register', authLimiter, async (req, res) => {
  try {
    const { organization_name, email, password, first_name, last_name } = req.body;
    if (!organization_name || !email || !password || !first_name || !last_name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
    if (password.length > 128) return res.status(400).json({ error: 'Password must be at most 128 characters' });

    const tenantId = crypto.randomUUID();
    const userId = crypto.randomUUID();
    const slug = sanitizeString(organization_name).toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50);
    const passwordHash = await hashPassword(password);

    db.prepare(`INSERT INTO tenants (id, name, slug, plan, status) VALUES (?, ?, ?, 'trial', 'active')`)
      .bind(tenantId, sanitizeString(organization_name, 200), slug).run();
    db.prepare(`INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) VALUES (?, ?, ?, ?, ?, ?, 'admin', 'active')`)
      .bind(userId, tenantId, sanitizeString(email, 254), passwordHash, sanitizeString(first_name, 100), sanitizeString(last_name, 100)).run();

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

app.post('/api/v1/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = db.prepare(
      `SELECT u.*, t.name as tenant_name, t.slug as tenant_slug FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE u.email = ? AND u.status != 'deactivated'`
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

// ==================== USER MANAGEMENT ====================

app.get('/api/v1/users', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const users = db.prepare(
    `SELECT id, email, first_name, last_name, role, mfa_enabled, status, last_login, created_at
     FROM users WHERE tenant_id = ? ORDER BY created_at DESC`
  ).bind(req.user.tenant_id).all();
  res.json({ data: users.results });
});

app.get('/api/v1/users/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const user = db.prepare(
    `SELECT id, email, first_name, last_name, role, mfa_enabled, status, last_login, failed_login_attempts, locked_until, created_at, updated_at
     FROM users WHERE id = ? AND tenant_id = ?`
  ).bind(req.params.id, req.user.tenant_id).first();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ data: user });
});

app.post('/api/v1/users', requireAuth, async (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const { email, password, first_name, last_name, role } = req.body;
  if (!email || !password || !first_name || !last_name) {
    return res.status(400).json({ error: 'email, password, first_name, and last_name are required' });
  }
  if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
  if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
  const validRoles = ['admin', 'governance_lead', 'reviewer', 'viewer'];
  const userRole = validRoles.includes(role) ? role : 'viewer';

  try {
    const id = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    db.prepare(
      `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`
    ).bind(id, req.user.tenant_id, sanitizeString(email, 254), passwordHash,
      sanitizeString(first_name, 100), sanitizeString(last_name, 100), userRole).run();
    auditLog(req.user.tenant_id, req.user.user_id, 'create', 'user', id, { email, role: userRole });
    res.status(201).json({
      data: { id, email, first_name, last_name, role: userRole, status: 'active' },
      message: 'User created successfully',
    });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Email already exists in this organization' });
    console.error('Create user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/v1/users/:id', requireAuth, async (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const existing = db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'User not found' });

  const updates = []; const values = [];
  if (req.body.first_name !== undefined) { updates.push('first_name = ?'); values.push(sanitizeString(req.body.first_name, 100)); }
  if (req.body.last_name !== undefined) { updates.push('last_name = ?'); values.push(sanitizeString(req.body.last_name, 100)); }
  if (req.body.role !== undefined) {
    const validRoles = ['admin', 'governance_lead', 'reviewer', 'viewer'];
    if (validRoles.includes(req.body.role)) { updates.push('role = ?'); values.push(req.body.role); }
  }
  if (req.body.status !== undefined) {
    const validStatuses = ['active', 'deactivated'];
    if (validStatuses.includes(req.body.status)) { updates.push('status = ?'); values.push(req.body.status); }
  }
  if (req.body.password) {
    if (req.body.password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
    const passwordHash = await hashPassword(req.body.password);
    updates.push('password_hash = ?'); values.push(passwordHash);
    updates.push('failed_login_attempts = 0');
    updates.push('locked_until = NULL');
  }
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`)
    .bind(...values, req.params.id, req.user.tenant_id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'user', req.params.id, { fields: Object.keys(req.body) });

  const updated = db.prepare(
    `SELECT id, email, first_name, last_name, role, mfa_enabled, status, last_login, created_at, updated_at
     FROM users WHERE id = ?`
  ).bind(req.params.id).first();
  res.json({ data: updated });
});

app.delete('/api/v1/users/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  if (req.params.id === req.user.user_id) return res.status(400).json({ error: 'Cannot deactivate your own account' });
  const existing = db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'User not found' });
  db.prepare(`UPDATE users SET status = 'deactivated', updated_at = datetime('now') WHERE id = ?`).bind(req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'deactivate', 'user', req.params.id, {});
  res.json({ message: 'User deactivated' });
});

app.post('/api/v1/users/:id/unlock', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const existing = db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'User not found' });
  db.prepare(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, status = 'active', updated_at = datetime('now') WHERE id = ?`)
    .bind(req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'unlock', 'user', req.params.id, {});
  res.json({ message: 'User account unlocked' });
});

app.post('/api/v1/users/:id/reset-password', requireAuth, async (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const { new_password } = req.body;
  if (!new_password || new_password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
  const existing = db.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'User not found' });
  const passwordHash = await hashPassword(new_password);
  db.prepare(`UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?`)
    .bind(passwordHash, req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'reset_password', 'user', req.params.id, {});
  res.json({ message: 'Password reset successfully' });
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
  ).bind(id, req.user.tenant_id, sanitizeString(name, 200), b.vendor ? sanitizeString(b.vendor, 200) : null,
    b.version || null, category,
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
  const { ai_asset_id } = req.query;
  let where = 'WHERE r.tenant_id = ?';
  const params = [req.user.tenant_id];
  if (ai_asset_id) { where += ' AND r.ai_asset_id = ?'; params.push(ai_asset_id); }
  const results = db.prepare(
    `SELECT r.*, a.name as asset_name, a.category as asset_category, a.risk_tier,
      u.first_name || ' ' || u.last_name as assessor_name
     FROM risk_assessments r JOIN ai_assets a ON r.ai_asset_id = a.id JOIN users u ON r.assessor_id = u.id
     ${where} ORDER BY r.created_at DESC`
  ).bind(...params).all();
  res.json({ data: results.results });
});

app.get('/api/v1/risk-assessments/:id', requireAuth, (req, res) => {
  const assessment = db.prepare(
    `SELECT r.*, a.name as asset_name, a.category as asset_category, a.risk_tier,
      u.first_name || ' ' || u.last_name as assessor_name
     FROM risk_assessments r JOIN ai_assets a ON r.ai_asset_id = a.id JOIN users u ON r.assessor_id = u.id
     WHERE r.id = ? AND r.tenant_id = ?`
  ).bind(req.params.id, req.user.tenant_id).first();
  if (!assessment) return res.status(404).json({ error: 'Risk assessment not found' });
  res.json({ data: assessment });
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
      cybersecurity_score, regulatory_score, overall_risk_level, findings, recommendations, mitigation_plan, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')`
  ).bind(id, req.user.tenant_id, ai_asset_id, assessment_type, req.user.user_id,
    scores.patient_safety_score || null, scores.bias_fairness_score || null, scores.data_privacy_score || null,
    scores.clinical_validity_score || null, scores.cybersecurity_score || null, scores.regulatory_score || null,
    overallRisk, JSON.stringify(b.findings || {}), b.recommendations || null, b.mitigation_plan || null
  ).run();

  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'risk_assessment', id, { overall_risk_level: overallRisk });
  const assessment = db.prepare('SELECT * FROM risk_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: assessment });
});

app.put('/api/v1/risk-assessments/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM risk_assessments WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Risk assessment not found' });
  if (existing.status === 'approved') return res.status(400).json({ error: 'Cannot edit an approved assessment' });

  const updates = []; const values = [];
  const scoreFields = ['patient_safety_score', 'bias_fairness_score', 'data_privacy_score', 'clinical_validity_score', 'cybersecurity_score', 'regulatory_score'];
  const textFields = ['assessment_type', 'recommendations', 'mitigation_plan', 'status'];

  for (const f of scoreFields) {
    if (req.body[f] !== undefined) {
      const v = validateScore(req.body[f]);
      if (v !== null) { updates.push(`${f} = ?`); values.push(v); }
    }
  }
  for (const f of textFields) {
    if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  if (req.body.findings !== undefined) { updates.push('findings = ?'); values.push(JSON.stringify(req.body.findings)); }

  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

  // Recalculate overall risk if scores changed
  const merged = { ...existing };
  for (const f of scoreFields) { if (req.body[f] !== undefined) merged[f] = validateScore(req.body[f]) || merged[f]; }
  const allScored = scoreFields.every(f => merged[f] >= 1 && merged[f] <= 5);
  if (allScored) {
    const overallRisk = calculateOverallRisk(merged);
    updates.push('overall_risk_level = ?'); values.push(overallRisk);
  }
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE risk_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`)
    .bind(...values, req.params.id, req.user.tenant_id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'risk_assessment', req.params.id, {});
  const updated = db.prepare('SELECT * FROM risk_assessments WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
});

app.post('/api/v1/risk-assessments/:id/approve', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM risk_assessments WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const newStatus = req.body.approved ? 'approved' : 'rejected';
  db.prepare(`UPDATE risk_assessments SET status = ?, approved_by = ?, review_notes = ?, completed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`)
    .bind(newStatus, req.user.user_id, req.body.review_notes || null, req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, newStatus === 'approved' ? 'approve' : 'reject', 'risk_assessment', req.params.id, {});
  res.json({ message: `Assessment ${newStatus}` });
});

// ==================== IMPACT ASSESSMENTS ====================

app.get('/api/v1/impact-assessments', requireAuth, (req, res) => {
  const { ai_asset_id } = req.query;
  let where = 'WHERE ia.tenant_id = ?';
  const params = [req.user.tenant_id];
  if (ai_asset_id) { where += ' AND ia.ai_asset_id = ?'; params.push(ai_asset_id); }
  const results = db.prepare(
    `SELECT ia.*, a.name as asset_name, a.category, u.first_name || ' ' || u.last_name as assessor_name
     FROM impact_assessments ia JOIN ai_assets a ON ia.ai_asset_id = a.id JOIN users u ON ia.assessor_id = u.id
     ${where} ORDER BY ia.created_at DESC`
  ).bind(...params).all();
  res.json({ data: results.results });
});

app.get('/api/v1/impact-assessments/:id', requireAuth, (req, res) => {
  const assessment = db.prepare(
    `SELECT ia.*, a.name as asset_name, a.category, u.first_name || ' ' || u.last_name as assessor_name
     FROM impact_assessments ia JOIN ai_assets a ON ia.ai_asset_id = a.id JOIN users u ON ia.assessor_id = u.id
     WHERE ia.id = ? AND ia.tenant_id = ?`
  ).bind(req.params.id, req.user.tenant_id).first();
  if (!assessment) return res.status(404).json({ error: 'Impact assessment not found' });
  res.json({ data: assessment });
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
  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'impact_assessment', id, {});
  const aia = db.prepare('SELECT * FROM impact_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: aia });
});

app.put('/api/v1/impact-assessments/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM impact_assessments WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Impact assessment not found' });

  const updates = []; const values = [];
  const textFields = ['assessment_period', 'remediation_plan', 'remediation_status', 'status'];
  for (const f of textFields) {
    if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  const jsonFields = ['demographic_groups_tested', 'performance_by_group', 'bias_indicators', 'drift_details', 'clinical_outcomes'];
  for (const f of jsonFields) {
    if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(JSON.stringify(req.body[f])); }
  }
  if (req.body.drift_detected !== undefined) { updates.push('drift_detected = ?'); values.push(req.body.drift_detected ? 1 : 0); }
  if (req.body.remediation_required !== undefined) { updates.push('remediation_required = ?'); values.push(req.body.remediation_required ? 1 : 0); }
  if (req.body.disparate_impact_ratio !== undefined) { updates.push('disparate_impact_ratio = ?'); values.push(req.body.disparate_impact_ratio); }
  if (req.body.status === 'completed') { updates.push("completed_at = datetime('now')"); }

  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE impact_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`)
    .bind(...values, req.params.id, req.user.tenant_id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'impact_assessment', req.params.id, {});
  const updated = db.prepare('SELECT * FROM impact_assessments WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
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

app.get('/api/v1/vendor-assessments/:id', requireAuth, (req, res) => {
  const va = db.prepare(
    `SELECT va.*, u.first_name || ' ' || u.last_name as assessor_name FROM vendor_assessments va
     LEFT JOIN users u ON va.assessed_by = u.id WHERE va.id = ? AND va.tenant_id = ?`
  ).bind(req.params.id, req.user.tenant_id).first();
  if (!va) return res.status(404).json({ error: 'Vendor assessment not found' });
  res.json({ data: va });
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
  ).bind(id, req.user.tenant_id, sanitizeString(vendor_name, 200), sanitizeString(product_name, 200),
    b.training_data_provenance || null, b.validation_methodology || null,
    b.transparency_score || null, b.bias_testing_score || null,
    b.security_score || null, b.data_practices_score || null, b.contractual_score || null,
    b.recommendation || 'pending', req.user.user_id
  ).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'vendor_assessment', id, { vendor_name, product_name });
  const va = db.prepare('SELECT * FROM vendor_assessments WHERE id = ?').bind(id).first();
  res.status(201).json({ data: va });
});

app.put('/api/v1/vendor-assessments/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM vendor_assessments WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Vendor assessment not found' });

  const updates = []; const values = [];
  const textFields = ['vendor_name', 'product_name', 'training_data_provenance', 'validation_methodology', 'recommendation', 'conditions'];
  for (const f of textFields) {
    if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  const scoreFields = ['transparency_score', 'bias_testing_score', 'security_score', 'data_practices_score', 'contractual_score'];
  for (const f of scoreFields) {
    if (req.body[f] !== undefined) {
      const v = validateScore(req.body[f]);
      if (v !== null) { updates.push(`${f} = ?`); values.push(v); }
    }
  }
  if (req.body.next_reassessment !== undefined) { updates.push('next_reassessment = ?'); values.push(req.body.next_reassessment); }

  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE vendor_assessments SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`)
    .bind(...values, req.params.id, req.user.tenant_id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'vendor_assessment', req.params.id, {});
  const updated = db.prepare('SELECT * FROM vendor_assessments WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
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
  const { status, severity, ai_asset_id } = req.query;
  let where = 'WHERE i.tenant_id = ?'; const params = [req.user.tenant_id];
  if (status) { where += ' AND i.status = ?'; params.push(status); }
  if (severity) { where += ' AND i.severity = ?'; params.push(severity); }
  if (ai_asset_id) { where += ' AND i.ai_asset_id = ?'; params.push(ai_asset_id); }
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
  ).bind(id, req.user.tenant_id, ai_asset_id, req.user.user_id, incident_type, severity,
    sanitizeString(title, 300), sanitizeString(description, 5000), req.body.patient_impact ? 1 : 0).run();
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
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'incident', req.params.id, {});
  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
});

// ==================== AUDIT LOG ====================

app.get('/api/v1/audit-log', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const { entity_type, user_id, action, limit = 100 } = req.query;
  let where = 'WHERE al.tenant_id = ?'; const params = [req.user.tenant_id];
  if (entity_type) { where += ' AND al.entity_type = ?'; params.push(entity_type); }
  if (user_id) { where += ' AND al.user_id = ?'; params.push(user_id); }
  if (action) { where += ' AND al.action = ?'; params.push(action); }
  const results = db.prepare(
    `SELECT al.*, u.first_name || ' ' || u.last_name as user_name, u.email as user_email
     FROM audit_log al LEFT JOIN users u ON al.user_id = u.id
     ${where} ORDER BY al.created_at DESC LIMIT ?`
  ).bind(...params, Math.min(+limit, 500)).all();
  res.json({ data: results.results });
});

// ==================== EVIDENCE MANAGEMENT ====================

app.get('/api/v1/evidence', requireAuth, (req, res) => {
  const { entity_type, entity_id } = req.query;
  let where = 'WHERE e.tenant_id = ?';
  const params = [req.user.tenant_id];
  if (entity_type) { where += ' AND e.entity_type = ?'; params.push(entity_type); }
  if (entity_id) { where += ' AND e.entity_id = ?'; params.push(entity_id); }
  const results = db.prepare(
    `SELECT e.*, u.first_name || ' ' || u.last_name as uploaded_by_name
     FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id
     ${where} ORDER BY e.created_at DESC`
  ).bind(...params).all();
  res.json({ data: results.results });
});

app.post('/api/v1/evidence', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead', 'reviewer'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const { entity_type, entity_id, title, description, evidence_type, url } = req.body;
  if (!entity_type || !entity_id || !title) return res.status(400).json({ error: 'entity_type, entity_id, and title are required' });

  const validEntityTypes = ['ai_asset', 'risk_assessment', 'impact_assessment', 'vendor_assessment', 'control_implementation'];
  if (!validEntityTypes.includes(entity_type)) return res.status(400).json({ error: 'Invalid entity_type' });

  const validEvidenceTypes = ['document', 'link', 'screenshot', 'test_result', 'policy', 'audit_report', 'certification', 'other'];
  const evType = validEvidenceTypes.includes(evidence_type) ? evidence_type : 'other';

  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO evidence (id, tenant_id, entity_type, entity_id, title, description, evidence_type, url, uploaded_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, req.user.tenant_id, entity_type, entity_id, sanitizeString(title, 300),
    description ? sanitizeString(description, 2000) : null, evType, url || null, req.user.user_id).run();

  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'evidence', id, { entity_type, entity_id, title });
  const evidence = db.prepare('SELECT * FROM evidence WHERE id = ?').bind(id).first();
  res.status(201).json({ data: evidence });
});

app.delete('/api/v1/evidence/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin', 'governance_lead'])) return res.status(403).json({ error: 'Insufficient permissions' });
  const existing = db.prepare('SELECT * FROM evidence WHERE id = ? AND tenant_id = ?').bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Evidence not found' });
  db.prepare('DELETE FROM evidence WHERE id = ?').bind(req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'delete', 'evidence', req.params.id, { title: existing.title });
  res.json({ message: 'Evidence deleted' });
});

// ==================== ONBOARDING PROGRESS ====================

app.get('/api/v1/onboarding/progress', requireAuth, (req, res) => {
  const tid = req.user.tenant_id;
  const hasAssets = db.prepare('SELECT COUNT(*) as c FROM ai_assets WHERE tenant_id = ?').bind(tid).first().c > 0;
  const hasRiskAssessment = db.prepare('SELECT COUNT(*) as c FROM risk_assessments WHERE tenant_id = ?').bind(tid).first().c > 0;
  const hasImpactAssessment = db.prepare('SELECT COUNT(*) as c FROM impact_assessments WHERE tenant_id = ?').bind(tid).first().c > 0;
  const hasCompliance = db.prepare('SELECT COUNT(*) as c FROM control_implementations WHERE tenant_id = ?').bind(tid).first().c > 0;
  const hasVendorAssessment = db.prepare('SELECT COUNT(*) as c FROM vendor_assessments WHERE tenant_id = ?').bind(tid).first().c > 0;
  const hasMaturity = db.prepare('SELECT COUNT(*) as c FROM maturity_assessments WHERE tenant_id = ?').bind(tid).first().c > 0;
  const hasMultipleUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE tenant_id = ? AND status = \'active\'').bind(tid).first().c > 1;

  const steps = [
    { key: 'register', label: 'Create your organization', completed: true, description: 'Set up your ForgeAI Govern account' },
    { key: 'add_asset', label: 'Register an AI system', completed: hasAssets, description: 'Add your first AI/ML system to the governance registry' },
    { key: 'risk_assessment', label: 'Complete a risk assessment', completed: hasRiskAssessment, description: 'Evaluate risk across 6 dimensions for an AI system' },
    { key: 'impact_assessment', label: 'Run an impact assessment', completed: hasImpactAssessment, description: 'Assess algorithmic bias and fairness' },
    { key: 'compliance', label: 'Map compliance controls', completed: hasCompliance, description: 'Implement controls from NIST AI RMF, FDA SaMD, HIPAA' },
    { key: 'vendor_assessment', label: 'Assess a vendor', completed: hasVendorAssessment, description: 'Evaluate a third-party AI vendor' },
    { key: 'maturity', label: 'Assess governance maturity', completed: hasMaturity, description: 'Score your org across 7 governance domains' },
    { key: 'invite_team', label: 'Invite team members', completed: hasMultipleUsers, description: 'Add colleagues with appropriate roles' },
  ];

  const completedCount = steps.filter(s => s.completed).length;
  const percentage = Math.round((completedCount / steps.length) * 100);

  res.json({ data: { steps, completed: completedCount, total: steps.length, percentage } });
});

// ==================== SUPPORT TICKETS ====================

app.get('/api/v1/support-tickets', requireAuth, (req, res) => {
  const { status, category } = req.query;
  const isAdmin = authorize(req.user, ['admin']);
  let where = 'WHERE t.tenant_id = ?';
  const params = [req.user.tenant_id];
  if (!isAdmin) { where += ' AND t.created_by = ?'; params.push(req.user.user_id); }
  if (status) { where += ' AND t.status = ?'; params.push(status); }
  if (category) { where += ' AND t.category = ?'; params.push(category); }
  const results = db.prepare(
    `SELECT t.*, u.first_name || ' ' || u.last_name as created_by_name, u.email as created_by_email
     FROM support_tickets t JOIN users u ON t.created_by = u.id
     ${where} ORDER BY t.created_at DESC`
  ).bind(...params).all();
  res.json({ data: results.results });
});

app.get('/api/v1/support-tickets/:id', requireAuth, (req, res) => {
  const ticket = db.prepare(
    `SELECT t.*, u.first_name || ' ' || u.last_name as created_by_name
     FROM support_tickets t JOIN users u ON t.created_by = u.id
     WHERE t.id = ? AND t.tenant_id = ?`
  ).bind(req.params.id, req.user.tenant_id).first();
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  if (!authorize(req.user, ['admin']) && ticket.created_by !== req.user.user_id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json({ data: ticket });
});

app.post('/api/v1/support-tickets', requireAuth, (req, res) => {
  const { subject, description, category, priority } = req.body;
  if (!subject || !description) return res.status(400).json({ error: 'subject and description are required' });

  const validCategories = ['general', 'technical', 'compliance', 'billing', 'feature_request', 'bug_report'];
  const validPriorities = ['low', 'medium', 'high', 'urgent'];
  const cat = validCategories.includes(category) ? category : 'general';
  const pri = validPriorities.includes(priority) ? priority : 'medium';

  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO support_tickets (id, tenant_id, created_by, subject, description, category, priority)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, req.user.tenant_id, req.user.user_id, sanitizeString(subject, 300),
    sanitizeString(description, 5000), cat, pri).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'support_ticket', id, { subject, category: cat });
  const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').bind(id).first();
  res.status(201).json({ data: ticket });
});

app.put('/api/v1/support-tickets/:id', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT * FROM support_tickets WHERE id = ? AND tenant_id = ?')
    .bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Ticket not found' });

  const isAdmin = authorize(req.user, ['admin']);
  const isOwner = existing.created_by === req.user.user_id;
  if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Access denied' });

  const updates = []; const values = [];
  if (req.body.status !== undefined) {
    const validStatuses = ['open', 'in_progress', 'waiting', 'resolved', 'closed'];
    if (validStatuses.includes(req.body.status)) {
      updates.push('status = ?'); values.push(req.body.status);
      if (['resolved', 'closed'].includes(req.body.status)) updates.push("resolved_at = datetime('now')");
    }
  }
  if (req.body.admin_notes !== undefined && isAdmin) {
    updates.push('admin_notes = ?'); values.push(sanitizeString(req.body.admin_notes, 5000));
  }
  if (req.body.priority !== undefined && isAdmin) {
    const validPriorities = ['low', 'medium', 'high', 'urgent'];
    if (validPriorities.includes(req.body.priority)) { updates.push('priority = ?'); values.push(req.body.priority); }
  }
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE support_tickets SET ${updates.join(', ')} WHERE id = ?`).bind(...values, req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'support_ticket', req.params.id, {});
  const updated = db.prepare('SELECT * FROM support_tickets WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
});

// ==================== FEATURE REQUESTS ====================

app.get('/api/v1/feature-requests', requireAuth, (req, res) => {
  const { status, category, sort } = req.query;
  let where = 'WHERE fr.tenant_id = ?';
  const params = [req.user.tenant_id];
  if (status) { where += ' AND fr.status = ?'; params.push(status); }
  if (category) { where += ' AND fr.category = ?'; params.push(category); }
  const orderBy = sort === 'votes' ? 'fr.vote_count DESC' : 'fr.created_at DESC';
  const results = db.prepare(
    `SELECT fr.*, u.first_name || ' ' || u.last_name as created_by_name,
      (SELECT COUNT(*) FROM feature_request_votes v WHERE v.feature_request_id = fr.id AND v.user_id = ?) as user_voted
     FROM feature_requests fr JOIN users u ON fr.created_by = u.id
     ${where} ORDER BY ${orderBy}`
  ).bind(req.user.user_id, ...params).all();
  res.json({ data: results.results });
});

app.post('/api/v1/feature-requests', requireAuth, (req, res) => {
  const { title, description, category } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'title and description are required' });

  const validCategories = ['governance', 'compliance', 'reporting', 'monitoring', 'integration', 'general'];
  const cat = validCategories.includes(category) ? category : 'general';

  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO feature_requests (id, tenant_id, created_by, title, description, category, vote_count)
     VALUES (?, ?, ?, ?, ?, ?, 1)`
  ).bind(id, req.user.tenant_id, req.user.user_id, sanitizeString(title, 300),
    sanitizeString(description, 5000), cat).run();

  // Auto-vote for creator
  db.prepare(
    `INSERT INTO feature_request_votes (id, feature_request_id, user_id, tenant_id)
     VALUES (?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), id, req.user.user_id, req.user.tenant_id).run();

  auditLog(req.user.tenant_id, req.user.user_id, 'create', 'feature_request', id, { title, category: cat });
  const fr = db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(id).first();
  res.status(201).json({ data: fr });
});

app.post('/api/v1/feature-requests/:id/vote', requireAuth, (req, res) => {
  const fr = db.prepare('SELECT * FROM feature_requests WHERE id = ? AND tenant_id = ?')
    .bind(req.params.id, req.user.tenant_id).first();
  if (!fr) return res.status(404).json({ error: 'Feature request not found' });

  const existingVote = db.prepare(
    'SELECT id FROM feature_request_votes WHERE feature_request_id = ? AND user_id = ?'
  ).bind(req.params.id, req.user.user_id).first();

  if (existingVote) {
    // Unvote
    db.prepare('DELETE FROM feature_request_votes WHERE id = ?').bind(existingVote.id).run();
    db.prepare('UPDATE feature_requests SET vote_count = vote_count - 1 WHERE id = ?').bind(req.params.id).run();
    const updated = db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(req.params.id).first();
    return res.json({ data: updated, voted: false });
  }

  // Vote
  db.prepare(
    `INSERT INTO feature_request_votes (id, feature_request_id, user_id, tenant_id)
     VALUES (?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), req.params.id, req.user.user_id, req.user.tenant_id).run();
  db.prepare('UPDATE feature_requests SET vote_count = vote_count + 1 WHERE id = ?').bind(req.params.id).run();
  const updated = db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated, voted: true });
});

app.put('/api/v1/feature-requests/:id', requireAuth, (req, res) => {
  if (!authorize(req.user, ['admin'])) return res.status(403).json({ error: 'Admin access required' });
  const existing = db.prepare('SELECT * FROM feature_requests WHERE id = ? AND tenant_id = ?')
    .bind(req.params.id, req.user.tenant_id).first();
  if (!existing) return res.status(404).json({ error: 'Feature request not found' });

  const updates = []; const values = [];
  if (req.body.status !== undefined) {
    const validStatuses = ['submitted', 'under_review', 'planned', 'in_progress', 'completed', 'declined'];
    if (validStatuses.includes(req.body.status)) { updates.push('status = ?'); values.push(req.body.status); }
  }
  if (req.body.admin_response !== undefined) {
    updates.push('admin_response = ?'); values.push(sanitizeString(req.body.admin_response, 5000));
  }
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  updates.push("updated_at = datetime('now')");

  db.prepare(`UPDATE feature_requests SET ${updates.join(', ')} WHERE id = ?`).bind(...values, req.params.id).run();
  auditLog(req.user.tenant_id, req.user.user_id, 'update', 'feature_request', req.params.id, {});
  const updated = db.prepare('SELECT * FROM feature_requests WHERE id = ?').bind(req.params.id).first();
  res.json({ data: updated });
});

// ==================== KNOWLEDGE BASE ====================

app.get('/api/v1/knowledge-base', requireAuth, (req, res) => {
  const articles = [
    {
      id: 'kb-nist-ai-rmf', category: 'framework', title: 'NIST AI Risk Management Framework (AI RMF)',
      summary: 'The NIST AI RMF provides a structured approach to managing AI risks through four core functions: Govern, Map, Measure, and Manage.',
      content: 'The NIST AI RMF 1.0 establishes a voluntary framework for managing risks associated with AI systems throughout their lifecycle. It defines four core functions:\n\n**Govern** - Establish and maintain organizational AI governance structures, policies, and processes.\n**Map** - Categorize AI systems, identify stakeholders, and understand the context of AI deployment.\n**Measure** - Assess and monitor AI risks including performance, bias, security, and compliance.\n**Manage** - Implement risk mitigation strategies, monitor controls, and respond to incidents.\n\nForgeAI Govern maps 39 controls across these four families.',
      frameworks: ['NIST AI RMF 1.0'], relevance: 'core',
    },
    {
      id: 'kb-fda-samd', category: 'regulatory', title: 'FDA Software as Medical Device (SaMD) Classification',
      summary: 'FDA regulates AI/ML-based Software as a Medical Device through pre-market pathways including 510(k), De Novo, and PMA.',
      content: 'The FDA classifies AI/ML-enabled medical devices based on the significance of the information provided by the SaMD to the healthcare decision and the state of the healthcare situation or condition. Key pathways:\n\n**510(k)** - Demonstrates substantial equivalence to a predicate device. Most common pathway for moderate-risk AI tools.\n**De Novo** - For novel, low-to-moderate risk devices without a predicate. Increasingly used for AI-based diagnostic tools.\n**PMA** - Pre-Market Approval required for high-risk (Class III) devices.\n\nThe FDA Action Plan for AI/ML-Based SaMD introduces the concept of Predetermined Change Control Plans (PCCPs) to accommodate iterative model updates.',
      frameworks: ['FDA SaMD', '21 CFR Part 820'], relevance: 'core',
    },
    {
      id: 'kb-hipaa-ai', category: 'regulatory', title: 'HIPAA Compliance for AI Systems',
      summary: 'AI systems processing Protected Health Information (PHI) must comply with HIPAA Privacy, Security, and Breach Notification Rules.',
      content: 'When AI systems access or process PHI, HIPAA requirements apply:\n\n**Privacy Rule** - Establishes minimum necessary standards for PHI use. AI training data must be de-identified per Safe Harbor or Expert Determination methods.\n**Security Rule** - Requires administrative, physical, and technical safeguards for ePHI. AI systems must implement access controls, audit logging, encryption, and transmission security.\n**Breach Notification** - AI-related data breaches affecting PHI must be reported within 60 days.\n**Business Associate Agreements** - Required with AI vendors that process PHI on behalf of covered entities.\n\nForgeAI Govern tracks PHI access per AI system and maps relevant HIPAA controls.',
      frameworks: ['HIPAA', '45 CFR Parts 160, 164'], relevance: 'core',
    },
    {
      id: 'kb-onc-hti1', category: 'regulatory', title: 'ONC HTI-1 Final Rule - Decision Support Interventions',
      summary: 'The ONC HTI-1 rule establishes transparency and risk management requirements for AI-enabled clinical decision support within certified health IT.',
      content: 'The ONC Health Data, Technology, and Interoperability (HTI-1) Final Rule introduces requirements for Predictive Decision Support Interventions (DSIs) in certified health IT:\n\n**Source Attribute Transparency** - DSIs must disclose the intervention developer, funding source, and whether the output is based on a predictive model.\n**Risk Management Practices** - Developers must employ practices including bias analysis, validation studies, and ongoing performance monitoring.\n**Intervention Details** - Must be made available including intended use, training data characteristics, and known limitations.\n\nThese requirements align with ForgeAI Govern\'s AI asset metadata, bias testing, and transparency controls.',
      frameworks: ['ONC HTI-1', '45 CFR Part 170'], relevance: 'core',
    },
    {
      id: 'kb-risk-assessment', category: 'guide', title: 'How to Conduct an AI Risk Assessment',
      summary: 'Step-by-step guide to evaluating AI system risk across 6 dimensions using the ForgeAI weighted scoring model.',
      content: 'ForgeAI Govern uses a 6-dimension weighted risk model:\n\n1. **Patient Safety (25%)** - Potential for direct patient harm from incorrect outputs. Score 5 if errors could cause mortality.\n2. **Bias & Fairness (20%)** - Risk of disparate impact across demographic groups. Test with representative populations.\n3. **Data Privacy (15%)** - PHI exposure risk, data minimization compliance, de-identification effectiveness.\n4. **Clinical Validity (15%)** - Scientific evidence supporting the AI\'s clinical claims. Peer-reviewed validation studies.\n5. **Cybersecurity (15%)** - Attack surface, model poisoning risk, adversarial robustness, API security.\n6. **Regulatory (10%)** - Compliance gaps with FDA, HIPAA, state laws, and organizational policies.\n\n**Overall Risk Calculation:**\n- Critical: weighted score >= 4.0 OR patient safety = 5\n- High: weighted score >= 3.0\n- Moderate: weighted score >= 2.0\n- Low: weighted score < 2.0',
      frameworks: ['NIST AI RMF', 'FDA SaMD'], relevance: 'guide',
    },
    {
      id: 'kb-vendor-due-diligence', category: 'guide', title: 'AI Vendor Due Diligence Best Practices',
      summary: 'Framework for evaluating third-party AI vendors on transparency, bias testing, security, data practices, and contractual provisions.',
      content: 'When evaluating AI vendors, assess these 5 dimensions:\n\n1. **Transparency (15%)** - Model architecture disclosure, training data documentation, algorithm explainability.\n2. **Bias Testing (25%)** - Demographic testing methodology, results disaggregation, disparate impact analysis.\n3. **Security (25%)** - SOC 2 compliance, encryption standards, penetration testing, vulnerability management.\n4. **Data Practices (20%)** - Data handling policies, PHI protections, data retention/deletion, sub-processor agreements.\n5. **Contractual (15%)** - Audit rights, SLAs, performance guarantees, liability provisions, exit clauses.\n\n**Scoring:** Each dimension rated 1-5, weighted to produce a 0-100 overall score. Scores below 40 are rejected, 40-60 conditional, above 60 approved.',
      frameworks: ['NIST AI RMF', 'HIPAA BAA'], relevance: 'guide',
    },
    {
      id: 'kb-incident-response', category: 'guide', title: 'AI Incident Response Playbook',
      summary: 'Procedures for responding to AI-related incidents including patient safety events, bias detection, and model failures.',
      content: 'ForgeAI Govern supports structured incident response:\n\n**Severity Levels:**\n- **Critical** - Patient safety impact or data breach. Triggers automatic system suspension.\n- **High** - Significant performance degradation or bias detected. Requires 24-hour response.\n- **Moderate** - Notable drift or minor compliance gaps. Requires 72-hour review.\n- **Low** - Informational findings or minor anomalies. Tracked for pattern analysis.\n\n**Response Steps:**\n1. Report incident with severity classification\n2. For critical/patient safety: system auto-suspended pending investigation\n3. Assign investigation team and document root cause\n4. Implement corrective actions with evidence\n5. Review and close with audit trail\n6. Update risk assessment based on findings',
      frameworks: ['NIST AI RMF Manage', 'HIPAA Breach Notification'], relevance: 'guide',
    },
  ];

  const { category: cat, search } = req.query;
  let filtered = articles;
  if (cat) filtered = filtered.filter(a => a.category === cat);
  if (search) {
    const term = search.toLowerCase();
    filtered = filtered.filter(a => a.title.toLowerCase().includes(term) || a.summary.toLowerCase().includes(term) || a.content.toLowerCase().includes(term));
  }
  res.json({ data: filtered });
});

// ==================== API DOCUMENTATION ====================

app.get('/api/v1/docs', (req, res) => {
  const docs = {
    title: 'ForgeAI Govern API',
    version: '1.0.0',
    description: 'Healthcare AI Governance Platform REST API',
    base_url: '/api/v1',
    authentication: {
      type: 'Bearer Token (JWT)',
      header: 'Authorization: Bearer <token>',
      token_expiry: '15 minutes',
      refresh: 'POST /api/v1/auth/refresh with refresh_token',
    },
    rate_limits: {
      global: '200 requests/minute per IP',
      auth: '10 attempts/15 minutes per IP',
    },
    endpoints: [
      { method: 'GET', path: '/health', auth: false, description: 'Health check' },
      { method: 'POST', path: '/auth/register', auth: false, description: 'Register organization', body: 'organization_name, email, password, first_name, last_name' },
      { method: 'POST', path: '/auth/login', auth: false, description: 'Sign in', body: 'email, password' },
      { method: 'POST', path: '/auth/refresh', auth: false, description: 'Refresh access token', body: 'refresh_token' },
      { method: 'GET', path: '/ai-assets', auth: true, description: 'List AI assets', query: 'page, limit, category, risk_tier, status, search' },
      { method: 'GET', path: '/ai-assets/:id', auth: true, description: 'Get AI asset detail' },
      { method: 'POST', path: '/ai-assets', auth: true, description: 'Register AI asset', roles: 'admin, governance_lead' },
      { method: 'PUT', path: '/ai-assets/:id', auth: true, description: 'Update AI asset', roles: 'admin, governance_lead, reviewer' },
      { method: 'DELETE', path: '/ai-assets/:id', auth: true, description: 'Decommission AI asset', roles: 'admin' },
      { method: 'GET', path: '/risk-assessments', auth: true, description: 'List risk assessments', query: 'ai_asset_id' },
      { method: 'POST', path: '/risk-assessments', auth: true, description: 'Create risk assessment', roles: 'admin, governance_lead, reviewer' },
      { method: 'PUT', path: '/risk-assessments/:id', auth: true, description: 'Update risk assessment' },
      { method: 'POST', path: '/risk-assessments/:id/approve', auth: true, description: 'Approve/reject assessment', roles: 'admin, governance_lead' },
      { method: 'GET', path: '/impact-assessments', auth: true, description: 'List impact assessments', query: 'ai_asset_id' },
      { method: 'POST', path: '/impact-assessments', auth: true, description: 'Create impact assessment' },
      { method: 'PUT', path: '/impact-assessments/:id', auth: true, description: 'Update impact assessment' },
      { method: 'GET', path: '/controls', auth: true, description: 'List compliance controls', query: 'family, search' },
      { method: 'GET', path: '/implementations', auth: true, description: 'List control implementations', query: 'ai_asset_id, status' },
      { method: 'POST', path: '/implementations', auth: true, description: 'Record control implementation' },
      { method: 'GET', path: '/vendor-assessments', auth: true, description: 'List vendor assessments' },
      { method: 'POST', path: '/vendor-assessments', auth: true, description: 'Create vendor assessment' },
      { method: 'PUT', path: '/vendor-assessments/:id', auth: true, description: 'Update vendor assessment' },
      { method: 'GET', path: '/incidents', auth: true, description: 'List incidents', query: 'status, severity, ai_asset_id' },
      { method: 'POST', path: '/incidents', auth: true, description: 'Report incident' },
      { method: 'PUT', path: '/incidents/:id', auth: true, description: 'Update incident' },
      { method: 'GET', path: '/evidence', auth: true, description: 'List evidence', query: 'entity_type, entity_id' },
      { method: 'POST', path: '/evidence', auth: true, description: 'Add evidence' },
      { method: 'DELETE', path: '/evidence/:id', auth: true, description: 'Delete evidence' },
      { method: 'GET', path: '/support-tickets', auth: true, description: 'List support tickets (own or all for admin)' },
      { method: 'POST', path: '/support-tickets', auth: true, description: 'Create support ticket' },
      { method: 'PUT', path: '/support-tickets/:id', auth: true, description: 'Update support ticket' },
      { method: 'GET', path: '/feature-requests', auth: true, description: 'List feature requests', query: 'status, category, sort' },
      { method: 'POST', path: '/feature-requests', auth: true, description: 'Submit feature request' },
      { method: 'POST', path: '/feature-requests/:id/vote', auth: true, description: 'Toggle vote on feature request' },
      { method: 'PUT', path: '/feature-requests/:id', auth: true, description: 'Update feature request status', roles: 'admin' },
      { method: 'GET', path: '/knowledge-base', auth: true, description: 'Get knowledge base articles', query: 'category, search' },
      { method: 'GET', path: '/onboarding/progress', auth: true, description: 'Get onboarding checklist progress' },
      { method: 'GET', path: '/dashboard/stats', auth: true, description: 'Dashboard statistics' },
      { method: 'GET', path: '/reports/compliance', auth: true, description: 'Compliance summary report' },
      { method: 'GET', path: '/reports/executive', auth: true, description: 'Executive summary report' },
      { method: 'GET', path: '/export/:type', auth: true, description: 'Export data as CSV (assets, risk-assessments, compliance, vendor-assessments, incidents, evidence)' },
      { method: 'GET', path: '/users', auth: true, description: 'List users', roles: 'admin' },
      { method: 'POST', path: '/users', auth: true, description: 'Create user', roles: 'admin' },
      { method: 'PUT', path: '/users/:id', auth: true, description: 'Update user', roles: 'admin' },
      { method: 'GET', path: '/audit-log', auth: true, description: 'View audit log', roles: 'admin' },
      { method: 'GET', path: '/docs', auth: false, description: 'This API documentation' },
    ],
  };
  res.json(docs);
});

// ==================== EXPORT ====================

function generateCSV(columns, rows) {
  const header = columns.map(c => `"${c.label}"`).join(',');
  const body = rows.map(row =>
    columns.map(c => {
      const val = row[c.key];
      return `"${String(val ?? '').replace(/"/g, '""')}"`;
    }).join(',')
  ).join('\n');
  return header + '\n' + body;
}

function sendCSV(res, filename, csv) {
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csv);
}

app.get('/api/v1/export/assets', requireAuth, (req, res) => {
  const assets = db.prepare(
    `SELECT a.*, u1.first_name || ' ' || u1.last_name as owner_name
     FROM ai_assets a LEFT JOIN users u1 ON a.owner_user_id = u1.id
     WHERE a.tenant_id = ? ORDER BY a.name`
  ).bind(req.user.tenant_id).all();
  const columns = [
    { key: 'name', label: 'Name' }, { key: 'vendor', label: 'Vendor' }, { key: 'version', label: 'Version' },
    { key: 'category', label: 'Category' }, { key: 'risk_tier', label: 'Risk Tier' },
    { key: 'deployment_status', label: 'Status' }, { key: 'phi_access', label: 'PHI Access' },
    { key: 'department', label: 'Department' }, { key: 'owner_name', label: 'Owner' },
    { key: 'fda_classification', label: 'FDA Classification' }, { key: 'created_at', label: 'Created' },
  ];
  sendCSV(res, 'ai-assets.csv', generateCSV(columns, assets.results));
});

app.get('/api/v1/export/risk-assessments', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT r.*, a.name as asset_name, u.first_name || ' ' || u.last_name as assessor_name
     FROM risk_assessments r JOIN ai_assets a ON r.ai_asset_id = a.id JOIN users u ON r.assessor_id = u.id
     WHERE r.tenant_id = ? ORDER BY r.created_at DESC`
  ).bind(req.user.tenant_id).all();
  const columns = [
    { key: 'asset_name', label: 'AI System' }, { key: 'assessment_type', label: 'Type' },
    { key: 'patient_safety_score', label: 'Patient Safety' }, { key: 'bias_fairness_score', label: 'Bias/Fairness' },
    { key: 'data_privacy_score', label: 'Data Privacy' }, { key: 'clinical_validity_score', label: 'Clinical Validity' },
    { key: 'cybersecurity_score', label: 'Cybersecurity' }, { key: 'regulatory_score', label: 'Regulatory' },
    { key: 'overall_risk_level', label: 'Overall Risk' }, { key: 'status', label: 'Status' },
    { key: 'assessor_name', label: 'Assessor' }, { key: 'created_at', label: 'Date' },
  ];
  sendCSV(res, 'risk-assessments.csv', generateCSV(columns, results.results));
});

app.get('/api/v1/export/compliance', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT cc.control_id, cc.family, cc.title, cc.nist_ai_rmf_ref, cc.fda_samd_ref, cc.onc_hti1_ref, cc.hipaa_ref,
      ci.implementation_status
     FROM compliance_controls cc
     LEFT JOIN control_implementations ci ON cc.id = ci.control_id AND ci.tenant_id = ?
     ORDER BY cc.family, cc.control_id`
  ).bind(req.user.tenant_id).all();
  const columns = [
    { key: 'control_id', label: 'Control ID' }, { key: 'family', label: 'Family' }, { key: 'title', label: 'Title' },
    { key: 'implementation_status', label: 'Status' }, { key: 'nist_ai_rmf_ref', label: 'NIST AI RMF' },
    { key: 'fda_samd_ref', label: 'FDA SaMD' }, { key: 'onc_hti1_ref', label: 'ONC HTI-1' }, { key: 'hipaa_ref', label: 'HIPAA' },
  ];
  sendCSV(res, 'compliance-status.csv', generateCSV(columns, results.results));
});

app.get('/api/v1/export/vendor-assessments', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT va.*, u.first_name || ' ' || u.last_name as assessor_name FROM vendor_assessments va
     LEFT JOIN users u ON va.assessed_by = u.id WHERE va.tenant_id = ? ORDER BY va.created_at DESC`
  ).bind(req.user.tenant_id).all();
  const columns = [
    { key: 'vendor_name', label: 'Vendor' }, { key: 'product_name', label: 'Product' },
    { key: 'transparency_score', label: 'Transparency' }, { key: 'bias_testing_score', label: 'Bias Testing' },
    { key: 'security_score', label: 'Security' }, { key: 'data_practices_score', label: 'Data Practices' },
    { key: 'contractual_score', label: 'Contractual' }, { key: 'overall_risk_score', label: 'Overall Score' },
    { key: 'recommendation', label: 'Recommendation' }, { key: 'assessor_name', label: 'Assessor' },
    { key: 'assessed_at', label: 'Date' },
  ];
  sendCSV(res, 'vendor-assessments.csv', generateCSV(columns, results.results));
});

app.get('/api/v1/export/incidents', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT i.*, a.name as asset_name, u.first_name || ' ' || u.last_name as reporter_name
     FROM incidents i JOIN ai_assets a ON i.ai_asset_id = a.id JOIN users u ON i.reported_by = u.id
     WHERE i.tenant_id = ? ORDER BY i.created_at DESC`
  ).bind(req.user.tenant_id).all();
  const columns = [
    { key: 'title', label: 'Title' }, { key: 'asset_name', label: 'AI System' },
    { key: 'incident_type', label: 'Type' }, { key: 'severity', label: 'Severity' },
    { key: 'patient_impact', label: 'Patient Impact' }, { key: 'status', label: 'Status' },
    { key: 'root_cause', label: 'Root Cause' }, { key: 'corrective_actions', label: 'Corrective Actions' },
    { key: 'reporter_name', label: 'Reporter' }, { key: 'created_at', label: 'Reported' },
    { key: 'resolved_at', label: 'Resolved' },
  ];
  sendCSV(res, 'incidents.csv', generateCSV(columns, results.results));
});

app.get('/api/v1/export/evidence', requireAuth, (req, res) => {
  const results = db.prepare(
    `SELECT e.*, u.first_name || ' ' || u.last_name as uploaded_by_name
     FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id
     WHERE e.tenant_id = ? ORDER BY e.created_at DESC`
  ).bind(req.user.tenant_id).all();
  const columns = [
    { key: 'title', label: 'Title' }, { key: 'evidence_type', label: 'Type' },
    { key: 'entity_type', label: 'Entity Type' }, { key: 'entity_id', label: 'Entity ID' },
    { key: 'description', label: 'Description' }, { key: 'url', label: 'URL' },
    { key: 'uploaded_by_name', label: 'Uploaded By' }, { key: 'created_at', label: 'Date' },
  ];
  sendCSV(res, 'evidence.csv', generateCSV(columns, results.results));
});

// --- Catch-all: serve frontend for SPA routes ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'frontend', 'index.html'));
});

// --- Export for testing ---
module.exports = { app, db, createToken, hashPassword, verifyPassword, JWT_SECRET };

// --- Start Server (only when run directly) ---
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
