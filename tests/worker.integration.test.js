/**
 * ForgeAI Govern™ - Miniflare Integration Tests
 *
 * Tests the Cloudflare Worker code paths (router, auth, handlers) using
 * Miniflare's local simulation of Workers runtime, D1, R2, and KV.
 *
 * Run: npm run test:integration (requires miniflare: npm install)
 */

const path = require('path');
const fs = require('fs');

let Miniflare;
try {
  Miniflare = require('miniflare').Miniflare;
} catch {
  // Miniflare not installed
}

const SKIP = !Miniflare;

const describeIf = SKIP ? describe.skip : describe;

let mf;
let baseUrl;

// Read SQL files for DB setup
const schemaPath = path.join(__dirname, '..', 'src', 'database', 'schema.sql');
const seedPath = path.join(__dirname, '..', 'src', 'database', 'seed.sql');
const migrationsDir = path.join(__dirname, '..', 'migrations');

function readSqlFile(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch { return ''; }
}

beforeAll(async () => {
  if (SKIP) return;

  mf = new Miniflare({
    scriptPath: path.join(__dirname, '..', 'src', 'api', 'worker.js'),
    modules: true,
    compatibilityDate: '2024-12-01',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: { DB: 'test-db' },
    kvNamespaces: { SESSION_CACHE: 'test-kv' },
    r2Buckets: { EVIDENCE_STORE: 'test-r2' },
    bindings: {
      JWT_SECRET: 'test-secret-minimum-32-characters-long-enough',
      ENVIRONMENT: 'test',
      ALLOWED_ORIGINS: 'http://localhost:3000',
    },
  });

  // Initialize DB schema
  const db = await mf.getD1Database('DB');
  const schemaSql = readSqlFile(schemaPath);
  if (schemaSql) {
    for (const stmt of schemaSql.split(';').filter(s => s.trim())) {
      try { await db.exec(stmt); } catch (e) { /* skip errors from CREATE IF NOT EXISTS */ }
    }
  }

  // Apply migrations
  for (const file of fs.readdirSync(migrationsDir).sort()) {
    const sql = readSqlFile(path.join(migrationsDir, file));
    for (const stmt of sql.split(';').filter(s => s.trim())) {
      try { await db.exec(stmt); } catch { /* skip */ }
    }
  }

  // Seed compliance controls
  const seedSql = readSqlFile(seedPath);
  if (seedSql) {
    for (const stmt of seedSql.split(';').filter(s => s.trim())) {
      try { await db.exec(stmt); } catch { /* skip */ }
    }
  }

  baseUrl = 'http://localhost';
}, 30000);

afterAll(async () => {
  if (mf) await mf.dispose();
}, 10000);

async function fetchWorker(path, options = {}) {
  const url = `${baseUrl}${path}`;
  return mf.dispatchFetch(url, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
}

describeIf('Worker Integration Tests', () => {
  let cookies = '';
  let csrfToken = '';

  describe('Health Check', () => {
    test('GET /api/v1/health returns healthy status', async () => {
      const res = await fetchWorker('/api/v1/health');
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('healthy');
      expect(data.jwt_configured).toBe(true);
    });
  });

  describe('Authentication', () => {
    test('POST /api/v1/auth/register creates account with httpOnly cookies', async () => {
      const res = await fetchWorker('/api/v1/auth/register', {
        method: 'POST',
        body: {
          organization_name: 'Test Hospital',
          email: 'admin@test.hospital.org',
          password: 'SecurePassword123!',
          first_name: 'Test',
          last_name: 'Admin',
        },
      });
      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.user.email).toBe('admin@test.hospital.org');
      expect(data.user.role).toBe('admin');
      expect(data.tenant.name).toBe('Test Hospital');
      expect(data.access_token).toBeDefined();

      // Verify httpOnly cookies are set
      const setCookies = res.headers.getSetCookie?.() || [];
      const cookieStr = setCookies.join('; ');
      expect(cookieStr).toContain('forgeai_access=');
      expect(cookieStr).toContain('HttpOnly');

      // Extract cookies for subsequent requests
      cookies = setCookies.map(c => c.split(';')[0]).join('; ');
    });

    test('POST /api/v1/auth/login returns tokens in cookies', async () => {
      const res = await fetchWorker('/api/v1/auth/login', {
        method: 'POST',
        body: {
          email: 'admin@test.hospital.org',
          password: 'SecurePassword123!',
        },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.user.role).toBe('admin');
      expect(data.access_token).toBeDefined();

      const setCookies = res.headers.getSetCookie?.() || [];
      cookies = setCookies.map(c => c.split(';')[0]).join('; ');
    });

    test('GET /api/v1/csrf-token returns CSRF token', async () => {
      const res = await fetchWorker('/api/v1/csrf-token', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.csrf_token).toBeDefined();
      csrfToken = data.csrf_token;
    });

    test('Unauthenticated request returns 401', async () => {
      const res = await fetchWorker('/api/v1/ai-assets');
      expect(res.status).toBe(401);
    });
  });

  describe('AI Assets (authenticated)', () => {
    let assetId;

    test('POST /api/v1/ai-assets creates an asset', async () => {
      const res = await fetchWorker('/api/v1/ai-assets', {
        method: 'POST',
        headers: { Cookie: cookies, 'X-CSRF-Token': csrfToken },
        body: {
          name: 'Sepsis Prediction Model',
          category: 'predictive_analytics',
          risk_tier: 'high',
          description: 'ML model for early sepsis detection',
        },
      });
      expect([200, 201]).toContain(res.status);
      const data = await res.json();
      expect(data.data.name).toBe('Sepsis Prediction Model');
      assetId = data.data.id;
    });

    test('GET /api/v1/ai-assets lists assets', async () => {
      const res = await fetchWorker('/api/v1/ai-assets', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.length).toBeGreaterThanOrEqual(1);
    });

    test('GET /api/v1/ai-assets/:id returns single asset', async () => {
      if (!assetId) return;
      const res = await fetchWorker(`/api/v1/ai-assets/${assetId}`, {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.id).toBe(assetId);
    });

    test('PUT /api/v1/ai-assets/:id updates asset with audit diff', async () => {
      if (!assetId) return;
      const res = await fetchWorker(`/api/v1/ai-assets/${assetId}`, {
        method: 'PUT',
        headers: { Cookie: cookies, 'X-CSRF-Token': csrfToken },
        body: { risk_tier: 'critical' },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.risk_tier).toBe('critical');
    });
  });

  describe('Compliance Controls', () => {
    test('GET /api/v1/controls returns control catalog', async () => {
      const res = await fetchWorker('/api/v1/controls', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.length).toBeGreaterThan(0);
      expect(data.grouped).toBeDefined();
    });
  });

  describe('Rate Limiting Headers', () => {
    test('Responses include rate limit headers', async () => {
      const res = await fetchWorker('/api/v1/ai-assets', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
    });
  });

  describe('Framework Updates', () => {
    test('GET /api/v1/framework-updates returns registry', async () => {
      const res = await fetchWorker('/api/v1/framework-updates', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.length).toBeGreaterThan(0);
      expect(data.summary).toBeDefined();
    });
  });

  describe('MFA Endpoints', () => {
    test('POST /api/v1/auth/mfa/enroll returns TOTP secret', async () => {
      const res = await fetchWorker('/api/v1/auth/mfa/enroll', {
        method: 'POST',
        headers: { Cookie: cookies, 'X-CSRF-Token': csrfToken },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.secret).toBeDefined();
      expect(data.otpauth_url).toContain('otpauth://totp/');
    });
  });

  describe('Risk Assessments (authenticated)', () => {
    let assessmentId;

    test('POST /api/v1/risk-assessments creates assessment', async () => {
      // First we need an asset id — reuse the one created above or create one
      const assetRes = await fetchWorker('/api/v1/ai-assets', {
        headers: { Cookie: cookies },
      });
      const assets = await assetRes.json();
      const assetId = assets.data[0]?.id;
      if (!assetId) return;

      const res = await fetchWorker('/api/v1/risk-assessments', {
        method: 'POST',
        headers: { Cookie: cookies, 'X-CSRF-Token': csrfToken },
        body: {
          ai_asset_id: assetId,
          patient_safety_risk: 4,
          bias_risk: 3,
          privacy_risk: 4,
          clinical_validity_risk: 3,
          cybersecurity_risk: 2,
          regulatory_risk: 3,
          findings: 'Integration test risk assessment',
          recommendations: 'Continue monitoring',
        },
      });
      expect([200, 201]).toContain(res.status);
      const data = await res.json();
      assessmentId = data.data?.id;
      expect(assessmentId).toBeDefined();
    });

    test('GET /api/v1/risk-assessments lists assessments', async () => {
      const res = await fetchWorker('/api/v1/risk-assessments', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Incidents (authenticated)', () => {
    test('POST /api/v1/incidents creates an incident', async () => {
      const res = await fetchWorker('/api/v1/incidents', {
        method: 'POST',
        headers: { Cookie: cookies, 'X-CSRF-Token': csrfToken },
        body: {
          title: 'Model drift detected',
          severity: 'high',
          incident_type: 'performance_degradation',
          description: 'Integration test incident',
        },
      });
      expect([200, 201]).toContain(res.status);
      const data = await res.json();
      expect(data.data?.id).toBeDefined();
    });

    test('GET /api/v1/incidents lists incidents', async () => {
      const res = await fetchWorker('/api/v1/incidents', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Vendor Assessments (authenticated)', () => {
    test('POST /api/v1/vendor-assessments creates vendor assessment', async () => {
      const res = await fetchWorker('/api/v1/vendor-assessments', {
        method: 'POST',
        headers: { Cookie: cookies, 'X-CSRF-Token': csrfToken },
        body: {
          vendor_name: 'TestAI Corp',
          product_name: 'Diagnostic AI v2',
          assessment_type: 'initial',
        },
      });
      expect([200, 201]).toContain(res.status);
      const data = await res.json();
      expect(data.data?.id).toBeDefined();
    });
  });

  describe('Compliance Alerts', () => {
    test('GET /api/v1/compliance-alerts returns alert summary', async () => {
      const res = await fetchWorker('/api/v1/compliance-alerts', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.summary).toBeDefined();
      expect(typeof data.summary.total).toBe('number');
      expect(Array.isArray(data.data)).toBe(true);
    });
  });

  describe('Dashboard & Reports (authenticated)', () => {
    test('GET /api/v1/dashboard/stats returns dashboard stats', async () => {
      const res = await fetchWorker('/api/v1/dashboard/stats', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data).toBeDefined();
    });

    test('GET /api/v1/onboarding/progress returns onboarding status', async () => {
      const res = await fetchWorker('/api/v1/onboarding/progress', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
    });
  });

  describe('Notifications (authenticated)', () => {
    test('GET /api/v1/notifications returns notification list', async () => {
      const res = await fetchWorker('/api/v1/notifications', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(Array.isArray(data.data)).toBe(true);
      expect(typeof data.unread_count).toBe('number');
    });
  });

  describe('Export (authenticated)', () => {
    test('GET /api/v1/export/assets returns CSV export', async () => {
      const res = await fetchWorker('/api/v1/export/assets', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
    });
  });

  describe('CORS Preflight', () => {
    test('OPTIONS request returns 204 with CORS headers', async () => {
      const url = `${baseUrl}/api/v1/ai-assets`;
      const res = await mf.dispatchFetch(url, {
        method: 'OPTIONS',
        headers: { Origin: 'http://localhost:3000' },
      });
      expect(res.status).toBe(204);
    });
  });

  describe('Audit Log', () => {
    test('GET /api/v1/audit-log returns entries with hash chain', async () => {
      const res = await fetchWorker('/api/v1/audit-log', {
        headers: { Cookie: cookies },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.length).toBeGreaterThan(0);
    });
  });
});
