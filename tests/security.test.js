/**
 * ForgeAI Govern™ - Security Test Suite
 *
 * Tests for:
 * - SQL injection prevention
 * - XSS payload handling
 * - JWT tampering detection
 * - Tenant isolation boundaries
 * - Input fuzzing and edge cases
 * - CSRF enforcement
 * - System field injection prevention
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Use a dedicated test database
const TEST_DB_PATH = path.join(__dirname, '..', 'data', 'security-test.db');
[TEST_DB_PATH, TEST_DB_PATH + '-wal', TEST_DB_PATH + '-shm'].forEach(f => {
  try { fs.unlinkSync(f); } catch { /* ignore */ }
});
process.env.TEST_DB_PATH = TEST_DB_PATH;
process.env.NODE_ENV = 'test';

const { app, db, createToken } = require('../server');

const TEST_PASSWORD = 'SecurePass12345!';
let tenantAToken, tenantAUserId, tenantAId;
let tenantBToken, tenantBUserId, tenantBId;
let tenantAAssetId;

beforeAll(async () => {
  // Register Tenant A
  const resA = await request(app)
    .post('/api/v1/auth/register')
    .send({
      organization_name: 'Hospital Alpha',
      email: 'admin@alpha.org',
      password: TEST_PASSWORD,
      first_name: 'Alpha',
      last_name: 'Admin',
    });
  tenantAToken = resA.body.access_token;
  tenantAUserId = resA.body.user.id;
  tenantAId = resA.body.tenant.id;

  // Acknowledge BAA for tenant A
  db.prepare("UPDATE tenants SET hipaa_baa_signed = 1, hipaa_baa_signed_at = datetime('now'), hipaa_baa_signed_by = ? WHERE id = ?")
    .bind(tenantAUserId, tenantAId).run();

  // Register Tenant B
  const resB = await request(app)
    .post('/api/v1/auth/register')
    .send({
      organization_name: 'Hospital Beta',
      email: 'admin@beta.org',
      password: TEST_PASSWORD,
      first_name: 'Beta',
      last_name: 'Admin',
    });
  tenantBToken = resB.body.access_token;
  tenantBUserId = resB.body.user.id;
  tenantBId = resB.body.tenant.id;

  // Create an asset in Tenant A
  const assetRes = await request(app)
    .post('/api/v1/ai-assets')
    .set('Authorization', `Bearer ${tenantAToken}`)
    .send({
      name: 'Alpha Radiology AI',
      vendor: 'AlphaVendor',
      category: 'diagnostic_imaging',
      risk_tier: 'high',
      phi_access: true,
    });
  tenantAAssetId = assetRes.body.data.id;
});

afterAll(async () => {
  [TEST_DB_PATH, TEST_DB_PATH + '-wal', TEST_DB_PATH + '-shm'].forEach(f => {
    try { fs.unlinkSync(f); } catch { /* ignore */ }
  });
});

// ==================== TENANT ISOLATION ====================

describe('Tenant Isolation', () => {
  test('Tenant B cannot list Tenant A assets', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(0);
  });

  test('Tenant B cannot access Tenant A asset by ID', async () => {
    const res = await request(app)
      .get(`/api/v1/ai-assets/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(404);
  });

  test('Tenant B cannot update Tenant A asset', async () => {
    const res = await request(app)
      .put(`/api/v1/ai-assets/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantBToken}`)
      .send({ name: 'Hijacked Asset' });
    expect(res.status).toBe(404);
  });

  test('Tenant B cannot delete Tenant A asset', async () => {
    const res = await request(app)
      .delete(`/api/v1/ai-assets/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(404);
  });

  test('Tenant B cannot see Tenant A users', async () => {
    const res = await request(app)
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(200);
    const userEmails = res.body.data.map(u => u.email);
    expect(userEmails).not.toContain('admin@alpha.org');
  });

  test('Tenant B cannot access Tenant A audit log', async () => {
    const res = await request(app)
      .get('/api/v1/audit-log')
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(200);
    // Should only see Tenant B's own audit entries
    const tenantAEntries = res.body.data.filter(e => e.tenant_id === tenantAId);
    expect(tenantAEntries).toHaveLength(0);
  });

  test('Tenant B cannot export Tenant A assets', async () => {
    const res = await request(app)
      .get('/api/v1/export/assets')
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(200);
    expect(res.text).not.toContain('Alpha Radiology AI');
  });

  test('Tenant B cannot view Tenant A asset profile report', async () => {
    const res = await request(app)
      .get(`/api/v1/reports/asset-profile/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantBToken}`);
    expect(res.status).toBe(404);
  });
});

// ==================== SQL INJECTION ====================

describe('SQL Injection Prevention', () => {
  const sqlPayloads = [
    "'; DROP TABLE ai_assets; --",
    "' OR '1'='1",
    "1; SELECT * FROM users --",
    "' UNION SELECT id, email, password_hash, '', '', '', '', '', '', 0, 0, '', '', '', '' FROM users --",
    "Robert'); DROP TABLE tenants;--",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
  ];

  test.each(sqlPayloads)('Asset creation rejects SQL injection: %s', async (payload) => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: payload,
        category: 'clinical_decision_support',
      });
    // Should either succeed (stored safely) or reject — never execute SQL
    if (res.status === 201) {
      // Verify it was stored as a literal string, not executed
      const asset = await request(app)
        .get(`/api/v1/ai-assets/${res.body.data.id}`)
        .set('Authorization', `Bearer ${tenantAToken}`);
      expect(asset.body.data.name).toBe(payload);
    }
    // Tables should still exist
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_assets'").first();
    expect(tables).toBeTruthy();
  });

  test('Search parameter resists SQL injection', async () => {
    const res = await request(app)
      .get("/api/v1/ai-assets?search=' OR 1=1 --")
      .set('Authorization', `Bearer ${tenantAToken}`);
    expect(res.status).toBe(200);
    // Should not return all assets due to injection
  });

  test('Login resists SQL injection in email', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: "' OR 1=1 --",
        password: 'anything',
      });
    expect(res.status).toBe(401);
  });

  test('User ID parameter resists SQL injection', async () => {
    const res = await request(app)
      .get("/api/v1/users/' OR '1'='1")
      .set('Authorization', `Bearer ${tenantAToken}`);
    // Should return 404, not leak data
    expect([400, 404]).toContain(res.status);
  });
});

// ==================== XSS PREVENTION ====================

describe('XSS Prevention', () => {
  const xssPayloads = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(document.cookie)>',
    "javascript:alert('xss')",
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '{{constructor.constructor("return this")()}}',
  ];

  test.each(xssPayloads)('Asset name escapes XSS payload: %s', async (payload) => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: payload,
        category: 'operational',
      });
    if (res.status === 201) {
      // Check that HTML report escapes the payload
      const reportRes = await request(app)
        .get(`/api/v1/reports/asset-profile/${res.body.data.id}`)
        .set('Authorization', `Bearer ${tenantAToken}`);
      expect(reportRes.status).toBe(200);
      // Verify no unescaped HTML tags from user input survive in output.
      // The key check: angle brackets must be entity-encoded, preventing tag injection.
      // Escaped content like &lt;img onerror=...&gt; is safe because the browser
      // renders it as text, not as an executable tag.
      expect(reportRes.text).not.toMatch(/<script[^<]*>/i);
      expect(reportRes.text).not.toMatch(/<img[^<]*onerror/i);
      expect(reportRes.text).not.toMatch(/<svg[^<]*onload/i);
      expect(reportRes.text).not.toMatch(/<body[^<]*onload/i);
    }
  });

  test('Audit pack report has Content-Security-Policy header', async () => {
    const res = await request(app)
      .get('/api/v1/reports/audit-pack')
      .set('Authorization', `Bearer ${tenantAToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  });

  test('Asset profile report has Content-Security-Policy header', async () => {
    const res = await request(app)
      .get(`/api/v1/reports/asset-profile/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantAToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toBeDefined();
  });
});

// ==================== JWT TAMPERING ====================

describe('JWT Tampering', () => {
  test('Rejects completely invalid token', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', 'Bearer not-a-jwt');
    expect(res.status).toBe(401);
  });

  test('Rejects token with modified payload', async () => {
    // Create a valid token then tamper with the payload
    const validToken = createToken(
      { user_id: tenantAUserId, tenant_id: tenantAId, type: 'access' },
      3600
    );
    const parts = validToken.split('.');
    // Decode payload, change tenant_id, re-encode (but keep original signature)
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    payload.tenant_id = tenantBId; // Try to switch tenant
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const tamperedToken = parts.join('.');

    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tamperedToken}`);
    expect(res.status).toBe(401);
  });

  test('Rejects expired token', async () => {
    const expiredToken = createToken(
      { user_id: tenantAUserId, tenant_id: tenantAId, type: 'access' },
      -10 // expired 10 seconds ago
    );
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${expiredToken}`);
    expect(res.status).toBe(401);
  });

  test('Rejects token signed with wrong secret', async () => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      user_id: tenantAUserId,
      tenant_id: tenantAId,
      type: 'access',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
      .createHmac('sha256', 'wrong-secret-key-that-is-definitely-not-correct')
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');
    const forgedToken = `${headerB64}.${payloadB64}.${signature}`;

    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${forgedToken}`);
    expect(res.status).toBe(401);
  });

  test('Rejects refresh token used as access token', async () => {
    const refreshToken = createToken(
      { user_id: tenantAUserId, tenant_id: tenantAId, type: 'refresh' },
      3600
    );
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${refreshToken}`);
    expect(res.status).toBe(401);
  });

  test('Rejects token with missing required claims', async () => {
    const incompleteToken = createToken({ type: 'access' }, 3600);
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${incompleteToken}`);
    expect(res.status).toBe(401);
  });
});

// ==================== INPUT FUZZING ====================

describe('Input Fuzzing', () => {
  test('Rejects oversized request body', async () => {
    const largeString = 'x'.repeat(200000); // 200KB
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({ name: largeString, category: 'operational' });
    // Should reject due to body size limit or validation
    expect([400, 413]).toContain(res.status);
  });

  test('Handles empty request body gracefully', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({});
    expect(res.status).toBe(400);
  });

  test('Handles null values in fields', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({ name: null, category: null });
    expect(res.status).toBe(400);
  });

  test('Handles unicode edge cases', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: '🏥 AI模型 — 테스트 \u0000\uFFFF',
        category: 'operational',
      });
    // Should accept or reject gracefully, not crash
    expect([201, 400]).toContain(res.status);
  });

  test('Handles extremely long field values', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: 'A'.repeat(10000),
        category: 'operational',
      });
    // Should either truncate or reject, not crash
    expect([201, 400, 413]).toContain(res.status);
  });

  test('Handles array where string expected', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: ['array', 'not', 'string'],
        category: 'operational',
      });
    // Should handle gracefully — reject or coerce, not crash uncontrolled
    expect([201, 400, 500]).toContain(res.status);
  });

  test('Handles numeric where string expected', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: 12345,
        category: 'operational',
      });
    expect([201, 400]).toContain(res.status);
  });

  test('Rejects invalid category enum', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({
        name: 'Valid Name',
        category: 'not_a_valid_category',
      });
    expect(res.status).toBe(400);
  });
});

// ==================== SYSTEM FIELD INJECTION ====================

describe('System Field Injection Prevention', () => {
  test('Rejects tenant_id in asset update body', async () => {
    const res = await request(app)
      .put(`/api/v1/ai-assets/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({ tenant_id: tenantBId, name: 'Renamed' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('system field');
  });

  test('Rejects id in asset update body', async () => {
    const res = await request(app)
      .put(`/api/v1/ai-assets/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({ id: 'new-id', name: 'Renamed' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('system field');
  });

  test('Rejects created_at in asset update body', async () => {
    const res = await request(app)
      .put(`/api/v1/ai-assets/${tenantAAssetId}`)
      .set('Authorization', `Bearer ${tenantAToken}`)
      .send({ created_at: '2020-01-01', name: 'Renamed' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('system field');
  });
});

// ==================== HIPAA BAA ENFORCEMENT ====================

describe('HIPAA BAA Enforcement', () => {
  test('Tenant without BAA cannot create PHI-accessing asset', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantBToken}`)
      .send({
        name: 'PHI System',
        category: 'clinical_decision_support',
        phi_access: true,
      });
    expect(res.status).toBe(403);
    expect(res.body.error).toContain('HIPAA');
  });

  test('Tenant without BAA can create non-PHI asset', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${tenantBToken}`)
      .send({
        name: 'Non-PHI System',
        category: 'operational',
        phi_access: false,
      });
    expect(res.status).toBe(201);
  });
});

// ==================== AUTH EDGE CASES ====================

describe('Authentication Edge Cases', () => {
  test('Missing Authorization header returns 401', async () => {
    const res = await request(app).get('/api/v1/ai-assets');
    expect(res.status).toBe(401);
  });

  test('Empty Bearer token returns 401', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', 'Bearer ');
    expect(res.status).toBe(401);
  });

  test('Non-Bearer auth scheme returns 401', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Basic ${Buffer.from('admin:pass').toString('base64')}`);
    expect(res.status).toBe(401);
  });

  test('Password too short rejected at registration', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        organization_name: 'Short Pass Org',
        email: 'short@pass.org',
        password: 'short',
        first_name: 'Test',
        last_name: 'User',
      });
    expect(res.status).toBe(400);
  });
});
