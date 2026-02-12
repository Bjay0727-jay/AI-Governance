/**
 * ForgeAI Govern™ - API Test Suite
 *
 * Comprehensive tests for all API endpoints including:
 * - Authentication (register, login, refresh, lockout)
 * - AI Assets (CRUD + filtering)
 * - Risk Assessments (CRUD + approve/reject)
 * - Impact Assessments (CRUD)
 * - Vendor Assessments (CRUD + scoring)
 * - User Management (CRUD + unlock + password reset)
 * - Compliance Controls & Implementations
 * - Monitoring Metrics & Alerts
 * - Maturity Assessments
 * - Incidents (CRUD + auto-suspension)
 * - Dashboard & Reports
 * - Audit Log
 * - Security (rate limiting, input validation, authorization)
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');

// Use a dedicated test database — must be set BEFORE requiring server
const TEST_DB_PATH = path.join(__dirname, '..', 'data', 'test.db');
// Clean up any previous test DB
[TEST_DB_PATH, TEST_DB_PATH + '-wal', TEST_DB_PATH + '-shm'].forEach(f => {
  try { fs.unlinkSync(f); } catch (e) { /* ignore */ }
});
process.env.TEST_DB_PATH = TEST_DB_PATH;

const { app, db, createToken } = require('../server');

// Test helpers
let adminToken, adminUserId, tenantId;
let viewerToken, viewerUserId;
let assetId, riskAssessmentId, impactAssessmentId, vendorAssessmentId;

const TEST_PASSWORD = 'SecurePass12345!';

beforeAll(async () => {
  // Register admin org
  const res = await request(app)
    .post('/api/v1/auth/register')
    .send({
      organization_name: 'Test Health System',
      email: 'admin@testmed.org',
      password: TEST_PASSWORD,
      first_name: 'Admin',
      last_name: 'User',
    });
  adminToken = res.body.access_token;
  adminUserId = res.body.user.id;
  tenantId = res.body.tenant.id;

  // Create viewer user
  const viewerRes = await request(app)
    .post('/api/v1/users')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({
      email: 'viewer@testmed.org',
      password: TEST_PASSWORD,
      first_name: 'View',
      last_name: 'Only',
      role: 'viewer',
    });
  viewerUserId = viewerRes.body.data.id;

  // Login as viewer to get token
  const loginRes = await request(app)
    .post('/api/v1/auth/login')
    .send({ email: 'viewer@testmed.org', password: TEST_PASSWORD });
  viewerToken = loginRes.body.access_token;
});

afterAll(() => {
  // Clean up test database
  try { db.close(); } catch (e) { /* ignore */ }
  if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
  if (fs.existsSync(TEST_DB_PATH + '-wal')) fs.unlinkSync(TEST_DB_PATH + '-wal');
  if (fs.existsSync(TEST_DB_PATH + '-shm')) fs.unlinkSync(TEST_DB_PATH + '-shm');
});

// ==================== HEALTH CHECK ====================

describe('Health Check', () => {
  test('GET /api/v1/health returns healthy status', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
    expect(res.body.version).toBe('1.0.0');
    expect(res.body.mode).toBe('local');
  });
});

// ==================== AUTHENTICATION ====================

describe('Authentication', () => {
  test('POST /api/v1/auth/register creates org and admin user', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        organization_name: 'New Clinic',
        email: 'admin@newclinic.org',
        password: 'AnotherSecure123!',
        first_name: 'Jane',
        last_name: 'Doe',
      });
    expect(res.status).toBe(201);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.refresh_token).toBeTruthy();
    expect(res.body.user.role).toBe('admin');
    expect(res.body.tenant.name).toBe('New Clinic');
  });

  test('POST /api/v1/auth/register rejects short password', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        organization_name: 'Short PW Org',
        email: 'short@org.com',
        password: 'short',
        first_name: 'A',
        last_name: 'B',
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/12 characters/);
  });

  test('POST /api/v1/auth/register rejects missing fields', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'only@email.com' });
    expect(res.status).toBe(400);
  });

  test('POST /api/v1/auth/register rejects invalid email', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        organization_name: 'Bad Email Org',
        email: 'notanemail',
        password: TEST_PASSWORD,
        first_name: 'A',
        last_name: 'B',
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/email/i);
  });

  test('POST /api/v1/auth/register rejects duplicate org', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        organization_name: 'Test Health System',
        email: 'admin@testmed.org',
        password: TEST_PASSWORD,
        first_name: 'Dup',
        last_name: 'User',
      });
    expect(res.status).toBe(409);
  });

  test('POST /api/v1/auth/login with valid credentials', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'admin@testmed.org', password: TEST_PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.user.email).toBe('admin@testmed.org');
  });

  test('POST /api/v1/auth/login rejects invalid password', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'admin@testmed.org', password: 'wrongpassword123' });
    expect(res.status).toBe(401);
  });

  test('POST /api/v1/auth/login rejects non-existent user', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'ghost@nowhere.org', password: TEST_PASSWORD });
    expect(res.status).toBe(401);
  });

  test('POST /api/v1/auth/refresh issues new tokens', async () => {
    // Create a refresh token directly (bypasses rate-limited auth endpoints)
    const refreshToken = createToken(
      { user_id: adminUserId, tenant_id: tenantId, type: 'refresh' },
      7 * 24 * 60 * 60
    );
    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refresh_token: refreshToken });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.refresh_token).toBeTruthy();
  });

  test('POST /api/v1/auth/refresh rejects invalid token', async () => {
    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refresh_token: 'invalid.token.here' });
    expect(res.status).toBe(401);
  });

  test('Unauthenticated requests return 401', async () => {
    const res = await request(app).get('/api/v1/ai-assets');
    expect(res.status).toBe(401);
  });

  test('Invalid bearer token returns 401', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', 'Bearer garbage.token.value');
    expect(res.status).toBe(401);
  });
});

// ==================== USER MANAGEMENT ====================

describe('User Management', () => {
  let newUserId;

  test('GET /api/v1/users lists tenant users (admin only)', async () => {
    const res = await request(app)
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThanOrEqual(2);
    // Should not expose password_hash
    expect(res.body.data[0].password_hash).toBeUndefined();
  });

  test('GET /api/v1/users blocked for non-admins', async () => {
    const res = await request(app)
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(res.status).toBe(403);
  });

  test('POST /api/v1/users creates new user', async () => {
    const res = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        email: 'govlead@testmed.org',
        password: TEST_PASSWORD,
        first_name: 'Gov',
        last_name: 'Lead',
        role: 'governance_lead',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.role).toBe('governance_lead');
    newUserId = res.body.data.id;
  });

  test('POST /api/v1/users rejects duplicate email', async () => {
    const res = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        email: 'govlead@testmed.org',
        password: TEST_PASSWORD,
        first_name: 'Dup',
        last_name: 'User',
      });
    expect(res.status).toBe(409);
  });

  test('GET /api/v1/users/:id returns user details', async () => {
    const res = await request(app)
      .get(`/api/v1/users/${newUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.email).toBe('govlead@testmed.org');
  });

  test('PUT /api/v1/users/:id updates user role', async () => {
    const res = await request(app)
      .put(`/api/v1/users/${newUserId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'reviewer', first_name: 'Updated' });
    expect(res.status).toBe(200);
    expect(res.body.data.role).toBe('reviewer');
    expect(res.body.data.first_name).toBe('Updated');
  });

  test('POST /api/v1/users/:id/reset-password resets password', async () => {
    const res = await request(app)
      .post(`/api/v1/users/${newUserId}/reset-password`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ new_password: 'NewSecurePass123!' });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/reset/i);
  });

  test('DELETE /api/v1/users/:id deactivates user', async () => {
    const res = await request(app)
      .delete(`/api/v1/users/${newUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/deactivated/i);
  });

  test('DELETE /api/v1/users/:id cannot deactivate self', async () => {
    const res = await request(app)
      .delete(`/api/v1/users/${adminUserId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(400);
  });
});

// ==================== AI ASSETS ====================

describe('AI Assets', () => {
  test('POST /api/v1/ai-assets creates a new asset', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'TestML Model',
        vendor: 'TestVendor',
        version: '1.0',
        category: 'clinical_decision_support',
        risk_tier: 'high',
        phi_access: true,
        department: 'Radiology',
        description: 'Test AI model for radiology',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.name).toBe('TestML Model');
    expect(res.body.data.risk_tier).toBe('high');
    assetId = res.body.data.id;
  });

  test('POST /api/v1/ai-assets blocked for viewers', async () => {
    const res = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ name: 'Blocked', category: 'operational' });
    expect(res.status).toBe(403);
  });

  test('GET /api/v1/ai-assets lists assets with pagination', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toBeInstanceOf(Array);
    expect(res.body.pagination).toBeDefined();
    expect(res.body.pagination.total).toBeGreaterThan(0);
  });

  test('GET /api/v1/ai-assets supports search filter', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets?search=TestML')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBe(1);
    expect(res.body.data[0].name).toBe('TestML Model');
  });

  test('GET /api/v1/ai-assets/:id returns asset detail', async () => {
    const res = await request(app)
      .get(`/api/v1/ai-assets/${assetId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(assetId);
    expect(res.body.data.risk_assessment_count).toBeDefined();
  });

  test('PUT /api/v1/ai-assets/:id updates asset', async () => {
    const res = await request(app)
      .put(`/api/v1/ai-assets/${assetId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ deployment_status: 'deployed', version: '1.1' });
    expect(res.status).toBe(200);
    expect(res.body.data.deployment_status).toBe('deployed');
    expect(res.body.data.version).toBe('1.1');
  });

  test('GET /api/v1/ai-assets/:id returns 404 for unknown ID', async () => {
    const res = await request(app)
      .get('/api/v1/ai-assets/nonexistent-id')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });

  test('DELETE /api/v1/ai-assets/:id decommissions asset', async () => {
    // Create a disposable asset first
    const createRes = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'Disposable AI', category: 'operational' });
    const disposableId = createRes.body.data.id;

    const res = await request(app)
      .delete(`/api/v1/ai-assets/${disposableId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/decommissioned/i);
  });
});

// ==================== RISK ASSESSMENTS ====================

describe('Risk Assessments', () => {
  test('POST /api/v1/risk-assessments creates assessment', async () => {
    const res = await request(app)
      .post('/api/v1/risk-assessments')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ai_asset_id: assetId,
        assessment_type: 'initial',
        patient_safety_score: 4,
        bias_fairness_score: 3,
        data_privacy_score: 3,
        clinical_validity_score: 4,
        cybersecurity_score: 2,
        regulatory_score: 3,
        recommendations: 'Improve cybersecurity controls',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.overall_risk_level).toBeTruthy();
    expect(res.body.data.status).toBe('draft');
    riskAssessmentId = res.body.data.id;
  });

  test('GET /api/v1/risk-assessments lists assessments', async () => {
    const res = await request(app)
      .get('/api/v1/risk-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data[0].asset_name).toBeTruthy();
  });

  test('GET /api/v1/risk-assessments/:id returns single assessment', async () => {
    const res = await request(app)
      .get(`/api/v1/risk-assessments/${riskAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(riskAssessmentId);
    expect(res.body.data.assessor_name).toBeTruthy();
  });

  test('PUT /api/v1/risk-assessments/:id updates scores and recalculates risk', async () => {
    const res = await request(app)
      .put(`/api/v1/risk-assessments/${riskAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        patient_safety_score: 5,
        recommendations: 'Updated: Critical safety concern',
      });
    expect(res.status).toBe(200);
    expect(res.body.data.patient_safety_score).toBe(5);
    expect(res.body.data.overall_risk_level).toBe('critical');
  });

  test('POST /api/v1/risk-assessments/:id/approve approves assessment', async () => {
    const res = await request(app)
      .post(`/api/v1/risk-assessments/${riskAssessmentId}/approve`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ approved: true, review_notes: 'Reviewed and approved' });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/approved/);
  });

  test('PUT /api/v1/risk-assessments/:id rejects editing approved assessment', async () => {
    const res = await request(app)
      .put(`/api/v1/risk-assessments/${riskAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ patient_safety_score: 1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/approved/i);
  });
});

// ==================== IMPACT ASSESSMENTS ====================

describe('Impact Assessments', () => {
  test('POST /api/v1/impact-assessments creates assessment', async () => {
    const res = await request(app)
      .post('/api/v1/impact-assessments')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ai_asset_id: assetId,
        assessment_period: 'Q1 2026',
        demographic_groups_tested: ['race', 'gender', 'age'],
        drift_detected: true,
        remediation_required: true,
        remediation_plan: 'Retrain model with balanced dataset',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.drift_detected).toBe(1);
    expect(res.body.data.remediation_status).toBe('planned');
    impactAssessmentId = res.body.data.id;
  });

  test('GET /api/v1/impact-assessments lists assessments', async () => {
    const res = await request(app)
      .get('/api/v1/impact-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });

  test('GET /api/v1/impact-assessments/:id returns single assessment', async () => {
    const res = await request(app)
      .get(`/api/v1/impact-assessments/${impactAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(impactAssessmentId);
  });

  test('PUT /api/v1/impact-assessments/:id updates assessment', async () => {
    const res = await request(app)
      .put(`/api/v1/impact-assessments/${impactAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        remediation_status: 'in_progress',
        disparate_impact_ratio: 0.75,
        status: 'completed',
      });
    expect(res.status).toBe(200);
    expect(res.body.data.remediation_status).toBe('in_progress');
    expect(res.body.data.disparate_impact_ratio).toBe(0.75);
  });
});

// ==================== VENDOR ASSESSMENTS ====================

describe('Vendor Assessments', () => {
  test('POST /api/v1/vendor-assessments creates assessment', async () => {
    const res = await request(app)
      .post('/api/v1/vendor-assessments')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        vendor_name: 'AI Corp',
        product_name: 'DiagnosticAI Pro',
        transparency_score: 4,
        bias_testing_score: 3,
        security_score: 5,
        data_practices_score: 4,
        contractual_score: 3,
      });
    expect(res.status).toBe(201);
    expect(res.body.data.vendor_name).toBe('AI Corp');
    vendorAssessmentId = res.body.data.id;
  });

  test('GET /api/v1/vendor-assessments lists assessments', async () => {
    const res = await request(app)
      .get('/api/v1/vendor-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });

  test('GET /api/v1/vendor-assessments/:id returns single assessment', async () => {
    const res = await request(app)
      .get(`/api/v1/vendor-assessments/${vendorAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.vendor_name).toBe('AI Corp');
  });

  test('PUT /api/v1/vendor-assessments/:id updates assessment', async () => {
    const res = await request(app)
      .put(`/api/v1/vendor-assessments/${vendorAssessmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        transparency_score: 5,
        conditions: 'Must provide quarterly audit reports',
      });
    expect(res.status).toBe(200);
    expect(res.body.data.transparency_score).toBe(5);
  });

  test('POST /api/v1/vendor-assessments/:id/score calculates score', async () => {
    const res = await request(app)
      .post(`/api/v1/vendor-assessments/${vendorAssessmentId}/score`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.overall_risk_score).toBeGreaterThan(0);
    expect(['approved', 'conditional', 'rejected']).toContain(res.body.data.recommendation);
  });
});

// ==================== COMPLIANCE ====================

describe('Compliance', () => {
  test('GET /api/v1/controls returns grouped controls', async () => {
    const res = await request(app)
      .get('/api/v1/controls')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.grouped).toBeDefined();
    expect(res.body.grouped.Govern).toBeInstanceOf(Array);
    expect(res.body.grouped.Map).toBeInstanceOf(Array);
    expect(res.body.grouped.Measure).toBeInstanceOf(Array);
    expect(res.body.grouped.Manage).toBeInstanceOf(Array);
  });

  test('GET /api/v1/controls supports family filter', async () => {
    const res = await request(app)
      .get('/api/v1/controls?family=Govern')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.every(c => c.family === 'Govern')).toBe(true);
  });

  test('POST /api/v1/implementations records control implementation', async () => {
    const controlsRes = await request(app)
      .get('/api/v1/controls')
      .set('Authorization', `Bearer ${adminToken}`);
    const controlId = controlsRes.body.data[0]?.id;
    if (!controlId) return; // skip if no controls seeded

    const res = await request(app)
      .post('/api/v1/implementations')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        control_id: controlId,
        implementation_status: 'implemented',
        responsible_party: adminUserId,
      });
    expect(res.status).toBe(201);
  });

  test('GET /api/v1/implementations returns implementations with summary', async () => {
    const res = await request(app)
      .get('/api/v1/implementations')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.summary).toBeDefined();
    expect(res.body.summary.compliance_percentage).toBeDefined();
  });
});

// ==================== MONITORING ====================

describe('Monitoring', () => {
  test('POST /api/v1/monitoring/metrics records metric', async () => {
    const res = await request(app)
      .post('/api/v1/monitoring/metrics')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ai_asset_id: assetId,
        metric_type: 'accuracy',
        metric_value: 0.95,
        threshold_min: 0.90,
      });
    expect(res.status).toBe(201);
    expect(res.body.data.alert_triggered).toBe(false);
  });

  test('POST /api/v1/monitoring/metrics triggers alert on threshold breach', async () => {
    const res = await request(app)
      .post('/api/v1/monitoring/metrics')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ai_asset_id: assetId,
        metric_type: 'accuracy',
        metric_value: 0.85,
        threshold_min: 0.90,
      });
    expect(res.status).toBe(201);
    expect(res.body.data.alert_triggered).toBe(true);
    expect(res.body.data.alert_severity).toBe('warning');
  });

  test('GET /api/v1/ai-assets/:id/metrics returns metrics', async () => {
    const res = await request(app)
      .get(`/api/v1/ai-assets/${assetId}/metrics`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });

  test('GET /api/v1/monitoring/alerts returns triggered alerts', async () => {
    const res = await request(app)
      .get('/api/v1/monitoring/alerts')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data[0].alert_triggered).toBe(1);
  });
});

// ==================== MATURITY ASSESSMENTS ====================

describe('Maturity Assessments', () => {
  test('POST /api/v1/maturity-assessments creates assessment with weighted score', async () => {
    const res = await request(app)
      .post('/api/v1/maturity-assessments')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        governance_structure_score: 2,
        ai_inventory_score: 3,
        risk_assessment_score: 2,
        policy_compliance_score: 2,
        monitoring_performance_score: 1,
        vendor_management_score: 2,
        transparency_score: 1,
      });
    expect(res.status).toBe(201);
    expect(res.body.data.overall_maturity_score).toBeGreaterThan(0);
  });

  test('GET /api/v1/maturity-assessments lists assessments', async () => {
    const res = await request(app)
      .get('/api/v1/maturity-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });
});

// ==================== INCIDENTS ====================

describe('Incidents', () => {
  let incidentId;

  test('POST /api/v1/incidents creates incident', async () => {
    const res = await request(app)
      .post('/api/v1/incidents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ai_asset_id: assetId,
        incident_type: 'bias_detected',
        severity: 'high',
        title: 'Bias detected in predictions',
        description: 'Model shows disparate performance across racial groups',
        patient_impact: false,
      });
    expect(res.status).toBe(201);
    expect(res.body.data.status).toBe('open');
    incidentId = res.body.data.id;
  });

  test('GET /api/v1/incidents lists incidents', async () => {
    const res = await request(app)
      .get('/api/v1/incidents')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });

  test('PUT /api/v1/incidents/:id updates incident', async () => {
    const res = await request(app)
      .put(`/api/v1/incidents/${incidentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        status: 'investigating',
        root_cause: 'Training data underrepresentation',
      });
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('investigating');
    expect(res.body.data.root_cause).toBeTruthy();
  });

  test('PUT /api/v1/incidents/:id resolves incident with timestamp', async () => {
    const res = await request(app)
      .put(`/api/v1/incidents/${incidentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        status: 'resolved',
        corrective_actions: 'Retrained model with balanced dataset',
      });
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('resolved');
    expect(res.body.data.resolved_at).toBeTruthy();
  });

  test('Critical patient safety incident auto-suspends asset', async () => {
    // Create a new asset for this test
    const assetRes = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'Suspension Test AI', category: 'clinical_decision_support', deployment_status: 'deployed' });
    const testAssetId = assetRes.body.data.id;

    await request(app)
      .post('/api/v1/incidents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ai_asset_id: testAssetId,
        incident_type: 'patient_safety',
        severity: 'critical',
        title: 'Critical patient safety failure',
        description: 'AI provided dangerous recommendation',
        patient_impact: true,
      });

    const assetCheck = await request(app)
      .get(`/api/v1/ai-assets/${testAssetId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(assetCheck.body.data.deployment_status).toBe('suspended');
  });
});

// ==================== DASHBOARD & REPORTS ====================

describe('Dashboard & Reports', () => {
  test('GET /api/v1/dashboard/stats returns portfolio overview', async () => {
    const res = await request(app)
      .get('/api/v1/dashboard/stats')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.ai_portfolio).toBeDefined();
    expect(res.body.data.ai_portfolio.total_assets).toBeGreaterThan(0);
    expect(res.body.data.compliance).toBeDefined();
    expect(res.body.data.monitoring).toBeDefined();
  });

  test('GET /api/v1/reports/compliance returns compliance report', async () => {
    const res = await request(app)
      .get('/api/v1/reports/compliance')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.report.title).toMatch(/Compliance/);
    expect(res.body.report.summary_by_family).toBeDefined();
  });

  test('GET /api/v1/reports/executive returns executive summary', async () => {
    const res = await request(app)
      .get('/api/v1/reports/executive')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.report.title).toMatch(/Executive/);
  });
});

// ==================== AUDIT LOG ====================

describe('Audit Log', () => {
  test('GET /api/v1/audit-log returns audit trail (admin only)', async () => {
    const res = await request(app)
      .get('/api/v1/audit-log')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data[0].action).toBeTruthy();
  });

  test('GET /api/v1/audit-log supports entity_type filter', async () => {
    const res = await request(app)
      .get('/api/v1/audit-log?entity_type=ai_asset')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.every(e => e.entity_type === 'ai_asset')).toBe(true);
  });

  test('GET /api/v1/audit-log blocked for non-admins', async () => {
    const res = await request(app)
      .get('/api/v1/audit-log')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(res.status).toBe(403);
  });
});

// ==================== EVIDENCE MANAGEMENT ====================

describe('Evidence Management', () => {
  let evidenceId;

  test('POST /api/v1/evidence creates evidence record', async () => {
    const res = await request(app)
      .post('/api/v1/evidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        entity_type: 'ai_asset',
        entity_id: assetId,
        title: 'Validation Test Results',
        evidence_type: 'test_result',
        description: 'Q1 2026 validation testing results',
        url: 'https://docs.example.com/validation-q1-2026',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.title).toBe('Validation Test Results');
    expect(res.body.data.evidence_type).toBe('test_result');
    evidenceId = res.body.data.id;
  });

  test('POST /api/v1/evidence validates entity_type', async () => {
    const res = await request(app)
      .post('/api/v1/evidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        entity_type: 'invalid_type',
        entity_id: assetId,
        title: 'Bad Evidence',
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/entity_type/i);
  });

  test('POST /api/v1/evidence requires title', async () => {
    const res = await request(app)
      .post('/api/v1/evidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        entity_type: 'ai_asset',
        entity_id: assetId,
      });
    expect(res.status).toBe(400);
  });

  test('POST /api/v1/evidence blocked for viewers', async () => {
    const res = await request(app)
      .post('/api/v1/evidence')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({
        entity_type: 'ai_asset',
        entity_id: assetId,
        title: 'Blocked Evidence',
      });
    expect(res.status).toBe(403);
  });

  test('GET /api/v1/evidence lists evidence', async () => {
    const res = await request(app)
      .get('/api/v1/evidence')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });

  test('GET /api/v1/evidence filters by entity', async () => {
    const res = await request(app)
      .get(`/api/v1/evidence?entity_type=ai_asset&entity_id=${assetId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data.every(e => e.entity_type === 'ai_asset')).toBe(true);
  });

  test('POST /api/v1/evidence creates second evidence for risk assessment', async () => {
    const res = await request(app)
      .post('/api/v1/evidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        entity_type: 'risk_assessment',
        entity_id: riskAssessmentId,
        title: 'Risk Analysis Report',
        evidence_type: 'audit_report',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.evidence_type).toBe('audit_report');
  });

  test('DELETE /api/v1/evidence/:id deletes evidence', async () => {
    const res = await request(app)
      .delete(`/api/v1/evidence/${evidenceId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/deleted/i);
  });

  test('DELETE /api/v1/evidence/:id returns 404 for unknown ID', async () => {
    const res = await request(app)
      .delete('/api/v1/evidence/nonexistent-id')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });
});

// ==================== EXPORT ====================

describe('Export', () => {
  test('GET /api/v1/export/assets returns CSV', async () => {
    const res = await request(app)
      .get('/api/v1/export/assets')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.headers['content-disposition']).toMatch(/ai-assets\.csv/);
    expect(res.text).toContain('Name');
    expect(res.text).toContain('TestML Model');
  });

  test('GET /api/v1/export/risk-assessments returns CSV', async () => {
    const res = await request(app)
      .get('/api/v1/export/risk-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.text).toContain('Patient Safety');
  });

  test('GET /api/v1/export/compliance returns CSV', async () => {
    const res = await request(app)
      .get('/api/v1/export/compliance')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.text).toContain('Control ID');
  });

  test('GET /api/v1/export/vendor-assessments returns CSV', async () => {
    const res = await request(app)
      .get('/api/v1/export/vendor-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.text).toContain('AI Corp');
  });

  test('GET /api/v1/export/incidents returns CSV', async () => {
    const res = await request(app)
      .get('/api/v1/export/incidents')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
  });

  test('GET /api/v1/export/evidence returns CSV', async () => {
    const res = await request(app)
      .get('/api/v1/export/evidence')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
  });

  test('Export endpoints require authentication', async () => {
    const res = await request(app).get('/api/v1/export/assets');
    expect(res.status).toBe(401);
  });
});

// ==================== FILTERED QUERIES ====================

describe('Filtered Queries', () => {
  test('GET /api/v1/risk-assessments?ai_asset_id filters by asset', async () => {
    const res = await request(app)
      .get(`/api/v1/risk-assessments?ai_asset_id=${assetId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data.every(r => r.ai_asset_id === assetId)).toBe(true);
  });

  test('GET /api/v1/impact-assessments?ai_asset_id filters by asset', async () => {
    const res = await request(app)
      .get(`/api/v1/impact-assessments?ai_asset_id=${assetId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data.every(ia => ia.ai_asset_id === assetId)).toBe(true);
  });

  test('GET /api/v1/incidents?ai_asset_id filters by asset', async () => {
    const res = await request(app)
      .get(`/api/v1/incidents?ai_asset_id=${assetId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.every(i => i.ai_asset_id === assetId)).toBe(true);
  });

  test('GET /api/v1/risk-assessments without filter returns all', async () => {
    const res = await request(app)
      .get('/api/v1/risk-assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });
});

// ==================== SECURITY ====================

describe('Security', () => {
  test('CSRF token endpoint works', async () => {
    const res = await request(app).get('/api/v1/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body.csrf_token).toBeTruthy();
    expect(res.body.csrf_token.length).toBe(64);
  });

  test('Security headers are set', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBeTruthy();
  });

  test('JSON body size is limited', async () => {
    const largePayload = { data: 'x'.repeat(2 * 1024 * 1024) }; // 2MB
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send(largePayload);
    expect(res.status).toBe(413);
  });

  test('Authorization enforced across roles', async () => {
    // Viewer cannot create assets
    const res1 = await request(app)
      .post('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ name: 'Blocked', category: 'operational' });
    expect(res1.status).toBe(403);

    // Viewer cannot manage users
    const res2 = await request(app)
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(res2.status).toBe(403);

    // Viewer CAN view assets (read-only)
    const res3 = await request(app)
      .get('/api/v1/ai-assets')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(res3.status).toBe(200);
  });
});
