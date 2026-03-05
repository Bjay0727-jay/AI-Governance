/**
 * ForgeAI Govern™ - API Client
 *
 * Handles all communication with the backend API.
 * Tokens are stored in httpOnly cookies (set by the server).
 * Only non-sensitive user/tenant metadata is kept in sessionStorage.
 */

const API = {
  baseUrl: '/api/v1',
  csrfToken: null,
  user: null,
  tenant: null,
  authenticated: false,

  // --- Session Metadata (non-sensitive, UI-only) ---

  setUser(user, tenant) {
    this.user = user;
    this.tenant = tenant;
    this.authenticated = true;
    sessionStorage.setItem('forgeai_user', JSON.stringify(user));
    sessionStorage.setItem('forgeai_tenant', JSON.stringify(tenant));
  },

  loadSession() {
    this.user = JSON.parse(sessionStorage.getItem('forgeai_user') || 'null');
    this.tenant = JSON.parse(sessionStorage.getItem('forgeai_tenant') || 'null');
    this.authenticated = !!this.user;
    if (this.authenticated) this.fetchCsrfToken();
    return this.authenticated;
  },

  clearAuth() {
    this.user = null;
    this.tenant = null;
    this.authenticated = false;
    this.csrfToken = null;
    sessionStorage.removeItem('forgeai_user');
    sessionStorage.removeItem('forgeai_tenant');
  },

  async fetchCsrfToken() {
    try {
      const response = await fetch(`${this.baseUrl}/csrf-token`, { credentials: 'same-origin' });
      if (response.ok) {
        const data = await response.json();
        this.csrfToken = data.csrf_token;
      }
    } catch { /* CSRF token fetch failure is non-fatal */ }
  },

  // --- HTTP Client ---

  async request(method, path, body = null, retry = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }

    const options = { method, headers, credentials: 'same-origin' };
    if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${this.baseUrl}${path}`, options);

    // Handle token expiry — cookie-based refresh
    if (response.status === 401 && retry && this.authenticated) {
      const refreshed = await this.doRefresh();
      if (refreshed) return this.request(method, path, body, false);
      this.clearAuth();
      window.location.reload();
      return null;
    }

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
  },

  async doRefresh() {
    try {
      const response = await fetch(`${this.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
        credentials: 'same-origin',
      });
      if (!response.ok) return false;
      return true;
    } catch {
      return false;
    }
  },

  // --- Auth Endpoints ---

  async login(email, password, mfaCode) {
    const body = { email, password };
    if (mfaCode) body.mfa_code = mfaCode;

    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Login failed');

    // MFA challenge — password correct but TOTP needed
    if (data.mfa_required) return data;

    this.setUser(data.user, data.tenant);
    await this.fetchCsrfToken();
    return data;
  },

  async register(orgName, firstName, lastName, email, password) {
    const response = await fetch(`${this.baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        organization_name: orgName, first_name: firstName,
        last_name: lastName, email, password,
      }),
      credentials: 'same-origin',
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Registration failed');
    this.setUser(data.user, data.tenant);
    await this.fetchCsrfToken();
    return data;
  },

  async logout() {
    try {
      await fetch(`${this.baseUrl}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
        credentials: 'same-origin',
      });
    } catch { /* Best-effort logout */ }
    this.clearAuth();
  },

  // --- MFA ---
  enrollMfa() { return this.request('POST', '/auth/mfa/enroll'); },
  verifyMfa(code) { return this.request('POST', '/auth/mfa/verify', { code }); },
  disableMfa(code) { return this.request('POST', '/auth/mfa/disable', { code }); },

  // --- AI Assets ---
  getAssets(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/ai-assets${qs ? '?' + qs : ''}`);
  },
  getAsset(id) { return this.request('GET', `/ai-assets/${id}`); },
  createAsset(body) { return this.request('POST', '/ai-assets', body); },
  updateAsset(id, body) { return this.request('PUT', `/ai-assets/${id}`, body); },
  deleteAsset(id) { return this.request('DELETE', `/ai-assets/${id}`); },

  // --- Risk Assessments ---
  getRiskAssessments(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/risk-assessments${qs ? '?' + qs : ''}`);
  },
  getRiskAssessment(id) { return this.request('GET', `/risk-assessments/${id}`); },
  createRiskAssessment(body) { return this.request('POST', '/risk-assessments', body); },
  updateRiskAssessment(id, body) { return this.request('PUT', `/risk-assessments/${id}`, body); },
  approveRiskAssessment(id, body) { return this.request('POST', `/risk-assessments/${id}/approve`, body); },

  // --- Impact Assessments ---
  getImpactAssessments(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/impact-assessments${qs ? '?' + qs : ''}`);
  },
  getImpactAssessment(id) { return this.request('GET', `/impact-assessments/${id}`); },
  createImpactAssessment(body) { return this.request('POST', '/impact-assessments', body); },
  updateImpactAssessment(id, body) { return this.request('PUT', `/impact-assessments/${id}`, body); },

  // --- Compliance ---
  getControls(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/controls${qs ? '?' + qs : ''}`);
  },
  getFrameworkMappings(id) { return this.request('GET', `/controls/${id}/frameworks`); },
  getImplementations(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/implementations${qs ? '?' + qs : ''}`);
  },
  createImplementation(body) { return this.request('POST', '/implementations', body); },

  // --- Vendors ---
  getVendorAssessments() { return this.request('GET', '/vendor-assessments'); },
  getVendorAssessment(id) { return this.request('GET', `/vendor-assessments/${id}`); },
  createVendorAssessment(body) { return this.request('POST', '/vendor-assessments', body); },
  updateVendorAssessment(id, body) { return this.request('PUT', `/vendor-assessments/${id}`, body); },
  calculateVendorScore(id) { return this.request('POST', `/vendor-assessments/${id}/score`); },

  // --- Monitoring ---
  getAssetMetrics(assetId, params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/ai-assets/${assetId}/metrics${qs ? '?' + qs : ''}`);
  },
  recordMetric(body) { return this.request('POST', '/monitoring/metrics', body); },
  getAlerts(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/monitoring/alerts${qs ? '?' + qs : ''}`);
  },

  // --- Dashboard ---
  getDashboardStats() { return this.request('GET', '/dashboard/stats'); },
  getComplianceReport(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/reports/compliance${qs ? '?' + qs : ''}`);
  },
  getExecutiveReport() { return this.request('GET', '/reports/executive'); },

  // --- Maturity ---
  getMaturityAssessments() { return this.request('GET', '/maturity-assessments'); },
  getMaturityAssessment(id) { return this.request('GET', `/maturity-assessments/${id}`); },
  createMaturityAssessment(body) { return this.request('POST', '/maturity-assessments', body); },
  updateMaturityAssessment(id, body) { return this.request('PUT', `/maturity-assessments/${id}`, body); },

  // --- Incidents ---
  getIncidents(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/incidents${qs ? '?' + qs : ''}`);
  },
  createIncident(body) { return this.request('POST', '/incidents', body); },
  updateIncident(id, body) { return this.request('PUT', `/incidents/${id}`, body); },

  // --- User Management ---
  getUsers() { return this.request('GET', '/users'); },
  getUser(id) { return this.request('GET', `/users/${id}`); },
  createUser(body) { return this.request('POST', '/users', body); },
  updateUser(id, body) { return this.request('PUT', `/users/${id}`, body); },
  deactivateUser(id) { return this.request('DELETE', `/users/${id}`); },
  unlockUser(id) { return this.request('POST', `/users/${id}/unlock`); },
  resetUserPassword(id, body) { return this.request('POST', `/users/${id}/reset-password`, body); },

  // --- Audit Log ---
  getAuditLog(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/audit-log${qs ? '?' + qs : ''}`);
  },

  // --- Evidence ---
  getEvidence(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/evidence${qs ? '?' + qs : ''}`);
  },
  createEvidence(body) { return this.request('POST', '/evidence', body); },
  deleteEvidence(id) { return this.request('DELETE', `/evidence/${id}`); },

  // --- Onboarding ---
  getOnboardingProgress() { return this.request('GET', '/onboarding/progress'); },

  // --- Support Tickets ---
  getSupportTickets(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/support-tickets${qs ? '?' + qs : ''}`);
  },
  getSupportTicket(id) { return this.request('GET', `/support-tickets/${id}`); },
  createSupportTicket(body) { return this.request('POST', '/support-tickets', body); },
  updateSupportTicket(id, body) { return this.request('PUT', `/support-tickets/${id}`, body); },

  // --- Feature Requests ---
  getFeatureRequests(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/feature-requests${qs ? '?' + qs : ''}`);
  },
  createFeatureRequest(body) { return this.request('POST', '/feature-requests', body); },
  voteFeatureRequest(id) { return this.request('POST', `/feature-requests/${id}/vote`); },
  updateFeatureRequest(id, body) { return this.request('PUT', `/feature-requests/${id}`, body); },

  // --- Knowledge Base ---
  getKnowledgeBase(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/knowledge-base${qs ? '?' + qs : ''}`);
  },

  // --- Notifications ---
  getNotifications(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/notifications${qs ? '?' + qs : ''}`);
  },
  markNotificationRead(id) { return this.request('PUT', `/notifications/${id}/read`); },
  markAllNotificationsRead() { return this.request('POST', '/notifications/read-all'); },

  // --- Training ---
  getTrainingModules(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request('GET', `/training/modules${qs ? '?' + qs : ''}`);
  },
  getTrainingModule(id) { return this.request('GET', `/training/modules/${id}`); },
  completeTrainingModule(id, body = {}) { return this.request('POST', `/training/modules/${id}/complete`, body); },
  getTrainingProgress() { return this.request('GET', '/training/progress'); },

  // --- Operations ---
  getOpsMetrics() { return this.request('GET', '/ops/metrics'); },
  getTenantHealth() { return this.request('GET', '/ops/tenant-health'); },

  // --- Audit Reports ---
  getAuditPack(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return `${this.baseUrl}/reports/audit-pack${qs ? '?' + qs : ''}`;
  },
  getAssetProfile(id) {
    return `${this.baseUrl}/reports/asset-profile/${id}`;
  },
};
