/**
 * ForgeAI Govern™ - API Client
 *
 * Handles all communication with the backend API.
 * Manages JWT tokens, automatic refresh, and request/response formatting.
 */

const API = {
  baseUrl: '/api/v1',
  accessToken: null,
  refreshToken: null,
  user: null,
  tenant: null,

  // --- Token Management ---

  setTokens(accessToken, refreshToken) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    localStorage.setItem('forgeai_access_token', accessToken);
    localStorage.setItem('forgeai_refresh_token', refreshToken);
  },

  loadTokens() {
    this.accessToken = localStorage.getItem('forgeai_access_token');
    this.refreshToken = localStorage.getItem('forgeai_refresh_token');
    this.user = JSON.parse(localStorage.getItem('forgeai_user') || 'null');
    this.tenant = JSON.parse(localStorage.getItem('forgeai_tenant') || 'null');
    return !!this.accessToken;
  },

  setUser(user, tenant) {
    this.user = user;
    this.tenant = tenant;
    localStorage.setItem('forgeai_user', JSON.stringify(user));
    localStorage.setItem('forgeai_tenant', JSON.stringify(tenant));
  },

  clearAuth() {
    this.accessToken = null;
    this.refreshToken = null;
    this.user = null;
    this.tenant = null;
    localStorage.removeItem('forgeai_access_token');
    localStorage.removeItem('forgeai_refresh_token');
    localStorage.removeItem('forgeai_user');
    localStorage.removeItem('forgeai_tenant');
  },

  // --- HTTP Client ---

  async request(method, path, body = null, retry = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;

    const options = { method, headers };
    if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${this.baseUrl}${path}`, options);

    // Handle token expiry
    if (response.status === 401 && retry && this.refreshToken) {
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
        body: JSON.stringify({ refresh_token: this.refreshToken }),
      });
      if (!response.ok) return false;
      const data = await response.json();
      this.setTokens(data.access_token, data.refresh_token);
      return true;
    } catch {
      return false;
    }
  },

  // --- Auth Endpoints ---

  async login(email, password) {
    const data = await this.request('POST', '/auth/login', { email, password });
    this.setTokens(data.access_token, data.refresh_token);
    this.setUser(data.user, data.tenant);
    return data;
  },

  async register(orgName, firstName, lastName, email, password) {
    const data = await this.request('POST', '/auth/register', {
      organization_name: orgName, first_name: firstName,
      last_name: lastName, email, password,
    });
    this.setTokens(data.access_token, data.refresh_token);
    this.setUser(data.user, data.tenant);
    return data;
  },

  logout() { this.clearAuth(); },

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
};
