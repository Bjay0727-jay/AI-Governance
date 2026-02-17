/**
 * ForgeAI Govern™ - Main Application Controller
 *
 * Manages navigation, authentication state, and page rendering.
 */

const App = {
  currentPage: 'dashboard',

  init() {
    this.bindEvents();
    if (API.loadTokens()) {
      this.showApp();
    } else {
      this.showScreen('login-screen');
    }
  },

  bindEvents() {
    // Auth forms
    document.getElementById('login-form').addEventListener('submit', (e) => this.handleLogin(e));
    document.getElementById('register-form').addEventListener('submit', (e) => this.handleRegister(e));
    document.getElementById('show-register').addEventListener('click', () => this.showScreen('register-screen'));
    document.getElementById('show-login').addEventListener('click', () => this.showScreen('login-screen'));
    document.getElementById('logout-btn').addEventListener('click', () => this.handleLogout());

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => this.navigate(item.dataset.page));
    });

    // Modal
    document.getElementById('modal-close').addEventListener('click', () => this.closeModal());
    document.getElementById('modal-overlay').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) this.closeModal();
    });
  },

  // --- Screen Management ---

  showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(screenId).classList.add('active');
  },

  showApp() {
    this.showScreen('main-app');
    document.getElementById('user-info').textContent =
      `${API.user?.first_name} ${API.user?.last_name} | ${API.tenant?.name}`;

    // Show/hide admin-only nav items
    const isAdmin = API.user?.role === 'admin';
    document.querySelectorAll('.admin-only').forEach(el => {
      el.style.display = isAdmin ? '' : 'none';
    });

    this.navigate('dashboard');
  },

  // --- Authentication ---

  async handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');
    errorEl.classList.add('hidden');

    try {
      await API.login(email, password);
      this.showApp();
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    }
  },

  async handleRegister(e) {
    e.preventDefault();
    const errorEl = document.getElementById('register-error');
    errorEl.classList.add('hidden');

    try {
      await API.register(
        document.getElementById('reg-org').value,
        document.getElementById('reg-first').value,
        document.getElementById('reg-last').value,
        document.getElementById('reg-email').value,
        document.getElementById('reg-password').value
      );
      this.showApp();
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    }
  },

  handleLogout() {
    API.logout();
    this.showScreen('login-screen');
  },

  // --- Navigation ---

  navigate(page) {
    this.currentPage = page;
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.page === page);
    });
    this.renderPage(page);
  },

  async renderPage(page) {
    const content = document.getElementById('content-area');
    content.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

    try {
      switch (page) {
        case 'dashboard': content.innerHTML = await Pages.dashboard(); break;
        case 'ai-assets': content.innerHTML = await Pages.aiAssets(); break;
        case 'risk-assessments': content.innerHTML = await Pages.riskAssessments(); break;
        case 'impact-assessments': content.innerHTML = await Pages.impactAssessments(); break;
        case 'compliance': content.innerHTML = await Pages.compliance(); break;
        case 'vendors': content.innerHTML = await Pages.vendors(); break;
        case 'monitoring': content.innerHTML = await Pages.monitoring(); break;
        case 'maturity': content.innerHTML = await Pages.maturity(); break;
        case 'incidents': content.innerHTML = await Pages.incidents(); break;
        case 'users': content.innerHTML = await Pages.users(); break;
        case 'audit-log': content.innerHTML = await Pages.auditLog(); break;
        case 'asset-detail': content.innerHTML = await Pages.assetDetail(); break;
        case 'reports': content.innerHTML = await Pages.reports(); break;
        case 'knowledge-base': content.innerHTML = await Pages.knowledgeBase(); break;
        case 'support': content.innerHTML = await Pages.support(); break;
        case 'feature-requests': content.innerHTML = await Pages.featureRequests(); break;
        default: content.innerHTML = '<div class="empty-state"><p>Page not found</p></div>';
      }
      // Bind page-specific events after rendering
      Pages.bindPageEvents(page);
    } catch (err) {
      content.innerHTML = `<div class="empty-state"><div class="empty-icon">&#9888;</div><p>Error loading page: ${err.message}</p></div>`;
    }
  },

  // --- Modal ---

  openModal(title, bodyHtml, footerHtml = '') {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = bodyHtml;
    document.getElementById('modal-footer').innerHTML = footerHtml;
    document.getElementById('modal-overlay').classList.remove('hidden');
  },

  closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
  },

  // --- Toast ---

  toast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  },

  // --- Helpers ---

  badge(value, prefix = '') {
    const cls = prefix ? `badge-${value}` : `badge-${value}`;
    return `<span class="badge ${cls}">${(value || 'N/A').replace(/_/g, ' ')}</span>`;
  },

  formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  },
};

// Initialize on load
document.addEventListener('DOMContentLoaded', () => App.init());
