export const admin = {
  async users() {
    let data = { data: [] };
    try { data = await API.getUsers(); } catch (e) { /* empty */ }

    const roleLabels = { admin: 'Admin', governance_lead: 'Governance Lead', reviewer: 'Reviewer', viewer: 'Viewer' };

    return `
      <div class="page-header">
        <div><h2>User Management</h2><p>Manage team members, roles, and access for ${API.tenant?.name || 'your organization'}</p></div>
        <button class="btn btn-primary" id="btn-add-user">+ Add User</button>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(u => `
                <tr>
                  <td><strong>${u.first_name} ${u.last_name}</strong></td>
                  <td>${u.email}</td>
                  <td>${App.badge(u.role === 'governance_lead' ? 'info' : u.role === 'admin' ? 'critical' : u.role === 'reviewer' ? 'moderate' : 'low')}
                      <span style="margin-left:4px">${roleLabels[u.role] || u.role}</span></td>
                  <td>${App.badge(u.status === 'active' ? 'approved' : u.status === 'locked' ? 'critical' : 'draft')}</td>
                  <td>${u.last_login ? App.formatDate(u.last_login) : 'Never'}</td>
                  <td>
                    <div class="btn-group">
                      <button class="btn btn-sm btn-outline" onclick="Pages.showEditUserForm('${u.id}')">Edit</button>
                      ${u.status === 'locked' ? `<button class="btn btn-sm btn-warning" onclick="Pages.unlockUser('${u.id}')">Unlock</button>` : ''}
                      ${u.id !== API.user?.id ? `<button class="btn btn-sm btn-outline" onclick="Pages.showResetPasswordForm('${u.id}')">Reset PW</button>` : ''}
                    </div>
                  </td>
                </tr>
              `).join('') : '<tr><td colspan="6" class="empty-state">No users found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  showUserForm() {
    App.openModal('Add New User', `
      <form id="user-form">
        <div class="form-row">
          <div class="form-group"><label>First Name *</label><input type="text" id="uf-first" required></div>
          <div class="form-group"><label>Last Name *</label><input type="text" id="uf-last" required></div>
        </div>
        <div class="form-group"><label>Email *</label><input type="email" id="uf-email" required></div>
        <div class="form-group"><label>Password *</label><input type="password" id="uf-password" required minlength="12" placeholder="Min 12 characters"></div>
        <div class="form-group"><label>Role *</label>
          <select id="uf-role">
            <option value="viewer">Viewer - Read-only access</option>
            <option value="reviewer">Reviewer - Can create assessments</option>
            <option value="governance_lead">Governance Lead - Can approve/reject</option>
            <option value="admin">Admin - Full access</option>
          </select>
        </div>
      </form>
    `, '<button class="btn btn-primary" id="uf-submit">Create User</button>');
    document.getElementById('uf-submit').addEventListener('click', async () => {
      try {
        await API.createUser({
          first_name: document.getElementById('uf-first').value,
          last_name: document.getElementById('uf-last').value,
          email: document.getElementById('uf-email').value,
          password: document.getElementById('uf-password').value,
          role: document.getElementById('uf-role').value,
        });
        App.closeModal();
        App.toast('User created successfully', 'success');
        App.navigate('users');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async showEditUserForm(userId) {
    try {
      const { data: u } = await API.getUser(userId);
      App.openModal(`Edit User: ${u.first_name} ${u.last_name}`, `
        <form id="edit-user-form">
          <div class="form-row">
            <div class="form-group"><label>First Name</label><input type="text" id="eu-first" value="${u.first_name}"></div>
            <div class="form-group"><label>Last Name</label><input type="text" id="eu-last" value="${u.last_name}"></div>
          </div>
          <div class="form-group"><label>Email</label><input type="email" id="eu-email" value="${u.email}" disabled></div>
          <div class="form-group"><label>Role</label>
            <select id="eu-role">
              <option value="viewer" ${u.role==='viewer'?'selected':''}>Viewer</option>
              <option value="reviewer" ${u.role==='reviewer'?'selected':''}>Reviewer</option>
              <option value="governance_lead" ${u.role==='governance_lead'?'selected':''}>Governance Lead</option>
              <option value="admin" ${u.role==='admin'?'selected':''}>Admin</option>
            </select>
          </div>
          <div class="form-group"><label>Status</label>
            <select id="eu-status">
              <option value="active" ${u.status==='active'?'selected':''}>Active</option>
              <option value="deactivated" ${u.status==='deactivated'?'selected':''}>Deactivated</option>
            </select>
          </div>
        </form>
      `, `<button class="btn btn-primary" id="eu-submit">Save Changes</button>
          ${u.id !== API.user?.id ? `<button class="btn btn-danger" id="eu-deactivate">Deactivate</button>` : ''}`);
      document.getElementById('eu-submit').addEventListener('click', async () => {
        try {
          await API.updateUser(userId, {
            first_name: document.getElementById('eu-first').value,
            last_name: document.getElementById('eu-last').value,
            role: document.getElementById('eu-role').value,
            status: document.getElementById('eu-status').value,
          });
          App.closeModal();
          App.toast('User updated', 'success');
          App.navigate('users');
        } catch (err) { App.toast(err.message, 'error'); }
      });
      document.getElementById('eu-deactivate')?.addEventListener('click', async () => {
        if (confirm('Deactivate this user? They will no longer be able to sign in.')) {
          try {
            await API.deactivateUser(userId);
            App.closeModal();
            App.toast('User deactivated', 'success');
            App.navigate('users');
          } catch (err) { App.toast(err.message, 'error'); }
        }
      });
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async unlockUser(userId) {
    try {
      await API.unlockUser(userId);
      App.toast('User account unlocked', 'success');
      App.navigate('users');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  showResetPasswordForm(userId) {
    App.openModal('Reset User Password', `
      <form id="reset-pw-form">
        <div class="form-group"><label>New Password *</label><input type="password" id="rp-password" required minlength="12" placeholder="Min 12 characters"></div>
        <div class="form-group"><label>Confirm Password *</label><input type="password" id="rp-confirm" required minlength="12"></div>
      </form>
    `, '<button class="btn btn-primary" id="rp-submit">Reset Password</button>');
    document.getElementById('rp-submit').addEventListener('click', async () => {
      const pw = document.getElementById('rp-password').value;
      const confirm = document.getElementById('rp-confirm').value;
      if (pw !== confirm) { App.toast('Passwords do not match', 'error'); return; }
      try {
        await API.resetUserPassword(userId, { new_password: pw });
        App.closeModal();
        App.toast('Password reset successfully', 'success');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async auditLog() {
    let data = { data: [] };
    try { data = await API.getAuditLog({ limit: 200 }); } catch (e) { /* empty */ }

    const actionIcons = {
      create: '+', update: '~', approve: '\u2713', reject: '\u2717',
      delete: '\u2715', decommission: '\u2715', login: '\u2192', register: '\u2605',
      deactivate: '\u2715', unlock: '\u2192', reset_password: '\u21BB',
    };

    return `
      <div class="page-header">
        <div><h2>Audit Log</h2><p>Immutable record of all governance activities</p></div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('')">All</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('ai_asset')">Assets</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('risk_assessment')">Risk</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('user')">Users</button>
          <button class="btn btn-sm btn-outline" onclick="Pages.filterAuditLog('incident')">Incidents</button>
        </div>
      </div>
      <div class="card">
        <div class="table-container">
          <table id="audit-table">
            <thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Entity Type</th><th>Entity ID</th><th>Details</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(a => `
                <tr data-entity-type="${a.entity_type}">
                  <td style="white-space:nowrap">${App.formatDate(a.created_at)}</td>
                  <td>${a.user_name || 'System'}<br><span style="font-size:11px;color:var(--text-muted)">${a.user_email || ''}</span></td>
                  <td><span style="font-weight:700;margin-right:4px">${actionIcons[a.action] || '?'}</span> ${a.action}</td>
                  <td>${(a.entity_type || '').replace(/_/g, ' ')}</td>
                  <td style="font-family:monospace;font-size:11px">${a.entity_id ? a.entity_id.slice(0, 8) + '...' : '-'}</td>
                  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.details && a.details !== '{}' ? a.details : '-'}</td>
                </tr>
              `).join('') : '<tr><td colspan="6" class="empty-state">No audit records found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  async filterAuditLog(entityType) {
    try {
      const params = entityType ? { entity_type: entityType, limit: 200 } : { limit: 200 };
      const data = await API.getAuditLog(params);
      const rows = document.querySelectorAll('#audit-table tbody tr');
      if (entityType) {
        rows.forEach(row => {
          row.style.display = row.dataset.entityType === entityType ? '' : 'none';
        });
      } else {
        rows.forEach(row => { row.style.display = ''; });
      }
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async opsDashboard() {
    let metrics = { data: { totals: {}, activity_7d: [], users_by_role: [], assets_by_risk: [], active_users_30d: 0 } };
    let health = { data: { health_score: 0, health_grade: 'F', coverage: {}, alerts: [], overdue_assessments: 0, critical_incidents: 0 } };
    try {
      [metrics, health] = await Promise.all([
        API.getOpsMetrics(),
        API.getTenantHealth(),
      ]);
    } catch (e) { /* empty */ }

    const t = metrics.data.totals;
    const h = health.data;
    const gradeColors = { A: 'var(--success)', B: 'var(--accent)', C: 'var(--warning)', D: '#f97316', F: 'var(--danger)' };

    return `
      <div class="page-header">
        <div><h2>Operations Dashboard</h2><p>Platform health, usage metrics, and governance coverage</p></div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="border-left:4px solid ${gradeColors[h.health_grade] || 'var(--border)'}">
          <div class="stat-value" style="font-size:36px;color:${gradeColors[h.health_grade]}">${h.health_grade}</div>
          <div class="stat-label">Health Grade (${h.health_score}/100)</div>
        </div>
        <div class="stat-card info"><div class="stat-value">${t.users || 0}</div><div class="stat-label">Active Users</div></div>
        <div class="stat-card success"><div class="stat-value">${t.assets || 0}</div><div class="stat-label">AI Assets</div></div>
        <div class="stat-card warning"><div class="stat-value">${t.open_incidents || 0}</div><div class="stat-label">Open Incidents</div></div>
      </div>
      ${h.alerts.length > 0 ? `
      <div class="card" style="margin-bottom:16px;border-left:4px solid var(--warning)">
        <div class="card-header"><h3>Alerts</h3></div>
        ${h.alerts.map(a => `
          <div class="alert-item">
            <div class="alert-severity ${a.type}"></div>
            <div class="alert-text">${a.message}</div>
          </div>
        `).join('')}
      </div>` : ''}
      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:16px">
        <div class="card">
          <div class="card-header"><h3>Governance Coverage</h3></div>
          <div style="padding:8px 0">
            ${Object.entries(h.coverage).map(([key, val]) => `
              <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
                <span style="font-size:13px">${key.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase())}</span>
                <span style="font-size:14px;font-weight:700;color:${val ? 'var(--success)' : 'var(--danger)'}">${val ? '&#10003;' : '&#10007;'}</span>
              </div>
            `).join('')}
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h3>Platform Totals</h3></div>
          <div style="padding:8px 0">
            ${[
              ['Risk Assessments', t.risk_assessments],
              ['Impact Assessments', t.impact_assessments],
              ['Vendor Assessments', t.vendors],
              ['Evidence Records', t.evidence],
              ['Support Tickets', t.tickets],
              ['Open Tickets', t.open_tickets],
              ['Audit Log Entries', t.audit_entries],
            ].map(([label, val]) => `
              <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
                <span style="font-size:13px">${label}</span><span style="font-weight:700">${val || 0}</span>
              </div>
            `).join('')}
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h3>Users by Role</h3></div>
          ${metrics.data.users_by_role.map(r => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
              <span style="font-size:13px">${App.badge(r.role)}</span><span style="font-weight:700">${r.count}</span>
            </div>
          `).join('')}
        </div>
        <div class="card">
          <div class="card-header"><h3>Assets by Risk Tier</h3></div>
          ${metrics.data.assets_by_risk.map(r => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
              <span>${App.badge(r.risk_tier)}</span><span style="font-weight:700">${r.count}</span>
            </div>
          `).join('')}
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><h3>Audit-Ready Reports</h3></div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px">
          <div class="export-card card" style="text-align:center;padding:16px;cursor:pointer" onclick="Pages.openAuditReport('all')">
            <div style="font-size:28px">&#9744;</div><strong>Full Compliance Pack</strong>
            <p style="font-size:12px;color:var(--text-secondary)">All frameworks</p>
          </div>
          <div class="export-card card" style="text-align:center;padding:16px;cursor:pointer" onclick="Pages.openAuditReport('nist')">
            <div style="font-size:28px">&#9878;</div><strong>NIST AI RMF Pack</strong>
            <p style="font-size:12px;color:var(--text-secondary)">NIST controls only</p>
          </div>
          <div class="export-card card" style="text-align:center;padding:16px;cursor:pointer" onclick="Pages.openAuditReport('hipaa')">
            <div style="font-size:28px">&#9829;</div><strong>HIPAA Pack</strong>
            <p style="font-size:12px;color:var(--text-secondary)">HIPAA controls only</p>
          </div>
        </div>
      </div>`;
  },

  openAuditReport(framework) {
    const url = framework === 'all'
      ? '/api/v1/reports/audit-pack'
      : `/api/v1/reports/audit-pack?framework=${framework}`;
    const win = window.open('', '_blank');
    fetch(url, { headers: { 'Authorization': `Bearer ${API.accessToken}` } })
      .then(r => r.text())
      .then(html => { win.document.write(html); win.document.close(); })
      .catch(() => { win.close(); App.toast('Failed to generate report', 'error'); });
  },

  openAssetProfile(assetId) {
    const url = `/api/v1/reports/asset-profile/${assetId}`;
    const win = window.open('', '_blank');
    fetch(url, { headers: { 'Authorization': `Bearer ${API.accessToken}` } })
      .then(r => r.text())
      .then(html => { win.document.write(html); win.document.close(); })
      .catch(() => { win.close(); App.toast('Failed to generate report', 'error'); });
  },
};
