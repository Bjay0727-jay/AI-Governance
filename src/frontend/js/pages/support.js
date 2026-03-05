export const support = {
  async support() {
    let data = { data: [] };
    try { data = await API.getSupportTickets(); } catch (e) { /* empty */ }

    const isAdmin = API.user?.role === 'admin';
    const openCount = data.data.filter(t => ['open', 'in_progress', 'waiting'].includes(t.status)).length;
    const resolvedCount = data.data.filter(t => ['resolved', 'closed'].includes(t.status)).length;

    return `
      <div class="page-header">
        <div><h2>Support Center</h2><p>${isAdmin ? 'Manage all support tickets' : 'Submit and track your support requests'}</p></div>
        <button class="btn btn-primary" id="btn-add-ticket">+ New Ticket</button>
      </div>
      <div class="stats-row" style="grid-template-columns: repeat(3, 1fr)">
        <div class="stat-card info"><div class="stat-value">${data.data.length}</div><div class="stat-label">Total Tickets</div></div>
        <div class="stat-card warning"><div class="stat-value">${openCount}</div><div class="stat-label">Open</div></div>
        <div class="stat-card success"><div class="stat-value">${resolvedCount}</div><div class="stat-label">Resolved</div></div>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead><tr><th>Subject</th>${isAdmin ? '<th>Submitted By</th>' : ''}<th>Category</th><th>Priority</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
              ${data.data.length > 0 ? data.data.map(t => `
                <tr>
                  <td><strong>${t.subject}</strong></td>
                  ${isAdmin ? `<td>${t.created_by_name || 'Unknown'}<br><span style="font-size:11px;color:var(--text-muted)">${t.created_by_email || ''}</span></td>` : ''}
                  <td>${App.badge(t.category)}</td>
                  <td>${App.badge(t.priority)}</td>
                  <td>${App.badge(t.status)}</td>
                  <td>${App.formatDate(t.created_at)}</td>
                  <td><button class="btn btn-sm btn-outline" onclick="Pages.viewTicket('${t.id}')">View</button></td>
                </tr>
              `).join('') : '<tr><td colspan="7" class="empty-state">No support tickets. Click "New Ticket" to submit a request.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  showTicketForm() {
    App.openModal('Submit Support Ticket', `
      <form id="ticket-form">
        <div class="form-group"><label>Subject *</label><input type="text" id="tk-subject" required placeholder="Brief description of your issue"></div>
        <div class="form-row">
          <div class="form-group"><label>Category</label>
            <select id="tk-category">
              <option value="general">General</option>
              <option value="technical">Technical Issue</option>
              <option value="compliance">Compliance Question</option>
              <option value="billing">Billing</option>
              <option value="feature_request">Feature Request</option>
              <option value="bug_report">Bug Report</option>
            </select>
          </div>
          <div class="form-group"><label>Priority</label>
            <select id="tk-priority">
              <option value="low">Low</option>
              <option value="medium" selected>Medium</option>
              <option value="high">High</option>
              <option value="urgent">Urgent</option>
            </select>
          </div>
        </div>
        <div class="form-group"><label>Description *</label><textarea id="tk-desc" required rows="5" placeholder="Describe your issue in detail..."></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="tk-submit">Submit Ticket</button>');
    document.getElementById('tk-submit').addEventListener('click', async () => {
      try {
        await API.createSupportTicket({
          subject: document.getElementById('tk-subject').value,
          description: document.getElementById('tk-desc').value,
          category: document.getElementById('tk-category').value,
          priority: document.getElementById('tk-priority').value,
        });
        App.closeModal();
        App.toast('Support ticket submitted', 'success');
        App.navigate('support');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async viewTicket(ticketId) {
    try {
      const { data: t } = await API.getSupportTicket(ticketId);
      const isAdmin = API.user?.role === 'admin';
      App.openModal(`Ticket: ${t.subject}`, `
        <div class="detail-grid" style="grid-template-columns: repeat(2, 1fr); margin-bottom:16px">
          <div class="detail-item"><span class="detail-label">Status</span><span>${App.badge(t.status)}</span></div>
          <div class="detail-item"><span class="detail-label">Priority</span><span>${App.badge(t.priority)}</span></div>
          <div class="detail-item"><span class="detail-label">Category</span><span>${App.badge(t.category)}</span></div>
          <div class="detail-item"><span class="detail-label">Created</span><span>${App.formatDate(t.created_at)}</span></div>
        </div>
        <div style="margin-bottom:16px">
          <strong>Description:</strong>
          <p style="margin-top:8px;white-space:pre-wrap;color:var(--text-secondary)">${t.description}</p>
        </div>
        ${t.admin_notes ? `<div style="margin-bottom:16px;padding:12px;background:var(--bg);border-radius:6px">
          <strong>Admin Response:</strong>
          <p style="margin-top:8px;white-space:pre-wrap">${t.admin_notes}</p>
        </div>` : ''}
        ${isAdmin ? `
          <div style="border-top:1px solid var(--border);padding-top:16px;margin-top:16px">
            <div class="form-row">
              <div class="form-group"><label>Update Status</label>
                <select id="tv-status">
                  <option value="open" ${t.status==='open'?'selected':''}>Open</option>
                  <option value="in_progress" ${t.status==='in_progress'?'selected':''}>In Progress</option>
                  <option value="waiting" ${t.status==='waiting'?'selected':''}>Waiting</option>
                  <option value="resolved" ${t.status==='resolved'?'selected':''}>Resolved</option>
                  <option value="closed" ${t.status==='closed'?'selected':''}>Closed</option>
                </select>
              </div>
              <div class="form-group"><label>Priority</label>
                <select id="tv-priority">
                  <option value="low" ${t.priority==='low'?'selected':''}>Low</option>
                  <option value="medium" ${t.priority==='medium'?'selected':''}>Medium</option>
                  <option value="high" ${t.priority==='high'?'selected':''}>High</option>
                  <option value="urgent" ${t.priority==='urgent'?'selected':''}>Urgent</option>
                </select>
              </div>
            </div>
            <div class="form-group"><label>Admin Notes</label><textarea id="tv-notes" rows="3">${t.admin_notes || ''}</textarea></div>
          </div>
        ` : ''}
      `, isAdmin ? '<button class="btn btn-primary" id="tv-save">Save Changes</button>' : '');
      if (isAdmin) {
        document.getElementById('tv-save').addEventListener('click', async () => {
          try {
            await API.updateSupportTicket(ticketId, {
              status: document.getElementById('tv-status').value,
              priority: document.getElementById('tv-priority').value,
              admin_notes: document.getElementById('tv-notes').value,
            });
            App.closeModal();
            App.toast('Ticket updated', 'success');
            App.navigate('support');
          } catch (err) { App.toast(err.message, 'error'); }
        });
      }
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async featureRequests() {
    let data = { data: [] };
    try { data = await API.getFeatureRequests({ sort: 'votes' }); } catch (e) { /* empty */ }

    const isAdmin = API.user?.role === 'admin';
    const categoryLabels = {
      governance: 'Governance', compliance: 'Compliance', reporting: 'Reporting',
      monitoring: 'Monitoring', integration: 'Integration', general: 'General',
    };

    return `
      <div class="page-header">
        <div><h2>Feature Requests</h2><p>Suggest and vote on platform improvements</p></div>
        <button class="btn btn-primary" id="btn-add-feature">+ Suggest Feature</button>
      </div>
      <div class="btn-group" style="margin-bottom:16px">
        <button class="btn btn-sm btn-outline fr-sort active" onclick="Pages.sortFeatureRequests('votes')">Most Voted</button>
        <button class="btn btn-sm btn-outline fr-sort" onclick="Pages.sortFeatureRequests('recent')">Most Recent</button>
      </div>
      <div id="fr-list">
        ${data.data.length > 0 ? data.data.map(fr => `
          <div class="card fr-card" style="margin-bottom:12px">
            <div style="display:flex;gap:16px;align-items:flex-start">
              <div class="vote-box ${fr.user_voted ? 'voted' : ''}" onclick="Pages.toggleVote('${fr.id}')" title="${fr.user_voted ? 'Remove vote' : 'Upvote'}">
                <span class="vote-arrow">&#9650;</span>
                <span class="vote-count" id="vc-${fr.id}">${fr.vote_count}</span>
              </div>
              <div style="flex:1">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                  <div>
                    <h3 style="margin:0 0 4px">${fr.title}</h3>
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                      <span class="badge badge-info">${categoryLabels[fr.category] || fr.category}</span>
                      ${App.badge(fr.status)}
                      <span style="font-size:11px;color:var(--text-muted)">by ${fr.created_by_name} &middot; ${App.formatDate(fr.created_at)}</span>
                    </div>
                  </div>
                  ${isAdmin ? `<button class="btn btn-sm btn-outline" onclick="Pages.manageFeatureRequest('${fr.id}')">Manage</button>` : ''}
                </div>
                <p style="margin:8px 0 0;color:var(--text-secondary);font-size:13px">${fr.description}</p>
                ${fr.admin_response ? `<div style="margin-top:8px;padding:8px 12px;background:var(--bg);border-radius:6px;font-size:13px">
                  <strong>Official Response:</strong> ${fr.admin_response}
                </div>` : ''}
              </div>
            </div>
          </div>
        `).join('') : '<div class="card"><div class="empty-state"><p>No feature requests yet. Be the first to suggest an improvement!</p></div></div>'}
      </div>`;
  },

  showFeatureForm() {
    App.openModal('Suggest a Feature', `
      <form id="feature-form">
        <div class="form-group"><label>Title *</label><input type="text" id="fr-title" required placeholder="Brief feature summary"></div>
        <div class="form-group"><label>Category</label>
          <select id="fr-category">
            <option value="general">General</option>
            <option value="governance">Governance</option>
            <option value="compliance">Compliance</option>
            <option value="reporting">Reporting</option>
            <option value="monitoring">Monitoring</option>
            <option value="integration">Integration</option>
          </select>
        </div>
        <div class="form-group"><label>Description *</label><textarea id="fr-desc" required rows="5" placeholder="Describe the feature you'd like to see, why it would be valuable, and any specific requirements..."></textarea></div>
      </form>
    `, '<button class="btn btn-primary" id="fr-submit">Submit Feature Request</button>');
    document.getElementById('fr-submit').addEventListener('click', async () => {
      try {
        await API.createFeatureRequest({
          title: document.getElementById('fr-title').value,
          description: document.getElementById('fr-desc').value,
          category: document.getElementById('fr-category').value,
        });
        App.closeModal();
        App.toast('Feature request submitted', 'success');
        App.navigate('feature-requests');
      } catch (err) { App.toast(err.message, 'error'); }
    });
  },

  async toggleVote(featureId) {
    try {
      const result = await API.voteFeatureRequest(featureId);
      const countEl = document.getElementById(`vc-${featureId}`);
      if (countEl) countEl.textContent = result.data.vote_count;
      const box = countEl?.closest('.vote-box');
      if (box) box.classList.toggle('voted', result.voted);
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async sortFeatureRequests(sort) {
    document.querySelectorAll('.fr-sort').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    try {
      const data = await API.getFeatureRequests({ sort });
      App.navigate('feature-requests');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async manageFeatureRequest(frId) {
    try {
      const data = await API.getFeatureRequests();
      const fr = data.data.find(f => f.id === frId);
      if (!fr) return;
      App.openModal(`Manage: ${fr.title}`, `
        <div class="form-group"><label>Status</label>
          <select id="mfr-status">
            <option value="submitted" ${fr.status==='submitted'?'selected':''}>Submitted</option>
            <option value="under_review" ${fr.status==='under_review'?'selected':''}>Under Review</option>
            <option value="planned" ${fr.status==='planned'?'selected':''}>Planned</option>
            <option value="in_progress" ${fr.status==='in_progress'?'selected':''}>In Progress</option>
            <option value="completed" ${fr.status==='completed'?'selected':''}>Completed</option>
            <option value="declined" ${fr.status==='declined'?'selected':''}>Declined</option>
          </select>
        </div>
        <div class="form-group"><label>Official Response</label><textarea id="mfr-response" rows="3">${fr.admin_response || ''}</textarea></div>
      `, '<button class="btn btn-primary" id="mfr-save">Save</button>');
      document.getElementById('mfr-save').addEventListener('click', async () => {
        try {
          await API.updateFeatureRequest(frId, {
            status: document.getElementById('mfr-status').value,
            admin_response: document.getElementById('mfr-response').value,
          });
          App.closeModal();
          App.toast('Feature request updated', 'success');
          App.navigate('feature-requests');
        } catch (err) { App.toast(err.message, 'error'); }
      });
    } catch (err) { App.toast(err.message, 'error'); }
  },
};
