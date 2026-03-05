export const training = {
  async training() {
    let modules = { data: [] };
    let progress = { data: { total_modules: 0, completed_modules: 0, completion_percentage: 0, average_score: 0, completions: [] } };
    try {
      [modules, progress] = await Promise.all([
        API.getTrainingModules(),
        API.getTrainingProgress(),
      ]);
    } catch (e) { /* empty */ }

    const p = progress.data;
    const categoryLabels = { platform: 'Platform', governance: 'Governance', compliance: 'Compliance', regulatory: 'Regulatory' };

    return `
      <div class="page-header">
        <div><h2>Training Center</h2><p>Complete training modules to build your AI governance expertise</p></div>
      </div>
      <div class="stats-row" style="grid-template-columns: repeat(4, 1fr)">
        <div class="stat-card info"><div class="stat-value">${p.total_modules}</div><div class="stat-label">Total Modules</div></div>
        <div class="stat-card success"><div class="stat-value">${p.completed_modules}</div><div class="stat-label">Completed</div></div>
        <div class="stat-card warning"><div class="stat-value">${p.completion_percentage}%</div><div class="stat-label">Progress</div></div>
        <div class="stat-card"><div class="stat-value">${p.average_score || '—'}</div><div class="stat-label">Avg Score</div></div>
      </div>
      <div class="onboarding-progress-bar" style="margin-bottom:24px">
        <div class="onboarding-track"><div class="onboarding-fill" style="width:${p.completion_percentage}%"></div></div>
        <span class="onboarding-pct">${p.completion_percentage}%</span>
      </div>
      <div class="training-modules">
        ${modules.data.map(m => `
          <div class="card training-card" style="margin-bottom:12px">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
              <div style="flex:1">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                  ${m.completed ? '<span style="color:var(--success);font-size:18px">&#10003;</span>' : '<span style="color:var(--text-muted);font-size:18px">&#9675;</span>'}
                  <h3 style="margin:0">${m.title}</h3>
                </div>
                <p style="color:var(--text-secondary);font-size:13px;margin:4px 0">${m.description}</p>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px">
                  <span class="badge badge-info">${categoryLabels[m.category] || m.category}</span>
                  <span style="font-size:11px;color:var(--text-muted)">${m.duration_minutes} min</span>
                  ${m.completed ? `<span style="font-size:11px;color:var(--success)">Completed ${App.formatDate(m.completion_data?.completed_at)}</span>` : ''}
                </div>
              </div>
              <button class="btn btn-sm ${m.completed ? 'btn-outline' : 'btn-primary'}" onclick="Pages.viewTrainingModule('${m.id}')">
                ${m.completed ? 'Review' : 'Start'}
              </button>
            </div>
          </div>
        `).join('')}
      </div>`;
  },

  async viewTrainingModule(moduleId) {
    try {
      const { data: m } = await API.getTrainingModule(moduleId);
      const contentHtml = m.content.split('\\n').map(line => {
        const formatted = line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        if (line.startsWith('- ')) return `<li>${formatted.slice(2)}</li>`;
        return formatted ? `<p>${formatted}</p>` : '';
      }).join('');

      App.openModal(m.title, `
        <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
          <span class="badge badge-info">${m.category}</span>
          <span style="font-size:12px;color:var(--text-muted)">${m.duration_minutes} minutes</span>
          ${m.completed ? '<span class="badge badge-low">Completed</span>' : ''}
        </div>
        <div class="kb-body" style="max-height:400px;overflow-y:auto;padding-right:8px">
          ${contentHtml}
        </div>
      `, m.completed ? '' :
        '<button class="btn btn-primary" id="tm-complete">Mark as Completed</button>');

      if (!m.completed) {
        document.getElementById('tm-complete')?.addEventListener('click', async () => {
          try {
            await API.completeTrainingModule(moduleId, { score: 100 });
            App.closeModal();
            App.toast('Module completed!', 'success');
            App.navigate('training');
          } catch (err) { App.toast(err.message, 'error'); }
        });
      }
    } catch (err) { App.toast(err.message, 'error'); }
  },
};
