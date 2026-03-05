export const knowledge = {
  async knowledgeBase() {
    let data = { data: [] };
    try { data = await API.getKnowledgeBase(); } catch (e) { /* empty */ }

    const categoryLabels = {
      framework: 'Framework', regulatory: 'Regulatory', guide: 'How-To Guide',
    };
    const categoryIcons = {
      framework: '&#9881;', regulatory: '&#9878;', guide: '&#9997;',
    };

    return `
      <div class="page-header">
        <div><h2>Knowledge Base</h2><p>Regulatory guidance, framework references, and how-to guides for healthcare AI governance</p></div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline kb-filter active" onclick="Pages.filterKB('')">All</button>
          <button class="btn btn-sm btn-outline kb-filter" onclick="Pages.filterKB('framework')">Frameworks</button>
          <button class="btn btn-sm btn-outline kb-filter" onclick="Pages.filterKB('regulatory')">Regulatory</button>
          <button class="btn btn-sm btn-outline kb-filter" onclick="Pages.filterKB('guide')">Guides</button>
        </div>
      </div>
      <div class="kb-search" style="margin-bottom:20px">
        <input type="text" id="kb-search-input" placeholder="Search articles..." class="form-input" style="width:100%;max-width:400px"
          oninput="Pages.searchKB(this.value)">
      </div>
      <div class="kb-articles" id="kb-articles">
        ${data.data.map(article => `
          <div class="card kb-article" data-category="${article.category}" style="margin-bottom:12px;cursor:pointer"
            onclick="Pages.expandKBArticle('${article.id}')">
            <div class="card-header">
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:18px">${categoryIcons[article.category] || ''}</span>
                <div>
                  <h3 style="margin:0">${article.title}</h3>
                  <span class="badge badge-info" style="margin-top:4px">${categoryLabels[article.category] || article.category}</span>
                  ${article.frameworks ? article.frameworks.map(f => `<span class="badge badge-moderate" style="margin-left:4px">${f}</span>`).join('') : ''}
                </div>
              </div>
            </div>
            <p style="color:var(--text-secondary);font-size:13px;margin:8px 0 0">${article.summary}</p>
            <div class="kb-content" id="kb-${article.id}" style="display:none;margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
              <div class="kb-body">${article.content.split('\n').map(line => {
                if (line.startsWith('**') && line.endsWith('**')) return `<h4>${line.replace(/\*\*/g, '')}</h4>`;
                if (line.startsWith('- ')) return `<li>${line.slice(2)}</li>`;
                return line ? `<p>${line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')}</p>` : '';
              }).join('')}</div>
            </div>
          </div>
        `).join('')}
      </div>`;
  },

  expandKBArticle(articleId) {
    const el = document.getElementById(`kb-${articleId}`);
    if (!el) return;
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
  },

  filterKB(category) {
    document.querySelectorAll('.kb-filter').forEach(b => b.classList.remove('active'));
    if (category) {
      event.target.classList.add('active');
    } else {
      document.querySelector('.kb-filter').classList.add('active');
    }
    document.querySelectorAll('.kb-article').forEach(el => {
      el.style.display = !category || el.dataset.category === category ? '' : 'none';
    });
  },

  searchKB(term) {
    const lower = term.toLowerCase();
    document.querySelectorAll('.kb-article').forEach(el => {
      const text = el.textContent.toLowerCase();
      el.style.display = !term || text.includes(lower) ? '' : 'none';
    });
  },
};
