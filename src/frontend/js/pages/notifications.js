export const notifications = {
  async showNotifications() {
    try {
      const data = await API.getNotifications({ limit: '30' });
      App.openModal('Notifications', `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <span style="font-size:13px;color:var(--text-muted)">${data.unread_count} unread</span>
          ${data.unread_count > 0 ? `<button class="btn btn-sm btn-outline" onclick="Pages.markAllRead()">Mark All Read</button>` : ''}
        </div>
        <div class="notif-list">
          ${data.data.length > 0 ? data.data.map(n => `
            <div class="notif-item ${n.read ? '' : 'unread'}" onclick="Pages.readNotification('${n.id}')">
              <div class="notif-icon notif-${n.type}">${n.type === 'success' ? '&#10003;' : n.type === 'warning' ? '&#9888;' : n.type === 'danger' ? '&#10007;' : '&#9432;'}</div>
              <div class="notif-content">
                <strong>${n.title}</strong>
                <p style="margin:2px 0 0;font-size:12px;color:var(--text-secondary)">${n.message}</p>
                <span style="font-size:11px;color:var(--text-muted)">${App.formatDate(n.created_at)}</span>
              </div>
            </div>
          `).join('') : '<p style="text-align:center;color:var(--text-muted);padding:20px">No notifications</p>'}
        </div>
      `, '');
    } catch (err) { App.toast(err.message, 'error'); }
  },

  async readNotification(id) {
    try {
      await API.markNotificationRead(id);
      const items = document.querySelectorAll('.notif-item');
      items.forEach(el => { if (el.getAttribute('onclick')?.includes(id)) el.classList.remove('unread'); });
      App.pollNotifications();
    } catch (e) { /* ignore */ }
  },

  async markAllRead() {
    try {
      await API.markAllNotificationsRead();
      App.closeModal();
      App.pollNotifications();
      App.toast('All notifications marked as read', 'success');
    } catch (err) { App.toast(err.message, 'error'); }
  },
};
