(async function () {
  const usersEl = document.getElementById('adminUsers');
  const logsEl = document.getElementById('adminLogs');
  const refreshBtn = document.getElementById('refreshAdminBtn');
  const inviteBtn = document.getElementById('createInviteBtn');
  const inviteModal = document.getElementById('inviteModal');
  const inviteForm = document.getElementById('inviteForm');
  const inviteResult = document.getElementById('inviteResult');
  const closeInviteBtn = document.getElementById('closeInviteBtn');
  const createAdminForm = document.getElementById('createAdminForm');

  async function jfetch(url, opts = {}) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  async function loadUsers() {
    const users = await jfetch('/api/admin/users');
    usersEl.innerHTML = users.map(u => `
      <div class="admin-item">
        <div>
          <strong>${escapeHtml(u.display_name)}</strong>
          <small>${escapeHtml(u.email)} · ${u.is_admin ? 'Admin' : 'User'} · ${u.is_active ? 'Active' : 'Disabled'}</small>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <button class="chip" data-promote="${u.id}">Promote</button>
          <button class="chip chip--danger" data-toggle="${u.id}">${u.is_active ? 'Disable' : 'Enable'}</button>
          ${u.is_admin ? `<button class="chip chip--danger" data-delete-admin="${u.id}">Delete admin</button>` : ''}
        </div>
      </div>
    `).join('');

    usersEl.querySelectorAll('[data-promote]').forEach(btn => btn.addEventListener('click', async () => {
      await jfetch(`/api/admin/promote/${btn.dataset.promote}`, { method: 'POST' });
      await refreshAll();
    }));

    usersEl.querySelectorAll('[data-toggle]').forEach(btn => btn.addEventListener('click', async () => {
      await jfetch(`/api/admin/toggle/${btn.dataset.toggle}`, { method: 'POST' });
      await refreshAll();
    }));

    usersEl.querySelectorAll('[data-delete-admin]').forEach(btn => btn.addEventListener('click', async () => {
      if (!confirm('Delete this admin account?')) return;
      await jfetch(`/api/admin/delete/${btn.dataset.deleteAdmin}`, { method: 'POST' });
      await refreshAll();
    }));
  }

  async function loadLogs() {
    const logs = await jfetch('/api/admin/logs');
    logsEl.innerHTML = logs.map(l => `
      <div class="admin-item">
        <div>
          <strong>${escapeHtml(l.action)}</strong>
          <small>${escapeHtml(l.detail || '')} · ${escapeHtml(l.user_email || 'system')} · ${escapeHtml(l.created_at || '')}</small>
        </div>
        <div>${escapeHtml(l.severity || 'info')}</div>
      </div>
    `).join('');
  }

  async function refreshAll() {
    await Promise.all([loadUsers(), loadLogs()]);
  }

  inviteBtn?.addEventListener('click', () => inviteModal.classList.remove('hidden'));
  closeInviteBtn?.addEventListener('click', () => inviteModal.classList.add('hidden'));
  inviteModal?.addEventListener('click', e => {
    if (e.target.id === 'inviteModal') inviteModal.classList.add('hidden');
  });

  inviteForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(inviteForm);
    const data = await jfetch('/api/invites', {
      method: 'POST',
      body: new URLSearchParams({
        invite_email: fd.get('invite_email') || '',
        expires_days: fd.get('expires_days') || '14'
      })
    });
    inviteResult.innerHTML = `
      <div><strong>Invite created</strong></div>
      <div>Code: ${escapeHtml(data.code)}</div>
      <div>Link: ${escapeHtml(data.url)}</div>
    `;
  });

  createAdminForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(createAdminForm);
    await jfetch('/api/admin/create', {
      method: 'POST',
      body: new URLSearchParams({
        display_name: fd.get('display_name') || '',
        email: fd.get('email') || '',
        password: fd.get('password') || ''
      })
    });
    createAdminForm.reset();
    await refreshAll();
  });

  refreshBtn?.addEventListener('click', refreshAll);

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  await refreshAll();
})();