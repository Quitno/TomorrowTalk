(async function () {
  const usersEl = document.getElementById("adminUsers");
  const logsEl = document.getElementById("adminLogs");
  const refreshBtn = document.getElementById("refreshAdminBtn");
  const inviteBtn = document.getElementById("createInviteBtn");
  const createAdminBtn = document.getElementById("createAdminBtn");
  const inviteModal = document.getElementById("inviteModal");
  const createAdminModal = document.getElementById("createAdminModal");
  const inviteForm = document.getElementById("inviteForm");
  const createAdminForm = document.getElementById("createAdminForm");
  const inviteResult = document.getElementById("inviteResult");
  const createAdminResult = document.getElementById("createAdminResult");
  const closeInviteBtn = document.getElementById("closeInviteBtn");
  const closeCreateAdminBtn = document.getElementById("closeCreateAdminBtn");
  const searchInput = document.getElementById("userSearch");

  const statTotalUsers = document.getElementById("statTotalUsers");
  const statAdmins = document.getElementById("statAdmins");
  const statActive = document.getElementById("statActive");
  const statDisabled = document.getElementById("statDisabled");

  let searchTimer = null;

  async function jfetch(url, opts = {}) {
    const res = await fetch(url, {
      headers: { "X-Requested-With": "fetch" },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function openModal(modal) {
    if (modal) modal.classList.remove("hidden");
  }

  function closeModal(modal) {
    if (modal) modal.classList.add("hidden");
  }

  function renderStats(users) {
    const total = users.length;
    const admins = users.filter(u => u.is_admin).length;
    const active = users.filter(u => u.is_active).length;
    const disabled = total - active;

    statTotalUsers.textContent = total;
    statAdmins.textContent = admins;
    statActive.textContent = active;
    statDisabled.textContent = disabled;
  }

  async function loadUsers(query = "") {
    const users = await jfetch(`/api/admin/users?q=${encodeURIComponent(query)}`);
    renderStats(users);

    usersEl.innerHTML = users.length ? users.map(u => {
      const role = u.is_admin ? "Admin" : "User";
      const status = u.is_active ? "Active" : "Disabled";

      return `
        <div class="admin-item">
          <div class="admin-item-main">
            <strong>${escapeHtml(u.display_name)}</strong>
            <small>
              ${escapeHtml(u.email)} · ${role} · ${status}
              ${u.last_seen ? ` · last seen ${escapeHtml(u.last_seen)}` : ""}
            </small>
          </div>

          <div class="admin-item-actions">
            <button class="chip" data-admin-toggle="${u.id}">
              ${u.is_admin ? "Demote" : "Promote"}
            </button>
            <button class="chip" data-active-toggle="${u.id}">
              ${u.is_active ? "Disable" : "Enable"}
            </button>
            <button class="chip chip--danger" data-delete-user="${u.id}">
              Delete
            </button>
          </div>
        </div>
      `;
    }).join("") : `<div class="muted">No users found.</div>`;

    usersEl.querySelectorAll("[data-admin-toggle]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.adminToggle;
        const makeAdmin = btn.textContent.trim() === "Promote";
        const ok = confirm(makeAdmin ? "Promote this user to admin?" : "Remove admin rights from this user?");
        if (!ok) return;

        await jfetch(`/api/admin/users/${id}/admin`, {
          method: makeAdmin ? "POST" : "DELETE",
        });
        await refreshAll();
      });
    });

    usersEl.querySelectorAll("[data-active-toggle]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.activeToggle;
        await jfetch(`/api/admin/users/${id}/toggle`, { method: "POST" });
        await refreshAll();
      });
    });

    usersEl.querySelectorAll("[data-delete-user]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.deleteUser;
        const ok = confirm("Delete this account fully? This removes the user, chats, blocks, and related records.");
        if (!ok) return;

        await jfetch(`/api/admin/users/${id}`, { method: "DELETE" });
        await refreshAll();
      });
    });
  }

  async function loadLogs() {
    const logs = await jfetch("/api/admin/logs");
    logsEl.innerHTML = logs.length ? logs.map(l => `
      <div class="admin-item">
        <div class="admin-item-main">
          <strong>${escapeHtml(l.action)}</strong>
          <small>
            ${escapeHtml(l.detail || "")}
            ${l.user_email ? ` · ${escapeHtml(l.user_email)}` : " · system"}
            ${l.created_at ? ` · ${escapeHtml(l.created_at)}` : ""}
          </small>
        </div>
        <div class="admin-severity">${escapeHtml(l.severity || "info")}</div>
      </div>
    `).join("") : `<div class="muted">No logs yet.</div>`;
  }

  async function refreshAll() {
    const q = searchInput ? searchInput.value.trim() : "";
    await Promise.all([loadUsers(q), loadLogs()]);
  }

  inviteBtn?.addEventListener("click", () => openModal(inviteModal));
  createAdminBtn?.addEventListener("click", () => openModal(createAdminModal));
  closeInviteBtn?.addEventListener("click", () => closeModal(inviteModal));
  closeCreateAdminBtn?.addEventListener("click", () => closeModal(createAdminModal));

  inviteModal?.addEventListener("click", (e) => {
    if (e.target.id === "inviteModal") closeModal(inviteModal);
  });

  createAdminModal?.addEventListener("click", (e) => {
    if (e.target.id === "createAdminModal") closeModal(createAdminModal);
  });

  inviteForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    inviteResult.innerHTML = "";

    const fd = new FormData(inviteForm);
    const data = await jfetch("/api/invites", {
      method: "POST",
      body: new URLSearchParams({
        invite_email: fd.get("invite_email") || "",
        expires_days: fd.get("expires_days") || "14",
      }),
    });

    inviteResult.innerHTML = `
      <div><strong>Invite created</strong></div>
      <div>Code: <code>${escapeHtml(data.code)}</code></div>
      <div>Link: <code>${escapeHtml(data.url)}</code></div>
    `;
  });

  createAdminForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    createAdminResult.innerHTML = "";

    const fd = new FormData(createAdminForm);
    const data = await jfetch("/api/admin/create-admin", {
      method: "POST",
      body: new URLSearchParams({
        email: fd.get("email") || "",
        display_name: fd.get("display_name") || "Administrator",
        password: fd.get("password") || "",
      }),
    });

    createAdminResult.innerHTML = `
      <div><strong>${escapeHtml(data.message || "Admin created")}</strong></div>
      <div>Email: <code>${escapeHtml(data.email)}</code></div>
    `;
    createAdminForm.reset();
    await refreshAll();
  });

  refreshBtn?.addEventListener("click", refreshAll);

  searchInput?.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refreshAll, 250);
  });

  await refreshAll();
})();