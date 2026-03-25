(function () {
  const installBtn = document.getElementById('installBtn');
  const PLACEHOLDER_AVATAR =
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 96 96'%3E%3Ccircle cx='48' cy='48' r='46' fill='%23e5e7eb'/%3E%3Ccircle cx='48' cy='37' r='15' fill='%23cbd5e1'/%3E%3Cpath d='M18 79c7-14 20-21 30-21s23 7 30 21' fill='%23cbd5e1'/%3E%3C/svg%3E";

  let deferredPrompt = null;

  function setMobileView(view) {
    document.body.classList.toggle('show-chat', view === 'chat');
  }

  function avatarUrl(src) {
    return src && String(src).trim() ? src : PLACEHOLDER_AVATAR;
  }

  if (installBtn) {
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;
      installBtn.classList.remove('hidden');
    });

    installBtn.addEventListener('click', async () => {
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      await deferredPrompt.userChoice.catch(() => {});
      deferredPrompt = null;
      installBtn.classList.add('hidden');
    });

    window.addEventListener('appinstalled', () => installBtn.classList.add('hidden'));
    if (window.matchMedia('(display-mode: standalone)').matches) installBtn.classList.add('hidden');
  }

  const authTabs = document.querySelectorAll('[data-auth-tab]');
  if (authTabs.length) {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    authTabs.forEach(btn => btn.addEventListener('click', () => {
      authTabs.forEach(x => x.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.authTab;
      if (loginForm) loginForm.classList.toggle('hidden', tab !== 'login');
      if (registerForm) registerForm.classList.toggle('hidden', tab !== 'register');
    }));

    const invite = window.__PREFILL_INVITE__;
    if (invite && registerForm) {
      const el = registerForm.querySelector('[name="invite_code"]');
      if (el && !el.value) el.value = invite;
      authTabs.forEach(x => x.classList.remove('active'));
      document.querySelector('[data-auth-tab="register"]')?.classList.add('active');
      if (loginForm) loginForm.classList.add('hidden');
      registerForm.classList.remove('hidden');
    }
  }

  const shell = document.querySelector('.app-shell');
  if (!shell) return;

  const me = window.__ME__ || {};
  const userId = Number(shell.dataset.userId);

  const conversationList = document.getElementById('conversationList');
  const messagesEl = document.getElementById('messages');
  const peerName = document.getElementById('peerName');
  const peerMeta = document.getElementById('peerMeta');
  const peerAvatar = document.getElementById('peerAvatar');
  const composer = document.getElementById('composer');
  const messageInput = document.getElementById('messageInput');
  const contactSearch = document.getElementById('contactSearch');
  const profileForm = document.getElementById('profileForm');
  const newChatModal = document.getElementById('newChatModal');
  const newChatForm = document.getElementById('newChatForm');
  const settingsModal = document.getElementById('settingsModal');
  const profilePreviewModal = document.getElementById('profilePreviewModal');
  const previewImage = document.getElementById('previewImage');
  const chatMenu = document.getElementById('chatMenu');
  const chatMenuBtn = document.getElementById('chatMenuBtn');
  const visibilityLabel = document.getElementById('visibilityLabel');
  const selfChatBtn = document.getElementById('selfChatBtn');
  const fontModeSelect = document.getElementById('fontModeSelect');
  const avatarVisibilitySelect = document.getElementById('avatarVisibilitySelect');
  const headerSettingsBtn = document.getElementById('headerSettingsBtn');
  const settingsBtn = document.getElementById('settingsBtn');
  const backToContactsBtn = document.getElementById('backToContactsBtn');

  const state = {
    conversations: [],
    activeConversationId: null,
    activeConversation: null,
    messages: [],
    profile: me,
    localStream: null,
    callMode: 'video',
    searchResults: false,
  };

  function fmt(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  async function jfetch(url, opts = {}) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('dc-theme', theme);
  }

  function setFont(mode) {
    document.documentElement.dataset.font = mode;
    localStorage.setItem('dc-font', mode);
    if (fontModeSelect) fontModeSelect.value = mode;
  }

  function openModal(el) {
    el?.classList.remove('hidden');
  }

  function closeModal(el) {
    el?.classList.add('hidden');
  }

  function renderAvatar(el, src) {
    if (!el) return;
    el.src = avatarUrl(src);
  }

  setTheme(localStorage.getItem('dc-theme') || 'navy');
  setFont(localStorage.getItem('dc-font') || me.font_mode || 'system');

  document.querySelectorAll('.theme-switch').forEach(btn => {
    btn.addEventListener('click', () => setTheme(btn.dataset.theme));
  });

  async function loadMe() {
    const meData = await jfetch('/api/me');
    state.profile = meData;

    renderAvatar(document.getElementById('avatarPreview'), meData.avatar_path);
    renderAvatar(previewImage, meData.avatar_path);
    if (visibilityLabel) visibilityLabel.textContent = meData.avatar_visibility || 'contacts';
    if (avatarVisibilitySelect) avatarVisibilitySelect.value = meData.avatar_visibility || 'contacts';
    if (fontModeSelect) fontModeSelect.value = meData.font_mode || localStorage.getItem('dc-font') || 'system';
    setFont(meData.font_mode || localStorage.getItem('dc-font') || 'system');
  }

  async function loadConversations() {
    const q = contactSearch?.value?.trim() || '';
    state.searchResults = Boolean(q);
    const data = q ? await jfetch('/api/users?q=' + encodeURIComponent(q)) : await jfetch('/api/conversations');
    state.conversations = data;
    renderConversationList();
  }

  function getAvatarFor(item) {
    if (item.id === userId) {
      return state.profile.avatar_visibility === 'hidden'
        ? PLACEHOLDER_AVATAR
        : (state.profile.avatar_path || PLACEHOLDER_AVATAR);
    }
    return item.avatar_path || item.partner_avatar || PLACEHOLDER_AVATAR;
  }

  function renderConversationList() {
    if (!conversationList) return;

    if (!state.conversations.length) {
      conversationList.innerHTML = '<div class="empty-state"><p>No chats yet. Search someone and open a thread.</p></div>';
      return;
    }

    conversationList.innerHTML = state.conversations.map(item => {
      const convId = item.conversation_id || item.id;
      const active = convId === state.activeConversationId ? 'active' : '';
      const title = item.partner_name || item.display_name || item.email || 'Chat';
      const blocked = item.blocked_by_me || item.blocked_me || item.blocked
        ? `<span class="tiny-meta">${item.blocked_by_me || item.blocked ? 'Blocked' : 'Blocked you'}</span>`
        : '';
      const action = item.conversation_id ? 'conv' : 'user';
      const preview = item.last_message_preview || (item.blocked_by_me || item.blocked_me ? 'Blocked conversation' : 'Tap to open');
      const time = item.last_message_at ? fmt(item.last_message_at) : '';

      return `
        <div class="conversation ${active}" data-open-type="${action}" data-conv-id="${convId}" data-user-id="${item.id}" data-blocked="${item.blocked_by_me || item.blocked_me ? '1' : '0'}">
          <img class="avatar avatar--md" src="${avatarUrl(getAvatarFor(item))}" alt="">
          <div class="conv-main">
            <div class="conv-top">
              <div class="conv-name">${escapeHtml(title)}</div>
              <div class="conv-time">${escapeHtml(time)}</div>
            </div>
            <div class="conv-preview">${escapeHtml(preview)}</div>
            ${blocked}
          </div>
        </div>
      `;
    }).join('');

    conversationList.querySelectorAll('.conversation').forEach(el => {
      el.addEventListener('click', async () => {
        if (el.dataset.blocked === '1') {
          alert('This chat is blocked. Unblock it from the conversation actions first.');
          return;
        }
        if (el.dataset.openType === 'user') {
          await openUserConversation(Number(el.dataset.userId));
        } else {
          await openConversation(Number(el.dataset.convId));
        }
      });
    });
  }

  async function openUserConversation(targetUserId) {
    const data = await jfetch('/api/conversations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ user_id: String(targetUserId) })
    });
    await loadConversations();
    await openConversation(data.conversation_id);
  }

  async function openConversation(convId) {
    const data = await jfetch(`/api/conversations/${convId}`);
    state.activeConversationId = data.id;
    state.activeConversation = data;
    state.messages = data.messages || [];

    if (peerName) peerName.textContent = data.partner.display_name || 'Chat';
    if (peerMeta) peerMeta.textContent = (data.partner.email || '') + (data.blocked ? ' · Blocked' : '');
    renderAvatar(peerAvatar, data.partner.avatar_path);

    renderMessages();
    renderConversationList();

    localStorage.setItem('dc-active-conv', String(convId));
    setMobileView('chat');
  }

  function renderMessages() {
    if (!messagesEl) return;

    if (!state.activeConversation) {
      messagesEl.innerHTML = `<div class="empty-state"><h2>Choose a chat</h2><p>Your conversation will appear here.</p></div>`;
      return;
    }

    if (!state.messages.length) {
      messagesEl.innerHTML = `<div class="empty-state"><h2>Fresh conversation</h2><p>Say hello and start the thread.</p></div>`;
      return;
    }

    messagesEl.innerHTML = state.messages.map(msg => {
      const out = msg.sender_id === userId ? 'out' : 'in';
      const status = msg.deleted ? 'deleted' : msg.edited_at ? 'edited' : (out === 'out' ? 'sent' : 'received');
      const content = escapeHtml(msg.content || '');
      const time = escapeHtml(msg.deleted_at_human || msg.edited_at_human || msg.created_at_human || '');

      return `
        <div class="message-row ${out}">
          <div class="message ${msg.deleted ? 'deleted' : ''}" data-message-id="${msg.id}">
            <div class="message-text">${content}</div>
            <div class="message-meta">
              <span>${status}</span>
              <span>${time}</span>
            </div>
            ${!msg.deleted && msg.sender_id === userId ? `
              <div class="message-actions">
                <button class="chip" data-edit="${msg.id}">Edit</button>
                <button class="chip chip--danger" data-delete="${msg.id}">Delete</button>
              </div>` : ''}
          </div>
        </div>
      `;
    }).join('');

    messagesEl.querySelectorAll('[data-edit]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.edit;
        const current = state.messages.find(m => String(m.id) === String(id));
        const next = prompt('Edit message', current?.content || '');
        if (next === null) return;
        await jfetch(`/api/messages/${id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ content: next })
        });
        await openConversation(state.activeConversationId);
        await loadConversations();
      });
    });

    messagesEl.querySelectorAll('[data-delete]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Delete this message?')) return;
        await jfetch(`/api/messages/${btn.dataset.delete}`, { method: 'DELETE' });
        await openConversation(state.activeConversationId);
        await loadConversations();
      });
    });

    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  composer?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.activeConversationId) return;

    const content = messageInput.value.trim();
    if (!content) return;

    messageInput.value = '';

    try {
      await jfetch(`/api/conversations/${state.activeConversationId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ content })
      });
      await openConversation(state.activeConversationId);
      await loadConversations();
    } catch (err) {
      alert(err.message || 'Could not send message.');
    }
  });

  contactSearch?.addEventListener('input', debounce(async () => {
    await loadConversations();
  }, 200));

  selfChatBtn?.addEventListener('click', () => openUserConversation(userId));

  document.getElementById('newChatBtn')?.addEventListener('click', () => openModal(newChatModal));
  document.getElementById('closeNewChatBtn')?.addEventListener('click', () => closeModal(newChatModal));
  document.getElementById('profilePicBtn')?.addEventListener('click', () => openModal(profilePreviewModal));
  document.getElementById('closePreviewBtn')?.addEventListener('click', () => closeModal(profilePreviewModal));

  function openSettings() {
    openModal(settingsModal);
  }

  headerSettingsBtn?.addEventListener('click', openSettings);
  settingsBtn?.addEventListener('click', openSettings);
  document.getElementById('closeSettingsBtn')?.addEventListener('click', () => closeModal(settingsModal));

  backToContactsBtn?.addEventListener('click', () => setMobileView('sidebar'));

  chatMenuBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    chatMenu?.classList.toggle('hidden');
  });

  document.addEventListener('click', (e) => {
    if (!chatMenu?.contains(e.target) && e.target !== chatMenuBtn) {
      chatMenu?.classList.add('hidden');
    }
  });

  profileForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(profileForm);
    const data = await jfetch('/api/profile', { method: 'POST', body: fd });

    closeModal(settingsModal);

    renderAvatar(document.getElementById('avatarPreview'), data.avatar_path);
    renderAvatar(previewImage, data.avatar_path);
    if (visibilityLabel) visibilityLabel.textContent = data.avatar_visibility || 'contacts';
    if (avatarVisibilitySelect) avatarVisibilitySelect.value = data.avatar_visibility || 'contacts';
    if (fontModeSelect) fontModeSelect.value = data.font_mode || 'system';
    setFont(data.font_mode || 'system');

    await loadMe();
    await loadConversations();
  });

  fontModeSelect?.addEventListener('change', () => setFont(fontModeSelect.value));

  document.getElementById('logoutBtn')?.addEventListener('click', () => {
    window.location.href = '/logout';
  });

  document.getElementById('deleteAccountBtn')?.addEventListener('click', async () => {
    if (!confirm('Delete your account? This will disable your profile.')) return;
    const data = await jfetch('/api/account', { method: 'DELETE' });
    window.location.href = data.redirect || '/';
  });

  document.getElementById('bgBtn')?.addEventListener('click', async () => {
    if (!state.activeConversationId) return;
    const theme = prompt('Choose background: navy / pure / light', state.activeConversation?.theme || 'navy');
    if (!theme) return;

    await jfetch(`/api/conversations/${state.activeConversationId}/theme`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ theme })
    });

    setTheme(theme);
    chatMenu?.classList.add('hidden');
    await openConversation(state.activeConversationId);
  });

  document.getElementById('voiceBtn')?.addEventListener('click', () => startCall('voice'));
  document.getElementById('videoBtn')?.addEventListener('click', () => startCall('video'));

  document.getElementById('blockBtn')?.addEventListener('click', async () => {
    if (!state.activeConversation?.partner?.id) return;
    await jfetch(`/api/users/${state.activeConversation.partner.id}/block`, { method: 'POST' });
    chatMenu?.classList.add('hidden');
    await openConversation(state.activeConversationId);
    await loadConversations();
  });

  document.getElementById('unblockBtn')?.addEventListener('click', async () => {
    if (!state.activeConversation?.partner?.id) return;
    await jfetch(`/api/users/${state.activeConversation.partner.id}/block`, { method: 'DELETE' });
    chatMenu?.classList.add('hidden');
    await openConversation(state.activeConversationId);
    await loadConversations();
  });

  document.getElementById('deleteChatBtn')?.addEventListener('click', async () => {
    if (!state.activeConversationId) return;
    if (!confirm('Delete this chat and all messages?')) return;

    await jfetch(`/api/conversations/${state.activeConversationId}`, { method: 'DELETE' });

    state.activeConversationId = null;
    state.activeConversation = null;
    state.messages = [];
    await loadConversations();
    renderMessages();

    if (peerName) peerName.textContent = 'Select a conversation';
    if (peerMeta) peerMeta.textContent = 'Messages are encrypted at rest';
    renderAvatar(peerAvatar, null);

    chatMenu?.classList.add('hidden');
    setMobileView('sidebar');
  });

  newChatForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = new FormData(newChatForm);
    const email = form.get('email');

    const data = await jfetch('/api/conversations', {
      method: 'POST',
      body: new URLSearchParams({ email })
    });

    closeModal(newChatModal);
    newChatForm.reset();
    await loadConversations();
    await openConversation(data.conversation_id);
  });

  async function startCall(mode) {
    if (!state.activeConversation) {
      alert('Open a chat first.');
      return;
    }

    const callPanel = document.getElementById('callPanel');
    const localVideo = document.getElementById('localVideo');
    const callTitle = document.getElementById('callTitle');

    if (!callPanel || !localVideo || !callTitle) {
      alert('Call panel is not available on this screen.');
      return;
    }

    const data = await jfetch('/api/call-room', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ peer_id: state.activeConversation.partner.id, mode })
    });

    state.callMode = data.mode;
    callTitle.textContent = `${mode === 'voice' ? 'Voice' : 'Video'} call · ${state.activeConversation.partner.display_name}`;
    callPanel.classList.remove('hidden');

    try {
      if (state.localStream) state.localStream.getTracks().forEach(t => t.stop());
      state.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: mode === 'video' });
      localVideo.srcObject = state.localStream;
    } catch (e) {
      localVideo.removeAttribute('srcObject');
    }
  }

  document.getElementById('closeCallBtn')?.addEventListener('click', () => {
    const callPanel = document.getElementById('callPanel');
    if (callPanel) callPanel.classList.add('hidden');

    if (state.localStream) {
      state.localStream.getTracks().forEach(t => t.stop());
      state.localStream = null;
    }

    const localVideo = document.getElementById('localVideo');
    if (localVideo) localVideo.srcObject = null;
  });

  async function bootstrap() {
    try {
      await loadMe();
      await loadConversations();

      const preferred = localStorage.getItem('dc-active-conv');
      const isMobile = window.matchMedia('(max-width: 900px)').matches;

      if (preferred) {
        const found = state.conversations.find(c => String((c.conversation_id || c.id)) === String(preferred));
        if (found) {
          await openConversation(found.conversation_id || found.id);
          if (!isMobile) setMobileView('chat');
          return;
        }
      }

      if (!isMobile && state.conversations.length && !state.searchResults) {
        await openConversation(state.conversations[0].id);
        setMobileView('chat');
      } else {
        setMobileView('sidebar');
      }
    } catch (e) {
      console.error(e);
    }
  }

  bootstrap();

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function debounce(fn, wait) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), wait);
    };
  }

  document.getElementById('newChatModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'newChatModal') closeModal(newChatModal);
  });

  document.getElementById('settingsModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'settingsModal') closeModal(settingsModal);
  });

  document.getElementById('profilePreviewModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'profilePreviewModal') closeModal(profilePreviewModal);
  });

  window.addEventListener('resize', () => {
    if (window.matchMedia('(min-width: 901px)').matches) {
      document.body.classList.remove('show-chat');
    }
  });
})();