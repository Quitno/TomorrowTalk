(function () {
  const installBtn = document.getElementById('installBtn');
  let deferredPrompt = null;

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
    const mq = window.matchMedia('(display-mode: standalone)');
    if (mq.matches) installBtn.classList.add('hidden');
  }

  const authTabs = document.querySelectorAll('[data-auth-tab]');
  if (authTabs.length) {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    authTabs.forEach(btn => btn.addEventListener('click', () => {
      authTabs.forEach(x => x.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.authTab;
      loginForm.classList.toggle('hidden', tab !== 'login');
      registerForm.classList.toggle('hidden', tab !== 'register');
    }));
    const invite = window.__PREFILL_INVITE__;
    if (invite && registerForm) {
      const el = registerForm.querySelector('[name="invite_code"]');
      if (el && !el.value) el.value = invite;
      authTabs.forEach(x => x.classList.remove('active'));
      document.querySelector('[data-auth-tab="register"]')?.classList.add('active');
      loginForm.classList.add('hidden');
      registerForm.classList.remove('hidden');
    }
  }

  const shell = document.querySelector('.app-shell');
  if (!shell) return;

  const me = window.__ME__;
  const userId = Number(shell.dataset.userId);
  const conversationList = document.getElementById('conversationList');
  const messagesEl = document.getElementById('messages');
  const peerName = document.getElementById('peerName');
  const peerMeta = document.getElementById('peerMeta');
  const peerAvatar = document.getElementById('peerAvatar');
  const composer = document.getElementById('composer');
  const messageInput = document.getElementById('messageInput');
  const contactSearch = document.getElementById('contactSearch');
  const profileModal = document.getElementById('profileModal');
  const profileForm = document.getElementById('profileForm');
  const newChatModal = document.getElementById('newChatModal');
  const newChatForm = document.getElementById('newChatForm');
  const callPanel = document.getElementById('callPanel');
  const localVideo = document.getElementById('localVideo');
  const callTitle = document.getElementById('callTitle');

  const state = {
    conversations: [],
    activeConversationId: null,
    activeConversation: null,
    messages: [],
    profile: me,
    localStream: null,
    callMode: 'video',
  };

  const fmt = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  async function jfetch(url, opts = {}) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('dc-theme', theme);
    document.querySelectorAll('.theme-switch').forEach(btn => btn.classList.toggle('active', btn.dataset.theme === theme));
  }
  setTheme(localStorage.getItem('dc-theme') || 'navy');
  document.querySelectorAll('.theme-switch').forEach(btn => btn.addEventListener('click', () => setTheme(btn.dataset.theme)));

  async function loadMe() {
    const meData = await jfetch('/api/me');
    state.profile = meData;
    const avatar = document.getElementById('avatarPreview');
    if (avatar) avatar.src = meData.avatar_path || '/static/logo.png';
  }

  async function loadConversations() {
    const q = contactSearch?.value?.trim() || '';
    const data = q ? await jfetch('/api/users?q=' + encodeURIComponent(q)) : await jfetch('/api/conversations');
    state.conversations = data;
    renderConversationList();
  }

  function renderConversationList() {
    if (!conversationList) return;
    if (!state.conversations.length) {
      conversationList.innerHTML = '<div class="empty-state"><p>No chats yet. Start one from email search.</p></div>';
      return;
    }
    conversationList.innerHTML = state.conversations.map(item => {
      const active = item.id === state.activeConversationId ? 'active' : '';
      const avatar = item.partner_avatar || '/static/logo.png';
      const title = item.partner_name || item.display_name || item.email || 'Chat';
      return `
        <div class="conversation ${active}" data-conv-id="${item.id}" data-partner-id="${item.partner_id || item.id}">
          <img class="avatar" src="${avatar}" alt="">
          <div class="conv-main">
            <div class="conv-top">
              <div class="conv-name">${escapeHtml(title)}</div>
              <div class="conv-time">${escapeHtml(item.last_message_at || '')}</div>
            </div>
            <div class="conv-preview">${escapeHtml(item.last_message_preview || 'No messages yet')}</div>
          </div>
        </div>
      `;
    }).join('');

    conversationList.querySelectorAll('.conversation').forEach(el => {
      el.addEventListener('click', () => openConversation(Number(el.dataset.convId)));
    });
  }

  async function openConversation(convId) {
    const data = await jfetch(`/api/conversations/${convId}`);
    state.activeConversationId = data.id;
    state.activeConversation = data;
    state.messages = data.messages || [];
    if (peerName) peerName.textContent = data.partner.display_name;
    if (peerMeta) peerMeta.textContent = data.partner.email;
    if (peerAvatar) peerAvatar.src = data.partner.avatar_path || '/static/logo.png';
    renderMessages();
    renderConversationList();
  }

  function renderMessages() {
    if (!messagesEl) return;
    if (!state.activeConversation) {
      messagesEl.innerHTML = `<div class="empty-state"><h2>Choose a chat</h2><p>Your conversations will appear here like a polished messenger.</p></div>`;
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
      return `
        <div class="message-row ${out}">
          <div class="message ${msg.deleted ? 'deleted' : ''}" data-message-id="${msg.id}">
            <div class="message-text">${content}</div>
            <div class="message-meta">
              <span>${status}</span>
              <span>${escapeHtml(msg.deleted_at_human || msg.edited_at_human || msg.created_at_human || '')}</span>
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
    await jfetch(`/api/conversations/${state.activeConversationId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ content })
    });
    await openConversation(state.activeConversationId);
    await loadConversations();
  });

  contactSearch?.addEventListener('input', debounce(loadConversations, 200));

  document.getElementById('newChatBtn')?.addEventListener('click', () => newChatModal.classList.remove('hidden'));
  document.getElementById('closeNewChatBtn')?.addEventListener('click', () => newChatModal.classList.add('hidden'));

  newChatForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = new FormData(newChatForm);
    const email = form.get('email');
    const data = await jfetch('/api/conversations', {
      method: 'POST',
      body: new URLSearchParams({ email })
    });
    newChatModal.classList.add('hidden');
    await loadConversations();
    await openConversation(data.conversation_id);
  });

  document.getElementById('profileBtn')?.addEventListener('click', () => profileModal.classList.remove('hidden'));
  document.getElementById('closeProfileBtn')?.addEventListener('click', () => profileModal.classList.add('hidden'));

  profileForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(profileForm);
    const data = await jfetch('/api/profile', { method: 'POST', body: fd });
    profileModal.classList.add('hidden');
    document.getElementById('avatarPreview').src = data.avatar_path || '/static/logo.png';
    await loadMe();
    await loadConversations();
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
    await openConversation(state.activeConversationId);
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
    if (peerAvatar) peerAvatar.src = '/static/logo.png';
  });

  document.getElementById('deleteAllBtn')?.addEventListener('click', async () => {
    if (!confirm('Delete all your chats? This cannot be undone.')) return;
    const convs = [...state.conversations];
    for (const c of convs) {
      try { await jfetch(`/api/conversations/${c.id}`, { method: 'DELETE' }); } catch (e) {}
    }
    await loadConversations();
    state.activeConversationId = null;
    state.activeConversation = null;
    state.messages = [];
    renderMessages();
  });

  document.getElementById('voiceBtn')?.addEventListener('click', () => startCall('voice'));
  document.getElementById('videoBtn')?.addEventListener('click', () => startCall('video'));
  document.getElementById('closeCallBtn')?.addEventListener('click', stopCall);
  document.getElementById('modeVoice')?.addEventListener('click', () => startCall('voice'));
  document.getElementById('modeVideo')?.addEventListener('click', () => startCall('video'));

  async function startCall(mode) {
    if (!state.activeConversation) {
      alert('Open a chat first.');
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
      if (state.localStream) {
        state.localStream.getTracks().forEach(t => t.stop());
      }
      state.localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: mode === 'video'
      });
      localVideo.srcObject = state.localStream;
    } catch (e) {
      localVideo.removeAttribute('srcObject');
    }
  }

  function stopCall() {
    callPanel.classList.add('hidden');
    if (state.localStream) {
      state.localStream.getTracks().forEach(t => t.stop());
      state.localStream = null;
    }
    localVideo.srcObject = null;
  }

  async function bootstrap() {
    try {
      await loadMe();
      await loadConversations();
      if (state.conversations.length) {
        await openConversation(state.conversations[0].id);
      }
      const preferred = localStorage.getItem('dc-active-conv');
      if (preferred) {
        const found = state.conversations.find(c => String(c.id) === String(preferred));
        if (found) await openConversation(found.id);
      }
    } catch (e) {
      console.error(e);
    }
  }

  const origOpen = openConversation;
  openConversation = async function (convId) {
    localStorage.setItem('dc-active-conv', String(convId));
    return origOpen(convId);
  };

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

  if (document.getElementById('newChatModal')) {
    document.getElementById('newChatModal').addEventListener('click', (e) => {
      if (e.target.id === 'newChatModal') e.currentTarget.classList.add('hidden');
    });
  }
  if (document.getElementById('profileModal')) {
    document.getElementById('profileModal').addEventListener('click', (e) => {
      if (e.target.id === 'profileModal') e.currentTarget.classList.add('hidden');
    });
  }
})();
