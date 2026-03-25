function closeMenus(except) {
  document.querySelectorAll('.dots-panel.open').forEach(panel => {
    if (panel !== except) panel.classList.remove('open');
  });
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('.dots-btn');
  if (btn) {
    const panel = btn.nextElementSibling;
    closeMenus(panel);
    if (panel && panel.classList.contains('dots-panel')) {
      panel.classList.toggle('open');
    }
    return;
  }
  if (!e.target.closest('.dots-menu') && !e.target.closest('.chat-menu')) closeMenus();
});

document.querySelectorAll('.tabs').forEach(tabset => {
  const tabs = tabset.querySelectorAll('.tab');
  const panels = tabset.parentElement.querySelectorAll('.tab-panel');
  tabs.forEach(tab => tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    panels.forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const panel = tabset.parentElement.querySelector(`#${tab.dataset.tab}`);
    if (panel) panel.classList.add('active');
  }));
});

const avatarBtn = document.querySelector('.chat-avatar-btn');
const modal = document.getElementById('imageModal');
const modalImg = document.getElementById('modalImage');
const closeModal = document.getElementById('closeModal');
if (avatarBtn && modal && modalImg) {
  avatarBtn.addEventListener('click', () => {
    modalImg.src = avatarBtn.dataset.preview;
    modal.classList.add('open');
  });
}
if (closeModal && modal) closeModal.addEventListener('click', () => modal.classList.remove('open'));
if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('open'); });

document.querySelectorAll('.rename-form').forEach(form => {
  form.addEventListener('submit', (e) => {
    const field = form.querySelector('input[name="alias"]');
    const current = field.value || '';
    const next = prompt('Rename this contact', current);
    if (next === null) {
      e.preventDefault();
      return;
    }
    field.value = next.trim();
  });
});

const searchInput = document.getElementById('contactSearch');
const contactList = document.getElementById('contactList');
if (searchInput && contactList) {
  const items = [...contactList.querySelectorAll('.contact-item')];
  searchInput.addEventListener('input', () => {
    const q = searchInput.value.trim().toLowerCase();
    items.forEach(item => {
      const name = item.dataset.name || '';
      item.style.display = !q || name.includes(q) ? '' : 'none';
    });
  });
}

const inviteResult = document.getElementById('inviteResult');
if (inviteResult) {
  const url = inviteResult.dataset.url;
  if (url) {
    inviteResult.hidden = false;
    inviteResult.innerHTML = `<div class="invite-label">Invite link</div><div class="invite-url">${url}</div>`;
    if (navigator.clipboard && window.isSecureContext) {
      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'secondary';
      copyBtn.style.marginTop = '10px';
      copyBtn.textContent = 'Copy link';
      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(url);
          copyBtn.textContent = 'Copied';
          setTimeout(() => copyBtn.textContent = 'Copy link', 1200);
        } catch (_) {}
      });
      inviteResult.appendChild(copyBtn);
    }
  }
}

const attachmentSheet = document.getElementById('attachmentSheet');
const closeAttachmentSheet = document.getElementById('closeAttachmentSheet');
const attachmentInput = document.getElementById('attachmentInput');
const shareLocation = document.getElementById('shareLocation');
const locationLabel = document.getElementById('locationLabel');
const locationMeta = document.getElementById('locationMeta');
const callOverlay = document.getElementById('callOverlay');
const callTitle = document.getElementById('callTitle');

function openCall(kind) {
  if (!callOverlay || !callTitle) return;
  callTitle.textContent = kind === 'video' ? 'Video call' : kind === 'audio' ? 'Audio call' : 'Share';
  callOverlay.classList.add('open');
  callOverlay.hidden = false;
}

function closeCall() {
  if (!callOverlay) return;
  callOverlay.classList.remove('open');
  callOverlay.hidden = true;
}

document.querySelectorAll('[data-call]').forEach(btn => {
  btn.addEventListener('click', () => {
    const kind = btn.dataset.call;
    if (kind === 'share') {
      if (attachmentSheet) {
        attachmentSheet.classList.add('open');
        attachmentSheet.hidden = false;
      }
      return;
    }
    openCall(kind);
  });
});

document.querySelectorAll('[data-attach]').forEach(btn => {
  btn.addEventListener('click', () => {
    if (attachmentInput) attachmentInput.click();
  });
});

if (closeAttachmentSheet && attachmentSheet) {
  closeAttachmentSheet.addEventListener('click', () => {
    attachmentSheet.classList.remove('open');
    attachmentSheet.hidden = true;
  });
}
if (attachmentSheet) {
  attachmentSheet.addEventListener('click', (e) => {
    if (e.target === attachmentSheet) {
      attachmentSheet.classList.remove('open');
      attachmentSheet.hidden = true;
    }
  });
}

if (shareLocation && locationLabel && locationMeta) {
  shareLocation.addEventListener('click', async () => {
    if (!navigator.geolocation) {
      alert('Location sharing is not supported on this device.');
      return;
    }
    navigator.geolocation.getCurrentPosition((pos) => {
      locationLabel.value = `Shared location`;
      locationMeta.value = JSON.stringify({
        lat: pos.coords.latitude,
        lng: pos.coords.longitude,
        accuracy: pos.coords.accuracy
      });
      const form = shareLocation.closest('form');
      if (form) form.requestSubmit();
    }, () => {
      alert('Could not get your location.');
    });
  });
}

const cancelCall = document.getElementById('cancelCall');
const muteCall = document.getElementById('muteCall');
const minimizeCall = document.getElementById('minimizeCall');
if (cancelCall) cancelCall.addEventListener('click', closeCall);
if (muteCall) muteCall.addEventListener('click', () => muteCall.textContent = muteCall.textContent === 'Mute' ? 'Muted' : 'Mute');
if (minimizeCall) minimizeCall.addEventListener('click', closeCall);
if (callOverlay) callOverlay.addEventListener('click', (e) => { if (e.target === callOverlay) closeCall(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeCall(); });

/* ----- PWA install + persistent storage ----- */
let deferredInstallPrompt = null;
const installBtn = document.getElementById('pwaInstallBtn');

async function requestPersistentStorage() {
  try {
    if (navigator.storage && navigator.storage.persist) {
      await navigator.storage.persist();
    }
  } catch (_) {}
}

function isStandaloneMode() {
  return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}

function refreshInstallButton() {
  if (!installBtn) return;
  const hiddenByInstall = localStorage.getItem('pwaInstalled') === '1' || isStandaloneMode();
  installBtn.hidden = hiddenByInstall || !deferredInstallPrompt;
}

if (installBtn) {
  installBtn.addEventListener('click', async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    try {
      const choice = await deferredInstallPrompt.userChoice;
      if (choice && choice.outcome === 'accepted') {
        localStorage.setItem('pwaInstalled', '1');
      }
    } finally {
      deferredInstallPrompt = null;
      refreshInstallButton();
    }
  });
}

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  refreshInstallButton();
});

window.addEventListener('appinstalled', () => {
  localStorage.setItem('pwaInstalled', '1');
  deferredInstallPrompt = null;
  refreshInstallButton();
});

window.addEventListener('load', () => {
  requestPersistentStorage();
  refreshInstallButton();
});

/* ----- local chat archive so chats survive builds on the device ----- */
const TT_DB_NAME = 'tomorrowtalk-pwa';
const TT_DB_VERSION = 1;
const TT_STORE = 'chatSnapshots';

function openTTDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(TT_DB_NAME, TT_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(TT_STORE)) {
        db.createObjectStore(TT_STORE, { keyPath: 'chatKey' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveChatSnapshot(chatKey, html) {
  if (!chatKey || !html) return;
  try {
    const db = await openTTDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(TT_STORE, 'readwrite');
      tx.objectStore(TT_STORE).put({
        chatKey,
        html,
        savedAt: new Date().toISOString()
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch (_) {}
}

async function loadChatSnapshot(chatKey) {
  try {
    const db = await openTTDB();
    const result = await new Promise((resolve, reject) => {
      const tx = db.transaction(TT_STORE, 'readonly');
      const req = tx.objectStore(TT_STORE).get(chatKey);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return result;
  } catch (_) {
    return null;
  }
}

async function hydrateChatFromCache() {
  const stream = document.getElementById('chatMessageStream');
  if (!stream) return;
  const chatKey = stream.dataset.chatKey;
  if (!chatKey) return;

  const currentHtml = stream.innerHTML.trim();
  const hasRealMessages = currentHtml && !currentHtml.includes('empty-chat');
  if (hasRealMessages) {
    await saveChatSnapshot(chatKey, stream.innerHTML);
    return;
  }

  const cached = await loadChatSnapshot(chatKey);
  if (cached && cached.html) {
    stream.innerHTML = cached.html;
  }
}

window.addEventListener('load', hydrateChatFromCache);
