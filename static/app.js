
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.dots-btn');
  document.querySelectorAll('.dots-panel.open').forEach(panel => {
    if (!btn || panel !== btn.nextElementSibling) panel.classList.remove('open');
  });
  if (btn) {
    const panel = btn.nextElementSibling;
    if (panel && panel.classList.contains('dots-panel')) panel.classList.toggle('open');
  }
});

document.addEventListener('click', (e) => {
  if (!e.target.closest('.dots-menu')) {
    document.querySelectorAll('.dots-panel.open').forEach(panel => panel.classList.remove('open'));
  }
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
    const current = form.querySelector('input[name="alias"]').value || '';
    const next = prompt('Rename this contact', current);
    if (next === null) {
      e.preventDefault();
      return;
    }
    form.querySelector('input[name="alias"]').value = next.trim();
  });
});

const inviteResult = document.getElementById('inviteResult');
if (inviteResult) {
  const flash = document.querySelector('.flash');
  if (flash && flash.innerText.includes('http')) {
    inviteResult.hidden = false;
    inviteResult.innerHTML = `<div>Invite link created</div><div style="margin-top:6px;word-break:break-all">${flash.innerText}</div>`;
  }
}
