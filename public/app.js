'use strict';

(() => {
  const $ = (id) => document.getElementById(id);

  const CATEGORY_LABELS = {
    DIGITAL_ARREST: 'Digital arrest scam',
    COURIER_PARCEL: 'Courier / parcel scam',
    KYC_BANK_UPDATE: 'KYC / bank account scam',
    UPI_PAYMENT_FRAUD: 'UPI payment fraud',
    INVESTMENT_TRADING: 'Investment / trading scam',
    JOB_TASK_SCAM: 'Job / task scam',
    LOTTERY_PRIZE: 'Lottery / prize scam',
    SEXTORTION: 'Sextortion',
    IMPERSONATION_FAMILY_FRIEND: 'Family / friend impersonation',
    LOAN_APP: 'Loan app fraud',
    UTILITY_BILL: 'Electricity / utility bill scam',
    CUSTOMER_CARE_FRAUD: 'Fake customer care / remote access',
    PHISHING_LINK: 'Phishing link',
    OTHER_FRAUD: 'Other cyber fraud',
    NOT_A_SCAM: 'No scam pattern detected',
  };
  const TACTIC_LABELS = {
    AUTHORITY_IMPERSONATION: 'Fake authority',
    FEAR_THREAT: 'Fear / threat',
    URGENCY: 'Urgency',
    ISOLATION_SECRECY: 'Isolation / secrecy',
    PAYMENT_DEMAND: 'Payment demand',
    PERSONAL_DATA_REQUEST: 'Data request',
    SUSPICIOUS_LINK: 'Suspicious link',
    TOO_GOOD_TO_BE_TRUE: 'Too good to be true',
    REMOTE_ACCESS: 'Remote access',
    OTHER: 'Red flag',
  };
  const VERDICT_TEXT = {
    SCAM: { label: 'Scam detected', cls: 'verdict--scam',
      icon: '<svg viewBox="0 0 24 24"><path d="M12 3 2 20h20L12 3Z" fill="currentColor"/><path d="M12 10v4" stroke="#0B0B0C" stroke-width="2.4" stroke-linecap="round"/><circle cx="12" cy="17" r="1.3" fill="#0B0B0C"/></svg>' },
    SUSPICIOUS: { label: 'Suspicious', cls: 'verdict--suspicious',
      icon: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M12 7v6" stroke="#FFD60A" stroke-width="2.4" stroke-linecap="round"/><circle cx="12" cy="16.6" r="1.3" fill="#FFD60A"/></svg>' },
    LIKELY_SAFE: { label: 'Likely safe', cls: 'verdict--safe',
      icon: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#16A34A"/><path d="m7.5 12.5 3 3 6-6" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>' },
  };
  const IND_LABELS = { urls: 'Link', phone_numbers: 'Phone', upi_ids: 'UPI', emails: 'Email', amounts: 'Amount', bank_accounts: 'Account' };

  const state = { image: null, last: null, lastText: '', samples: [], progressTimer: null };

  /* ---------------- helpers ---------------- */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const c of children) if (c != null) node.append(c);
    return node;
  }
  function show(which) {
    for (const s of ['empty', 'loading', 'result']) $(`state-${s}`).hidden = s !== which;
  }
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 2600);
  }
  function setError(msg) {
    $('error').textContent = msg || '';
    $('error').hidden = !msg;
  }
  const language = () => document.querySelector('input[name="language"]:checked').value;

  /* ---------------- status + stats ---------------- */
  async function loadHealth() {
    const s = $('status');
    try {
      const h = await (await fetch('/api/health')).json();
      s.classList.add(h.geminiConfigured ? 'is-online' : 'is-offline');
      s.querySelector('.status__text').textContent = h.geminiConfigured
        ? `Gemini online · ${h.revision === 'local' ? 'local' : 'Cloud Run'}`
        : 'Offline rule engine';
      s.title = `Model: ${h.model} · Revision: ${h.revision}`;
    } catch {
      s.querySelector('.status__text').textContent = 'Server unreachable';
    }
  }
  async function loadStats() {
    try {
      const st = await (await fetch('/api/stats')).json();
      if (!st.total) return;
      $('livestats').hidden = false;
      $('st-total').textContent = st.total;
      $('st-scam').textContent = st.scam;
      $('st-sus').textContent = st.suspicious;
      $('st-safe').textContent = st.safe;
    } catch { /* optional */ }
  }

  /* ---------------- samples ---------------- */
  async function loadSamples() {
    try {
      const { samples } = await (await fetch('/api/samples')).json();
      state.samples = samples;
      const list = $('samples');
      for (const s of samples) {
        const b = el('button', { type: 'button', class: `sample${s.expected === 'LIKELY_SAFE' ? ' sample--safe' : ''}`, title: s.title },
          el('span', { class: 'sample__dot' }), s.title);
        b.addEventListener('click', () => {
          selectTab('text');
          $('message').value = s.text;
          updateCount();
          $('message').focus();
          toast(`Loaded example: ${s.title}`);
        });
        list.append(b);
      }
    } catch { $('samples').closest('.samples').hidden = true; }
  }

  /* ---------------- tabs ---------------- */
  function selectTab(name) {
    for (const t of ['text', 'image']) {
      const tab = $(`tab-${t}`);
      const active = t === name;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', String(active));
      $(`panel-${t}`).hidden = !active;
    }
  }
  $('tab-text').addEventListener('click', () => selectTab('text'));
  $('tab-image').addEventListener('click', () => selectTab('image'));

  /* ---------------- text ---------------- */
  function updateCount() { $('count').textContent = `${$('message').value.length} / 8000`; }
  $('message').addEventListener('input', updateCount);
  $('message').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); $('analyze-form').requestSubmit(); }
  });

  /* ---------------- image ---------------- */
  function readImage(file) {
    if (!file || !/^image\/(png|jpe?g|webp)$/i.test(file.type)) {
      setError('Please choose a PNG, JPG or WEBP image.');
      return;
    }
    if (file.size > 15 * 1024 * 1024) { setError('Image is too large (max 15 MB).'); return; }
    setError('');
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      // Downscale large screenshots so uploads stay fast on mobile data.
      const max = 1600;
      const scale = Math.min(1, max / Math.max(img.width, img.height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.round(img.width * scale);
      canvas.height = Math.round(img.height * scale);
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const dataUrl = canvas.toDataURL('image/jpeg', 0.88);
      state.image = { mimeType: 'image/jpeg', data: dataUrl.split(',')[1] };
      $('preview-img').src = dataUrl;
      $('drop-empty').hidden = true;
      $('drop-preview').hidden = false;
      URL.revokeObjectURL(url);
      selectTab('image');
    };
    img.onerror = () => setError('Could not read that image.');
    img.src = url;
  }
  function clearImage() {
    state.image = null;
    $('file').value = '';
    $('preview-img').removeAttribute('src');
    $('drop-empty').hidden = false;
    $('drop-preview').hidden = true;
  }
  $('file').addEventListener('change', (e) => readImage(e.target.files[0]));
  $('clear-image').addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); clearImage(); });
