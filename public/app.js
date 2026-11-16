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
  const drop = $('drop');
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('is-over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('is-over'); }));
  drop.addEventListener('drop', (e) => readImage(e.dataTransfer.files[0]));
  document.addEventListener('paste', (e) => {
    const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith('image/'));
    if (item) { e.preventDefault(); readImage(item.getAsFile()); toast('Screenshot pasted'); }
  });

  /* ---------------- progress animation ---------------- */
  function startProgress() {
    const items = [...$('progress').children];
    items.forEach((li) => li.classList.remove('is-active', 'is-done'));
    let i = 0;
    items[0].classList.add('is-active');
    state.progressTimer = setInterval(() => {
      if (i < items.length - 1) {
        items[i].classList.replace('is-active', 'is-done');
        i += 1;
        items[i].classList.add('is-active');
      }
    }, 1400);
  }
  function stopProgress() { clearInterval(state.progressTimer); }

  /* ---------------- submit ---------------- */
  $('analyze-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    setError('');
    const text = $('message').value.trim();
    if (!text && !state.image) { setError('Paste a message or upload a screenshot first.'); return; }

    const btn = $('submit');
    btn.disabled = true;
    btn.querySelector('span').textContent = 'Analysing…';
    show('loading');
    $('engine').hidden = true;
    startProgress();
    if (window.innerWidth < 1024) $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, image: state.image, language: language() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      state.last = data;
      state.lastText = text;
      render(data);
      loadStats();
    } catch (err) {
      show(state.last ? 'result' : 'empty');
      setError(err.message || 'Something went wrong. Please try again.');
    } finally {
      stopProgress();
      btn.disabled = false;
      btn.querySelector('span').textContent = 'Analyse for scams';
    }
  });

  $('reset').addEventListener('click', () => {
    $('message').value = '';
    updateCount();
    clearImage();
    setError('');
    state.last = null;
    show('empty');
    $('engine').hidden = true;
    $('message').focus();
  });

  /* ---------------- render ---------------- */
  function render(data) {
    const a = data.analysis;
    const v = VERDICT_TEXT[a.verdict] || VERDICT_TEXT.SUSPICIOUS;

    const engine = $('engine');
    engine.hidden = false;
    engine.classList.toggle('is-rules', data.engine !== 'gemini');
    engine.textContent = data.engine === 'gemini'
      ? `Google Gemini · ${data.model} · ${(data.latencyMs / 1000).toFixed(1)}s`
      : 'Offline rule engine';

    const box = $('verdict');
    box.className = `verdict ${v.cls}`;
    const label = $('verdict-label');
    label.innerHTML = v.icon; // static, trusted SVG
    label.append(document.createTextNode(v.label));
    $('verdict-cat').textContent = CATEGORY_LABELS[a.scam_category] || a.scam_category;
    const meta = $('verdict-meta');
    meta.replaceChildren(el('span', { class: 'meta', text: `Confidence: ${a.confidence.toLowerCase()}` }));
    if (a.impersonated_entity) meta.append(el('span', { class: 'meta', text: `Pretending to be: ${a.impersonated_entity}` }));

    $('score').textContent = '0';
    const fill = $('gauge-fill');
    fill.style.strokeDasharray = '0 100';
    fill.style.opacity = a.risk_score > 0 ? '1' : '0';
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.strokeDasharray = `${a.risk_score} 100`; }));
    countUp($('score'), a.risk_score);

    $('notice').hidden = !data.notice;
    $('notice').textContent = data.notice || '';
    $('summary').textContent = a.summary;

    const flags = $('flags');
    flags.replaceChildren();
    $('flags-count').textContent = a.red_flags.length || '';
    if (!a.red_flags.length) flags.append(el('li', { class: 'flags__empty', text: 'No red flags were found in this content.' }));
    for (const f of a.red_flags) {
      flags.append(el('li', { class: 'flag' },
        el('span', { class: 'tag', text: TACTIC_LABELS[f.tactic] || 'Red flag' }),
        f.evidence ? el('p', { class: 'flag__quote', text: f.evidence }) : null,
        el('p', { class: 'flag__why', text: f.explanation })));
    }

    $('actions').replaceChildren(...a.recommended_actions.map((t) => el('li', { text: t })));
    $('donot-block').hidden = !a.do_not.length;
    $('donot-block').parentElement.classList.toggle('cols--single', !a.do_not.length);
    $('donot').replaceChildren(...a.do_not.map((t) => el('li', { text: t })));

    const ind = $('indicators');
    ind.replaceChildren();
    for (const [k, list] of Object.entries(data.indicators || {})) {
      for (const val of list) ind.append(el('span', { class: 'ind' }, el('b', { text: IND_LABELS[k] || k }), val));
    }
    $('ind-block').hidden = a.verdict === 'LIKELY_SAFE' || !ind.children.length;

    const rc = data.rule_check;
    const agree = rc.verdict === a.verdict;
    $('cc-badge').replaceChildren(el('span', { class: `agree${agree ? '' : ' is-diff'}`, text: agree ? 'agrees' : 'differs' }));
    $('cc-text').textContent = data.engine === 'gemini'
      ? `An independent keyword/pattern engine scored this ${rc.score}/100 (${rc.verdict.replace('_', ' ').toLowerCase()}). ${agree ? 'Both layers agree.' : 'Gemini understands context the rule engine cannot, so its verdict is shown.'}`
      : `Rule engine score: ${rc.score}/100. Patterns matched:`;
    $('cc-list').replaceChildren(...(rc.signals.length
      ? rc.signals.map((s) => el('li', { text: `${TACTIC_LABELS[s.tactic]}: ${s.explanation}` }))
      : [el('li', { text: 'No known scam keyword patterns matched.' })]));

    $('helplines').replaceChildren(...data.helplines.map((h) =>
      el('a', { href: h.href, target: h.href.startsWith('http') ? '_blank' : '_self', rel: 'noopener' }, h.value, el('small', { text: h.label }))));

    show('result');
  }

  function countUp(node, target) {
    const start = performance.now();
    const dur = 900;
    const step = (t) => {
      const p = Math.min(1, (t - start) / dur);
      node.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /* ---------------- result actions ---------------- */
  $('copy-complaint').addEventListener('click', async () => {
    const d = state.last;
    if (!d) return;
    const a = d.analysis;
    const lines = [
      'CYBER FRAUD COMPLAINT - DRAFT (for cybercrime.gov.in / 1930)',
      '',
      `Date & time of analysis: ${new Date(d.analyzedAt).toLocaleString()}`,
      `Type of fraud: ${CATEGORY_LABELS[a.scam_category] || a.scam_category}`,
      `Risk assessment: ${a.verdict} (${a.risk_score}/100)`,
      a.impersonated_entity ? `Caller / sender pretended to be: ${a.impersonated_entity}` : null,
      '',
      'What happened:',
      a.summary,
      '',
      'Red flags:',
      ...a.red_flags.map((f, i) => `${i + 1}. "${f.evidence}" - ${f.explanation}`),
    ];
    const ind = d.indicators || {};
    const indLines = Object.entries(ind).flatMap(([k, v]) => v.map((x) => `- ${IND_LABELS[k]}: ${x}`));
    if (indLines.length) lines.push('', 'Suspect details:', ...indLines);
    if (state.lastText) lines.push('', 'Original message:', state.lastText);
    lines.push('', '[Add: your name, phone number, amount lost (if any), transaction IDs, date & time of the call]');
    const out = lines.filter((l) => l !== null).join('\n');
    try {
      await navigator.clipboard.writeText(out);
      toast('Complaint draft copied - paste it at cybercrime.gov.in');
    } catch {
      toast('Copy failed - please select and copy manually');
    }
  });
  $('print').addEventListener('click', () => window.print());
  $('again').addEventListener('click', () => {
    $('reset').click();
    $('analyze').scrollIntoView({ behavior: 'smooth' });
  });

  /* ---------------- init ---------------- */
  updateCount();
  loadHealth();
  loadSamples();
  loadStats();
})();
