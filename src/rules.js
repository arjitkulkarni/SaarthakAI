'use strict';

/**
 * Layer 1 - Rule-based scam signal engine.
 *
 * Runs instantly on every request (no network). Its signals are shown next to the
 * Gemini result as an independent cross-check, and it becomes the fallback
 * classifier if the Gemini API is unreachable, so the system never fails silently.
 */

const { verdictFromScore } = require('./constants');

const RULES = [
  // ---- Authority impersonation ----
  { id: 'agency', tactic: 'AUTHORITY_IMPERSONATION', category: 'DIGITAL_ARREST', weight: 18,
    re: /\b(cbi|enforcement directorate|\bED\b|ncb|narcotics|crime branch|cyber ?cell|cyber crime (?:department|branch|police)|mumbai police|delhi police|income tax (?:department|officer)|customs (?:department|officer)|trai|rbi officer|supreme court|high court|interpol|ips officer|dcp|sho\b)/i,
    why: 'Claims to be from a police / investigation / government agency.' },
  { id: 'arrest', tactic: 'FEAR_THREAT', category: 'DIGITAL_ARREST', weight: 22,
    re: /(digital(?:ly)? arrest|arrest warrant|warrant (?:has been |is )?issued|you (?:will|shall) be arrested|under arrest|giraftar|गिरफ्तार|non[- ]bailable|fir (?:has been |is )?(?:registered|filed|lodged))/i,
    why: 'Threatens arrest / legal action. Real police never "arrest" anyone over a video or phone call.' },
  { id: 'crime', tactic: 'FEAR_THREAT', category: 'DIGITAL_ARREST', weight: 14,
    re: /(money laundering|hawala|drug trafficking|human trafficking|terror(?:ist)? funding|illegal (?:transaction|activity|activities)|case (?:registered )?against you|involved in (?:a )?(?:crime|case|scam))/i,
    why: 'Accuses the victim of a serious crime to create panic.' },
  { id: 'videocall', tactic: 'ISOLATION_SECRECY', category: 'DIGITAL_ARREST', weight: 16,
    re: /((?:stay|remain|be) (?:on|in) (?:the )?(?:video )?call|(?:do not|don'?t|never) (?:disconnect|cut|end) (?:the )?(?:video )?call|skype|camera on|under (?:video )?surveillance|keep (?:your )?(?:video|camera) on)/i,
    why: 'Forces the victim to stay on a video call - the hallmark of a "digital arrest" scam.' },
  { id: 'secrecy', tactic: 'ISOLATION_SECRECY', category: null, weight: 18,
    re: /((?:do not|don'?t|never) (?:tell|inform|share (?:this )?with|discuss with) (?:anyone|anybody|your family|family|friends|relatives|bank)|confidential (?:investigation|matter|case)|national secret|secret(?:ly)? (?:investigation|matter)|kisi ko mat (?:batana|batao)|किसी को (?:मत|ना) बता)/i,
    why: 'Asks the victim to keep it secret from family or bank - isolation is a classic scam tactic.' },
  { id: 'safeacct', tactic: 'PAYMENT_DEMAND', category: 'DIGITAL_ARREST', weight: 24,
    re: /(safe account|rbi (?:verification |secure )?account|verification account|(?:fund|money) (?:verification|legali[sz]ation)|security deposit|refundable (?:amount|deposit)|will be refunded|government account|escrow account|settlement amount)/i,
    why: 'Asks to move money to a "safe / verification" account. No government agency does this.' },
  { id: 'aadhaar', tactic: 'PERSONAL_DATA_REQUEST', category: null, weight: 8,
    re: /(aadhaar|aadhar|pan card|\bpan\b(?! india)|passport (?:number|details)|sim (?:card )?(?:is )?(?:registered|issued|linked))/i,
    why: 'Mentions your identity documents (Aadhaar / PAN / SIM) to sound official.' },

  // ---- Courier / parcel ----
  { id: 'parcel', tactic: 'FEAR_THREAT', category: 'COURIER_PARCEL', weight: 16,
    re: /((?:parcel|package|courier|consignment|shipment)[^.\n]{0,80}(?:seized|illegal|drugs|mdma|narcotic|passports?|contraband|returned|held|customs)|(?:seized|illegal|drugs|mdma)[^.\n]{0,60}(?:parcel|package|courier|consignment))/i,
    why: 'Claims a parcel in your name contains drugs / illegal items - a common opening for digital-arrest scams.' },
  { id: 'press9', tactic: 'URGENCY', category: 'COURIER_PARCEL', weight: 10,
    re: /(press (?:\d|one|nine)|dial (?:\d) to (?:speak|connect)|ivr)/i,
    why: 'Automated IVR "press a key" call - often used to route victims to fake officers.' },

  // ---- Payment / UPI ----
  { id: 'pay', tactic: 'PAYMENT_DEMAND', category: null, weight: 12,
    re: /((?:transfer|pay|send|deposit) (?:the )?(?:amount|money|rs\.?|₹|inr|fine|fee|penalty|charges|tax)|processing fee|registration fee|clearance (?:fee|charges)|pay (?:a )?(?:fine|penalty)|(?:make|do) (?:the )?payment)/i,
    why: 'Demands a payment or fee.' },
  { id: 'upipin', tactic: 'PAYMENT_DEMAND', category: 'UPI_PAYMENT_FRAUD', weight: 30,
    re: /((?:enter|share|tell|type) (?:your )?(?:upi )?pin|scan (?:this |the )?qr(?: code)? to (?:receive|get)|(?:accept|approve) (?:the |my )?(?:collect |payment )?request[^.\n]{0,40}(?:receive|get|refund))/i,
    why: 'UPI trick: you never need to enter a PIN, scan a QR code or accept a request to RECEIVE money.' },
  { id: 'mistake', tactic: 'URGENCY', category: 'UPI_PAYMENT_FRAUD', weight: 14,
    re: /(sent (?:to you |to your (?:number|account) )?by mistake|by mistake|wrongly (?:sent|transferred)|return (?:the |my )?(?:money|amount))/i,
    why: '"Sent by mistake" story - check your own bank app; the money usually never arrived.' },
  { id: 'otp', tactic: 'PERSONAL_DATA_REQUEST', category: 'KYC_BANK_UPDATE', weight: 16,
    re: /((?:share|send|tell|provide|give|forward)[^.\n]{0,25}\b(?:otp|cvv|pin|password|card (?:number|details))\b|\b(?:otp|cvv)\b[^.\n]{0,25}(?:share|send|tell|provide|give))/i,
    why: 'Asks for OTP / PIN / CVV / password. Banks never ask for these.' },

  // ---- KYC / bank / utility ----
  { id: 'blocked', tactic: 'URGENCY', category: 'KYC_BANK_UPDATE', weight: 14,
    re: /((?:account|card|sim|number|wallet|yono|net ?banking)[^.\n]{0,40}(?:will be |has been |is |be )(?:blocked|suspended|deactivated|frozen|closed|disconnected)|kyc[^.\n]{0,30}(?:expired|pending|update|incomplete|suspended)|update (?:your )?(?:kyc|pan))/i,
    why: 'Threatens to block your account / SIM unless you act now.' },
  { id: 'power', tactic: 'FEAR_THREAT', category: 'UTILITY_BILL', weight: 30,
    re: /((?:electricity|power|bijli|gas)[^.\n]{0,60}(?:disconnect|cut|cut off|discontinue)|(?:previous month|last month) bill (?:was )?not (?:updated|paid))/i,
    why: 'Threatens electricity / utility disconnection tonight - a well-known fraud SMS pattern.' },
  { id: 'deadline', tactic: 'URGENCY', category: null, weight: 10,
    re: /(immediately|urgent(?:ly)?|within (?:\d+|one|two|24) (?:hours?|hrs|minutes?|mins)|today itself|tonight|(?:at|by) \d{1,2}(?::\d{2})? ?(?:pm|am)|last (?:chance|warning|reminder)|turant|तुरंत|act now|right now|failing which)/i,
    why: 'Creates artificial urgency so you do not stop and verify.' },
  { id: 'callback', tactic: 'URGENCY', category: null, weight: 10,
    re: /((?:contact|call|whatsapp|reach) (?:our |the |this |immediately )?(?:[a-z]+ ){0,2}(?:officer|executive|agent|helpline|number)\b[^.\n]{0,25}\d{2}[\dX]{3,})/i,
    why: 'Asks you to call back a personal mobile number instead of an official helpline.' },
  { id: 'remote', tactic: 'REMOTE_ACCESS', category: 'CUSTOMER_CARE_FRAUD', weight: 22,
    re: /(anydesk|teamviewer|quick ?support|rustdesk|airdroid|screen ?shar(?:e|ing)|install (?:this |the )?(?:app|apk)|download (?:this |the )?(?:app|apk)|\.apk\b)/i,
    why: 'Asks you to install a remote-access / unknown app that lets scammers control your phone.' },

  // ---- Links ----
  { id: 'shortlink', tactic: 'SUSPICIOUS_LINK', category: 'PHISHING_LINK', weight: 14,
    re: /(bit\.ly|tinyurl|cutt\.ly|is\.gd|t\.ly|rb\.gy|shorturl|\b[a-z0-9-]+\.(?:xyz|top|club|online|site|buzz|icu|live|info|shop|click|link|vip|cc|tk)\b(?:\/\S*)?)/i,
    why: 'Contains a shortened or suspicious-domain link (possible phishing site).' },

  // ---- Too good to be true ----
  { id: 'job', tactic: 'TOO_GOOD_TO_BE_TRUE', category: 'JOB_TASK_SCAM', weight: 22,
    re: /(part[- ]time (?:job|work)|work from home[^.\n]{0,40}(?:earn|daily|income)|earn (?:rs\.?|₹|inr)?\s?[\d,]+ ?(?:\/|per|a)? ?(?:day|daily)|(?:like|rate|review|subscribe)[^.\n]{0,30}(?:videos?|hotels?|products?|channels?)[^.\n]{0,40}(?:earn|paid|commission)|prepaid task|telegram (?:task|group))/i,
    why: 'Easy money for simple online tasks - classic job / task scam.' },
  { id: 'invest', tactic: 'TOO_GOOD_TO_BE_TRUE', category: 'INVESTMENT_TRADING', weight: 16,
    re: /(guaranteed (?:returns?|profit)|(?:double|triple) your (?:money|investment)|\d{2,3}% (?:returns?|profit)|ipo allotment|stock tips|vip (?:trading )?group|institutional account|crypto (?:investment|trading) (?:platform|group)|risk[- ]free (?:profit|returns?))/i,
    why: 'Promises guaranteed / unrealistic investment returns.' },
  { id: 'lottery', tactic: 'TOO_GOOD_TO_BE_TRUE', category: 'LOTTERY_PRIZE', weight: 18,
    re: /((?:you have |you'?ve )?won (?:a |the )?(?:lottery|prize|lucky draw|car|iphone|cash)|lucky draw|kbc lottery|lottery (?:winner|prize)|claim (?:your )?(?:prize|reward|gift))/i,
    why: 'Claims you won a lottery / prize you never entered.' },
  { id: 'loan', tactic: 'TOO_GOOD_TO_BE_TRUE', category: 'LOAN_APP', weight: 14,
    re: /(instant loan[^.\n]{0,40}(?:without|no) (?:documents|cibil|verification)|pre[- ]?approved loan[^.\n]{0,40}(?:fee|charge|pay))/i,
    why: 'Instant loan that needs an upfront fee - typical loan-app fraud.' },
  { id: 'sextortion', tactic: 'FEAR_THREAT', category: 'SEXTORTION', weight: 24,
    re: /((?:obscene|nude|private|morphed|intimate) (?:video|photo|pictures?|clip)[^.\n]{0,60}(?:viral|upload|share|send|leak)|(?:viral|leak|upload)[^.\n]{0,40}(?:obscene|nude|private|morphed) (?:video|photo))/i,
    why: 'Threatens to leak private / morphed content - sextortion. Do not pay; report immediately.' },
  { id: 'family', tactic: 'URGENCY', category: 'IMPERSONATION_FAMILY_FRIEND', weight: 14,
    re: /((?:this is|it'?s) (?:your )?(?:son|daughter|beta|nephew|friend)[^.\n]{0,60}(?:new number|lost (?:my )?phone|accident|hospital|urgent)|(?:new number|lost (?:my )?phone)[^.\n]{0,60}(?:send|need|transfer) (?:money|rs|₹))/i,
    why: 'Pretends to be a family member / friend in an emergency asking for money.' },
];

const COMBOS = [
  { needs: ['AUTHORITY_IMPERSONATION', 'PAYMENT_DEMAND'], bonus: 15,
    why: 'An "officer" asking for money is never legitimate.' },
  { needs: ['AUTHORITY_IMPERSONATION', 'ISOLATION_SECRECY'], bonus: 15,
    why: 'An "officer" telling you to stay isolated on a call matches the digital-arrest pattern.' },
  { needs: ['FEAR_THREAT', 'PAYMENT_DEMAND'], bonus: 10,
    why: 'Threat followed by a payment demand is extortion.' },
];

function snippet(text, index, length) {
  const start = Math.max(0, index - 35);
  const end = Math.min(text.length, index + length + 35);
  let s = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) s = '…' + s;
  if (end < text.length) s = s + '…';
  return s;
}

/** Extract actionable indicators (useful when filing a complaint). */
function extractIndicators(text) {
  const uniq = (arr) => [...new Set(arr.map((x) => x.trim()))].slice(0, 10);
  const urls = text.match(/\b(?:https?:\/\/|www\.)[^\s<>"')]+|\b[a-z0-9-]+\.(?:xyz|top|club|online|site|buzz|icu|live|info|shop|click|link|vip|cc|tk|in|com|net|org)\/[^\s<>"')]*/gi) || [];
  const phones = (text.match(/(?:\+91[\s-]?|\b0)?[6-9]\d{4}[\s-]?\d{5}\b/g) || []).filter((p) => p.replace(/\D/g, '').length >= 10);
  const upi = (text.match(/\b[a-z0-9._-]{2,}@[a-z]{2,}\b(?![.@])/gi) || []);
  const emails = text.match(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi) || [];
  const amounts = text.match(/(?:₹|rs\.?|inr)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:lakh|lakhs|crore|k))?/gi) || [];
  const accounts = (text.match(/\b(?:a\/c|acct|account)(?:\s*(?:no|number|num)\.?)?[:\s#.-]*\d{9,18}\b/gi) || []);
  return {
    urls: uniq(urls),
    phone_numbers: uniq(phones),
    upi_ids: uniq(upi),
    emails: uniq(emails),
    amounts: uniq(amounts),
    bank_accounts: uniq(accounts),
  };
}

const ACTIONS = {
  DIGITAL_ARREST: [
    'Disconnect the call immediately. "Digital arrest" does not exist in Indian law - no police, CBI, ED, RBI or court arrests anyone over a video call.',
    'Do not transfer any money. No agency has a "safe" or "verification" account.',
    'Tell a family member right now - scammers depend on you staying isolated.',
    'Call 1930 or report at cybercrime.gov.in. If you already paid, call 1930 within the first hour (golden hour) to freeze the money.',
  ],
  COURIER_PARCEL: [
    'Hang up. Courier companies do not connect you to police over IVR.',
    'Track parcels only on the official courier website you used yourself.',
    'Report the number on Sanchar Saathi (Chakshu) and at cybercrime.gov.in.',
  ],
  KYC_BANK_UPDATE: [
    'Do not click the link or call the number in the message.',
    'Contact your bank only through the number printed on your card or the official app.',
    'Never share OTP, PIN, CVV or passwords with anyone.',
  ],
  UPI_PAYMENT_FRAUD: [
    'Remember: you never enter a UPI PIN or scan a QR code to RECEIVE money.',
    'Decline unknown collect requests and verify "sent by mistake" claims in your own bank app.',
    'Report on 1930 / cybercrime.gov.in.',
  ],
  DEFAULT: [
    'Do not reply, click links, install apps or make any payment.',
    'Verify independently using an official website or phone number you find yourself.',
    'Report it: call 1930, file at cybercrime.gov.in, and flag the number on Sanchar Saathi (Chakshu).',
  ],
  SAFE: [
    'No strong scam signals were found, but stay alert.',
    'If anyone later asks for money, OTP or secrecy, treat it as a scam and verify independently.',
  ],
};

const DO_NOT = [
  'Do not share OTP, UPI PIN, CVV or passwords.',
  'Do not install apps like AnyDesk / TeamViewer on a caller\'s request.',
  'Do not transfer money to "verify" or "clear" your name.',
  'Do not stay on a video call with someone claiming to be police.',
];

/**
 * Analyse text with the rule engine.
 * @returns {{score:number, verdict:string, category:string, signals:Array, indicators:object}}
 */
function analyzeRules(rawText) {
  const text = String(rawText || '');
  const signals = [];
  const tactics = new Set();
  const catWeights = {};
  let score = 0;

  for (const rule of RULES) {
    const m = rule.re.exec(text);
    if (!m) continue;
    score += rule.weight;
    tactics.add(rule.tactic);
    if (rule.category) catWeights[rule.category] = (catWeights[rule.category] || 0) + rule.weight;
    signals.push({
      id: rule.id,
      tactic: rule.tactic,
      evidence: snippet(text, m.index, m[0].length),
      explanation: rule.why,
      weight: rule.weight,
    });
  }

  for (const combo of COMBOS) {
    if (combo.needs.every((t) => tactics.has(t))) score += combo.bonus;
  }

  score = Math.max(0, Math.min(100, score));
  const verdict = verdictFromScore(score);

  let category = 'NOT_A_SCAM';
  if (verdict !== 'LIKELY_SAFE') {
    const best = Object.entries(catWeights).sort((a, b) => b[1] - a[1])[0];
    category = best ? best[0] : 'OTHER_FRAUD';
  }

  return { score, verdict, category, signals, tactics: [...tactics], indicators: extractIndicators(text) };
}

/** Build a full analysis object (same shape as the Gemini result) from rule output. */
function rulesToAnalysis(rules) {
  const isSafe = rules.verdict === 'LIKELY_SAFE';
  const actions = isSafe ? ACTIONS.SAFE : (ACTIONS[rules.category] || ACTIONS.DEFAULT);
  const n = rules.signals.length;
  return {
    verdict: rules.verdict,
    risk_score: rules.score,
    confidence: isSafe ? 'MEDIUM' : n >= 4 ? 'HIGH' : n >= 2 ? 'MEDIUM' : 'LOW',
    scam_category: rules.category,
    impersonated_entity: '',
    summary: isSafe
      ? 'The offline rule engine did not find strong scam patterns in this message.'
      : `The offline rule engine found ${n} scam signal${n === 1 ? '' : 's'} matching known Indian cyber-fraud patterns.`,
    red_flags: [...rules.signals].sort((a, b) => b.weight - a.weight).slice(0, 6)
      .map((s) => ({ evidence: s.evidence, explanation: s.explanation, tactic: s.tactic })),
    recommended_actions: actions,
    do_not: isSafe ? [] : DO_NOT,
  };
}

module.exports = { analyzeRules, rulesToAnalysis, extractIndicators, RULES };
