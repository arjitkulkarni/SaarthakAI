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

