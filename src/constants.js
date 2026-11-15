'use strict';

/** Scam categories the system can classify a message into. */
const CATEGORIES = [
  'DIGITAL_ARREST',
  'COURIER_PARCEL',
  'KYC_BANK_UPDATE',
  'UPI_PAYMENT_FRAUD',
  'INVESTMENT_TRADING',
  'JOB_TASK_SCAM',
  'LOTTERY_PRIZE',
  'SEXTORTION',
  'IMPERSONATION_FAMILY_FRIEND',
  'LOAN_APP',
  'UTILITY_BILL',
  'CUSTOMER_CARE_FRAUD',
  'PHISHING_LINK',
  'OTHER_FRAUD',
  'NOT_A_SCAM',
];

/** Psychological / technical manipulation tactics. */
const TACTICS = [
  'AUTHORITY_IMPERSONATION',
  'FEAR_THREAT',
  'URGENCY',
  'ISOLATION_SECRECY',
  'PAYMENT_DEMAND',
  'PERSONAL_DATA_REQUEST',
  'SUSPICIOUS_LINK',
  'TOO_GOOD_TO_BE_TRUE',
  'REMOTE_ACCESS',
  'OTHER',
];

const VERDICTS = ['SCAM', 'SUSPICIOUS', 'LIKELY_SAFE'];
const CONFIDENCE = ['HIGH', 'MEDIUM', 'LOW'];

const LANGUAGES = {
  en: 'English',
  hi: 'Hindi (Devanagari script)',
  kn: 'Kannada (Kannada script)',
};

/** Official Indian reporting channels shown with every result. */
const HELPLINES = [
  { label: 'National Cyber Crime Helpline', value: '1930', href: 'tel:1930' },
  { label: 'Report online', value: 'cybercrime.gov.in', href: 'https://cybercrime.gov.in' },
  { label: 'Report fraud calls / SMS (Chakshu)', value: 'sancharsaathi.gov.in', href: 'https://sancharsaathi.gov.in' },
];

/** Verdict thresholds applied to the 0-100 risk score. */
function verdictFromScore(score) {
  if (score >= 60) return 'SCAM';
  if (score >= 30) return 'SUSPICIOUS';
  return 'LIKELY_SAFE';
}

module.exports = { CATEGORIES, TACTICS, VERDICTS, CONFIDENCE, LANGUAGES, HELPLINES, verdictFromScore };
