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
