'use strict';

/**
 * Demo messages modelled on publicly reported Indian scam patterns.
 * Names, numbers, links and account IDs are fictitious.
 */
const SAMPLES = [
  {
    id: 'digital-arrest',
    title: 'Digital arrest video call',
    tag: 'Digital arrest',
    expected: 'SCAM',
    text: `[WhatsApp video call transcript]
Caller (in police uniform): This is Inspector R. K. Sharma, Cyber Crime Branch, Mumbai Police. Your Aadhaar number has been used to open a bank account that was used for money laundering of Rs 2.8 crore. An arrest warrant has been issued by the CBI in your name.
You are now under digital arrest. Do not disconnect the video call and keep your camera on at all times. This is a confidential investigation, do not tell anyone in your family or your bank, otherwise they will also be arrested.
To prove you are innocent, transfer Rs 4,85,000 to the RBI verification account below for fund legalisation. The amount will be refunded within 24 hours after verification.
A/c No: 50100234567812  IFSC: XYZB0001234  Name: RBI Fund Verification Cell`,
  },
