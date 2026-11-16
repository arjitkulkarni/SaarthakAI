# Satark AI: Digital Arrest & Cyber Fraud Scam Detector

**AI-Based Digital Arrest & Cyber Fraud Scam Detection System**, built with the **Google Gemini API (Google AI Studio)** and deployed on **Google Cloud Run**.

Paste a suspicious SMS, WhatsApp message or call transcript, or upload a screenshot. Satark AI returns:

- a verdict (**Scam / Suspicious / Likely safe**) and a **risk score from 0 to 100**
- the **scam category** (digital arrest, courier/parcel, KYC, UPI, job/task, investment, and more)
- **red flags quoted from the message**, each tagged with the tactic it uses
- **what to do now / what NOT to do**, in English, Hindi or Kannada
- the **1930 / cybercrime.gov.in / Sanchar Saathi** reporting links and a one-click complaint draft

## Architecture

![Architecture](docs/architecture.png)

| Layer | What it does |
|---|---|
| **Front end** (`public/`) | White, black and yellow dashboard. Text and screenshot input (drag, drop or paste), language choice, demo examples |
| **Cloud Run service** (`server.js`) | HTTPS API `POST /api/analyze`, validation, rate limiting, security headers, structured logs |
| **Layer 1: rule engine** (`src/rules.js`) | Instant Indian scam-pattern check, indicator extraction (phone, UPI, URL, amount, account), offline fallback |
| **Layer 2: Gemini** (`src/gemini.js`) | Multimodal analysis with a system instruction and a **structured JSON response schema**, plus model fallback |
| **Secret Manager** | Holds `GEMINI_API_KEY`, which is injected into Cloud Run at runtime |

The app has **no npm dependencies**. It uses only Node.js built-ins and calls the Gemini REST API with `fetch`.

