# Demo script, 17-11-2026 (about 5 minutes)

## Before you walk in

- [ ] Open the **Cloud Run URL** in Chrome and check that the header pill says **"Gemini online · Cloud Run"**.
- [ ] Open `<url>/api/health` in a second tab (it shows `geminiConfigured: true` and the revision).
- [ ] Open **Google Cloud Console → Cloud Run → satark-ai** in a third tab (shows Metrics and Logs).
- [ ] Keep a screenshot of a scam SMS on your desktop for the screenshot demo. You can screenshot the KYC demo text, for example.
- [ ] Backup: if Wi-Fi fails, run it locally with `npm start` from a phone hotspot. If Gemini fails, the rule engine still answers.

## 1. Problem (30 s)

> "Digital arrest scams: a fake CBI or police officer keeps the victim on a video call, tells them not to inform their family, and makes them transfer money to a 'safe account'. Digital arrest does not exist in Indian law, but people still lose their life savings. My project, Satark AI, gives anyone an instant AI check before they pay."

## 2. Live demo (2.5 min)

1. Click **"Digital arrest video call"**, then **Analyse**.
   Point out: **Scam** verdict, risk gauge, category **Digital arrest**, *"Pretending to be: …"*, red flags **quoted from the message** with the tactic tag (Fake authority, Isolation, Payment demand), "What to do now", and the 1930 links.
2. Switch the language to **ಕನ್ನಡ** or **हिन्दी** and analyse again. The explanation now appears in that language.
3. Open the **Screenshot** tab and upload or paste a scam screenshot. Gemini reads the image (multimodal).
4. Click **"Normal family message"**. It shows **Likely safe**, which proves the tool does not flag everything.
5. Click **Copy complaint draft** and paste it into Notepad. It is ready for cybercrime.gov.in.
6. Open the **Rule-engine cross-check**. Explain the two-layer design and the fallback.

## 3. Cloud and AI explanation (1.5 min, show the architecture slide or diagram)

- **Google Cloud Run**: serverless container, HTTPS URL, autoscaling from 0 to 3, Mumbai region. Show the Cloud Run console metrics and logs (structured JSON logs).
- **Google Gemini API (AI Studio key)**: model `gemini-3.8-flash`; the request contains a **system instruction** (Indian scam knowledge), the **content** (text and image) and a **response schema** (structured JSON output).
- **Secret Manager** stores the API key, so it never appears in the code.
- **Rule engine** provides an instant cross-check and an offline fallback, so the service never goes down.

## 4. Close (15 s)

> "It helps people, not replaces the police. The answer always ends with 1930 and cybercrime.gov.in."

---

## Likely viva questions

| Question | Answer |
|---|---|
| Why Gemini and not only keywords? | Scam scripts keep changing their wording. Gemini understands context and intent, reads screenshots, explains in simple language, and replies in Hindi or Kannada. Keywords alone rate most scams only "Suspicious". |
| What is structured output? | We send a JSON **response schema** (`responseMimeType: application/json`). Gemini must return fixed fields such as verdict, risk_score and red_flags, so the UI can trust the format. The server still validates every field. |
| Why Cloud Run? | Serverless (no VM to manage), HTTPS by default, autoscaling, scales to zero (pay per request), deploys straight from source with a Dockerfile. |
| Where is the API key? | In **Secret Manager**, injected as the `GEMINI_API_KEY` environment variable at runtime. It is not in the code or the image. |
| What if Gemini is down or rate-limited? | The client tries fallback models. If all fail, the rule engine answers and the UI shows a notice. |
| Is user data stored? | No. Content is analysed in memory. Logs keep only verdict, score, category and latency, never the message text. |
| Prompt injection? | The system instruction tells Gemini to treat the message only as data. The output is checked against fixed enums and the score is clamped. |
| Security? | HTTPS, Content-Security-Policy and other security headers, input size and type validation, rate limiting (20 per minute per IP), non-root container user. |
| How did you test it? | 15 automated tests (`npm test`): rule engine, Gemini handling with a mocked API, fallback, validation and server routes. Plus 8 demo messages: 6 scams and 2 genuine. |
| Cost? | Gemini Flash has a free tier in AI Studio. Cloud Run has a free tier and scales to zero, so a demo costs about ₹0. |
| Future scope? | Live call-audio analysis, a WhatsApp chatbot, more languages, a browser extension, and trend dashboards for cyber cells. |
