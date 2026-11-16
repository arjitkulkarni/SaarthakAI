# Demo script, 17-11-2026 (about 5 minutes)

## Before you walk in

- [ ] Open **https://satark-ai-murex.vercel.app** in a browser and check that the header pill says **"Grok online · Vercel"**.
- [ ] Open `https://satark-ai-murex.vercel.app/api/health` in a second tab. It shows `aiConfigured: true`, `platform: vercel` and `region: bom1`.
- [ ] Open the **Vercel dashboard → satark-ai** in a third tab. Show **Deployments**, **Logs** and **Settings → Environment Variables** (the key is hidden).
- [ ] Keep `docs/screenshots/sample-scam-sms.png` on your desktop for the screenshot demo.
- [ ] Backup: if Wi-Fi fails, run it locally with `npm start` from a phone hotspot. If Grok fails, the rule engine still answers.

## 1. Problem (30 s)

> "Digital arrest scams: a fake CBI or police officer keeps the victim on a video call, tells them not to inform their family, and makes them transfer money to a 'safe account'. Digital arrest does not exist in Indian law, but people still lose their life savings. My project, Satark AI, gives anyone an instant AI check before they pay."

## 2. Live demo (2.5 min)

1. Click **"Digital arrest video call"**, then **Analyse**.
   Point out: **Scam 95/100**, category **Digital arrest**, *"Pretending to be: …"*, red flags **quoted from the message** with the tactic tag (Fake authority, Isolation, Payment demand), "What to do now", the 1930 links, and the engine badge **"xAI Grok · grok-4.20 · ~5 s"**.
2. Switch the language to **ಕನ್ನಡ** or **हिन्दी** and analyse again. The explanation now appears in that language.
3. Open the **Screenshot** tab and upload `sample-scam-sms.png`. Grok's vision reads the image and finds the fake SBI KYC link.
4. Click **"Normal family message"**. It shows **Likely safe**, which proves the tool does not flag everything.
5. Click **Copy complaint draft** and paste it into Notepad. It is ready for cybercrime.gov.in.
6. Open the **Rule-engine cross-check**. Explain the two-layer design and the fallback.

## 3. Cloud and AI explanation (1.5 min, show the architecture diagram)

- **Vercel**: the dashboard is served from the Edge Network; `/api/*` runs as a **serverless function** in **bom1 (Mumbai)**, scales automatically, and is billed per request. Show Deployments and Logs (structured JSON logs).
- **xAI Grok API**: model `grok-4.20-0309-non-reasoning` (fallback `grok-4.3`). The request contains a **system prompt** (Indian scam knowledge), the **content** (text and image) and a **JSON schema** (structured output, strict mode).
- **Environment variables**: `XAI_API_KEY` is stored encrypted in Vercel, never in the code or on GitHub.
- **Rule engine** provides an instant cross-check and an offline fallback, so the service never goes down.

## 4. Close (15 s)

> "It helps people, not replaces the police. The answer always ends with 1930 and cybercrime.gov.in."

---

## Likely viva questions

| Question | Answer |
|---|---|
| Why Grok and not only keywords? | Scam scripts keep changing their wording. Grok understands context and intent, reads screenshots, explains in simple language, and replies in Hindi or Kannada. On our 8 demo messages, keywords alone rated 5 of 6 scams only "Suspicious"; Grok rated all 6 "Scam" with the right category. |
| What is structured output? | We send `response_format: { type: "json_schema", strict: true }` with our schema. Grok must return fixed fields such as verdict, risk_score and red_flags, so the UI can trust the format. The server still validates every field. |
| Why this Grok model? | `grok-4.20-0309-non-reasoning` answers in 2–6 s and supports images. The reasoning models gave the same verdicts but took 7–15 s, which is too slow for a user waiting on a scam call. |
| Why Vercel? | Serverless (no server to manage), HTTPS by default, automatic scaling, Mumbai region close to users, a global CDN for the page, and one-command deploys. |
| Where is the API key? | In Vercel **environment variables**, marked sensitive (encrypted, cannot be read back in the dashboard), provided to the function at runtime. It is not in the code or on GitHub. |
| What if Grok is down or rate-limited? | The client tries a fallback Grok model. If that fails, the rule engine answers and the UI shows a notice. |
| Is user data stored? | No. Content is analysed in memory. Logs keep only verdict, score, category and latency, never the message text. |
| Prompt injection? | The system prompt tells Grok to treat the message only as data. The output is checked against fixed enums and the score is clamped. |
| Security? | HTTPS, Content-Security-Policy and other security headers, input size and type validation, rate limiting (20 per minute per IP). |
| Vercel limits? | 4.5 MB request body (the browser compresses screenshots to JPEG) and 60 s per function call (Grok answers in seconds; the client stops retrying before 55 s). |
| How did you test it? | 19 automated tests (`npm test`): rule engine, Grok handling with a mocked API, fallback, validation, server routes and the Vercel function. Plus the 8 demo messages on the live deployment: 8 of 8 correct. |
| Cost? | Vercel's free (Hobby) plan covers the hosting. Grok costs about $1.25 per million input tokens, so one analysis costs a fraction of a rupee. |
| Future scope? | Live call-audio analysis, a WhatsApp chatbot, more languages, a browser extension, and trend dashboards for cyber cells. |
