# ZeroDay-Guard AI — Demo Video Shot List (2–3 min)

Record with **Loom** (free, gives a shareable link instantly) or **OBS** (local file → upload
to YouTube as *unlisted*). 1080p. Notifications off. Zoom in on small text.

## ⚠️ Before you hit record

- [ ] Backend running (`uvicorn app.main:app`) and the dashboard shows **"backend online"**
- [ ] Run the target **once** end-to-end and confirm the verdict is sensible
- [ ] The scan takes **2–3 minutes**. That's the *point* — the agent is doing real work on the
      live web. But it means you should **start the scan, then talk over it**, not wait in silence.
- [ ] Close every other tab. Open the source advisory in a second tab for the "real page" moment
- [ ] Have the README architecture diagram open in a third tab for the explainer shot

### Best target for the demo

```
https://nvd.nist.gov/vuln/detail/CVE-2021-44228
```

Log4Shell. It is the most-recognised CVE in the world, it has a public PoC and an upstream
patch, so every panel of the UI lights up: real CVE ID, real description, real patch diff, and
the Log4j/JNDI remediation rule fires.

---

## The script

### 0:00–0:20 — Hook
**Screen:** dark dashboard, target bar empty
**Say:** "A new CVE drops. How long before anyone knows if it's exploitable? For most teams:
hours. That's the gap this closes."

### 0:20–0:35 — What it is
**Screen:** you, or a clean title card — **ZeroDay-Guard AI**
**Say:** "This is an autonomous threat assessor. Give it a URL. It browses the target with an AI
web agent, harvests real exploit intelligence, scores it with a static analyser, and hands you
a patch."

### 0:35–1:50 — ⭐ Main demo (the most important 75 seconds)
**Screen:** app only, cursor visible. **Click "Initiate Scan" and talk over the running scan.**

Watch the **left terminal** fill up in real time. Point out the actual agent reasoning:

> "Navigating to the NVD page…"
> "Visit CVE-2021-44228 NVD page"
> "Get CVE-2021-44228 details from NVD page"
> "Expand CVE change history"

**Say:** "It's not a scraper. It's an AI browser agent — TinyFish — deciding what to click, what
to expand and what to read, and streaming its plan to us as it works."

Then the right-hand panel lands: **risk dial, radar chart, findings, patch**.

**Say:** "CodeBERT embeddings and a real AST analyser score the harvested code, and the
vulnerability class maps to a concrete patch."

### 1:50–2:10 — ⭐ The "this is real" moment
**Screen:** the findings list, with the evidence quote
**Say:** "That's the real advisory text, harvested from the live page — not generated."
*(Optional: switch to the NVD tab and Ctrl+F the quoted sentence.)*

### 2:10–2:30 — The patch
**Screen:** scroll to the Remediation Patch panel
**Say:** "It doesn't just say 'this is dangerous'. It gives you the fix — upgrade Log4j to
2.17.1, disable JNDI lookups — with the exact diff, and steps to hunt for exploitation."

### 2:30–2:50 — Architecture + honesty
**Screen:** README architecture diagram
**Say:** "Four TinyFish surfaces do the work: the Agent API drives the browser, Search finds the
advisories, Fetch renders the pages, Research reasons over the result. And it degrades
gracefully — if the agent is slow, Search and Fetch carry the scan on their own."

### 2:50–3:00 — Close
**Screen:** repo URL
**Say:** "Open source at github.com/abhiraj-ops/Zeroday. Point it at a target and watch
it work."

---

## Recording tips

- **Start the scan first, then talk.** The agent takes a minute or two — use that time.
- One clean take per section, then stitch. You will not nail 3 minutes in one go.
- Speak ~20% slower than feels natural.
- The terminal is the star — make sure the text is readable on the recording.
- **Total runtime target: 2:30.**

## After recording

- [ ] Watch it end-to-end **once**, sound on
- [ ] Upload → YouTube *unlisted* or Loom
- [ ] Play the shared link in an incognito window to confirm it works
