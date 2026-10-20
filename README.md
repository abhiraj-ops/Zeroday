# ZeroDay-Guard AI

> **Autonomous cybersecurity threat assessor.** Point it at a URL, and it crawls the live web
> with an AI browser agent, harvests real exploit intelligence, scores it with CodeBERT + AST
> static analysis, and hands you a risk verdict **and a working patch**.

```
Target URL  ──▶  TinyFish Web Agent  ──▶  CodeBERT + AST  ──▶  Risk Verdict + Diff
                (search · fetch · browse)   (semantic + static)    (streamed live)
```

**Live:** <https://zeroday-guard-ai.netlify.app> — a scan takes about 30 seconds and
returns a full assessment with findings and a remediation patch.

---

## 🖥 The interface

The dashboard is a **workbench**, not a landing page: a persistent shell around a single
scan, because an analyst's loop is *scan → read → act → compare*, and every step should
keep the previous result in view.

| Area | What it does |
|---|---|
| **Sidebar** | Workspace switcher, view navigation, the last six runs with their verdict, live engine status, account menu |
| **Top bar** | Breadcrumbs, global search (`⌘K`), engine heartbeat, primary action |
| **Target composer** | Labelled URL field with optional CVE ID and focus, inline validation, `⌘↵` to run |
| **Assessment** | Risk score on a labelled 0–100 scale, six-dimension risk vector, risk drivers, executive summary, findings |
| **Findings** | One row per vulnerability, expandable to show the evidence quote, code snippet and source link |
| **Remediation** | The generated diff with `+`/`−` counts, plus the manual steps and upstream references |
| **Run log** | Every pipeline stage, timestamped and level-filtered — the agent's trace, read as a log |
| **History** | Scans run from this browser, with target, verdict, finding count and timing |

### Design decisions

- **One accent, used sparingly.** `#1D4ED8` marks primary actions and active state only.
  Severity has its own muted ramp (`#B42318` → `#0369A1`) so a CRITICAL finding never
  competes with the interface chrome.
- **Warm neutrals, hairline separation.** A `#F5F5F3` canvas, white surfaces and 1px
  `#E4E4E1` borders. Depth comes from `0 1px 2px` shadows, not from blur or glow.
- **Two typefaces with a rule.** Inter for everything a human reads, IBM Plex Mono for
  anything a machine wrote — URLs, CVEs, diffs, timestamps.
- **Bars, not radar polygons.** The six risk dimensions are labelled horizontal meters with
  printed values, so two dimensions can be compared without decoding an angle.
- **Honest labelling.** `Patch availability` measures fix *coverage* rather than risk, and
  the panel says so instead of colour-coding it like a risk axis.

### Keyboard

| Shortcut | Action |
|---|---|
| `⌘K` | Command palette — views, actions and recent runs |
| `⌘↵` | Run a scan on the current target |
| `/` | Focus the target URL field |
| `↑` `↓` `↵` | Move through and run palette results |
| `?` | Shortcut reference |

---

## 💻 Run it locally

The serverless tier runs as one Next.js app, so local development is two commands.

```bash
# 1. the app (dashboard + API + job store)
cd frontend
npm install
npm run dev            # http://localhost:3000
```

Without a key it runs in **demo mode** and serves simulated intelligence, which is
enough to exercise the whole interface. To get the live agent, add your key:

```bash
# frontend/.env.local   (gitignored - never commit the real key)
TINYFISH_API_KEY=sk-tinyfish-…
```

Then `npm run dev` picks it up on the next start. `GET /api/v1/health` reports
`demo_mode` and `tinyfish_configured` so you can confirm at a glance which mode
you are in.

The self-hosted Python tier runs separately:

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env    # then fill in TINYFISH_API_KEY
uvicorn app.main:app --reload --port 8000
```

```bash
# the offline test suite - no network, no key
cd backend && python -m pytest tests -q
```

---

## 🚀 Deploy to Netlify (one click, this is the live site)

The whole product — dashboard **and** API — is one Next.js app, so it deploys as a single unit.
There is no second backend to run and no CORS to configure.

### 1. Connect the repo to Netlify

1. Go to <https://app.netlify.com> → **Add new site** → **Import an existing project**
2. Choose **abhiraj-ops/Zeroday**
3. Netlify reads `netlify.toml` automatically:
   - Build command: `npm run build`
   - Publish directory: `.next`
   - Base directory: `frontend`
4. Click **Deploy site**

### 2. Add your TinyFish key (required — without it the app runs in demo mode)

**Site configuration → Environment variables → Add:**

| Key | Value |
|---|---|
| `TINYFISH_API_KEY` | `sk-tinyfish-…` (from <https://agent.tinyfish.ai/api-keys>) |

Then **Deploy site → Trigger deploy → Clear cache and deploy site**.

#### Optional: the scan budgets

The whole scan runs inside one function invocation, so it has to fit the platform's
wall-clock ceiling. Two phases are slow — the browser agent and the reasoning pass —
and both are time-boxed:

| Key | Default | What it covers |
|---|---|---|
| `AGENT_TIME_BUDGET_MS` | `12000` | How long the TinyFish browser agent may run before the pipeline falls back to Search + Fetch |
| `RESEARCH_TIME_BUDGET_MS` | `15000` | How long the TinyFish Research synthesis may run before the deterministic template is used |

Search, Fetch and NVD enrichment together take about five seconds, so a scan completes
in roughly 30 seconds. Raise these on a platform with a longer ceiling — the
self-hosted Python tier has no such limit and can afford a 90-second agent budget.

### 3. Done

Your site is live at `https://<your-site>.netlify.app`. The dashboard, the scanning API and the
job store all run inside that one deploy.

> **No database, no queue, no third-party service.** Job state lives in Netlify Blobs, which is
> included on every plan.

### Deploying manually instead

```bash
npm i -g netlify-cli
cd frontend && npm run build
netlify deploy --prod --dir .next
```

---

## 🧱 Two tiers, one product

| | **Netlify tier** (the live site) | **Self-hosted tier** (full ML) |
|---|---|---|
| Runtime | Next.js 15 on Netlify Functions | Python 3.12 · FastAPI · Uvicorn |
| Static analysis | Pattern analysis (all languages) | **`ast` module** for true Python AST analysis |
| CodeBERT | ✗ (torch cannot run serverless) | ✓ `microsoft/codebert-base` embeddings |
| Run it | `netlify deploy` | `docker compose up --build` |
| Best for | the demo, judges, the live link | the finale, deeper analysis |

Both tiers run **the same pipeline** and produce the same kind of assessment. The Python tier is
the reference implementation and adds the CodeBERT embedding engine; the TypeScript tier is the
port that makes a one-click deploy possible.

---

## 🎯 What it actually does

1. **Autonomous reconnaissance** — hands TinyFish a natural-language goal ("find the advisory,
   the PoC, the affected versions and the patch"), and the agent drives a real cloud browser:
   dismisses cookie banners, expands collapsed sections, follows links, extracts.
2. **Intelligence harvesting** — pulls CVE IDs, affected versions, proof-of-concept code blocks
   and upstream patch diffs out of advisories, issue threads and release notes.
3. **ML risk scoring** — fuses CodeBERT contextual embeddings with a real AST/pattern static
   analyser into a normalised 0–100 risk score and a six-dimension risk vector.
4. **Reasoning + remediation** — synthesises an executive assessment and generates a concrete
   unified diff for the vulnerability class it found.

Every step streams to the dashboard over SSE, so you watch the agent work.

---

## 🐟 TinyFish integration (the core of this project)

TinyFish is **load-bearing**, not a mention. Four of its five API surfaces are used:

| Surface | Endpoint | How ZeroDay-Guard uses it | Cost |
|---|---|---|---|
| **Agent** | `POST agent.tinyfish.ai/v1/automation/run-sse` | Goal-driven browsing: navigates the target, dismisses modals, follows links, returns structured JSON validated against an `output_schema` | $0.016 / step |
| **Search** | `GET api.search.tinyfish.ai` | Discovers candidate advisory / PoC / release-note URLs for a target | **$0** |
| **Fetch** | `POST api.fetch.tinyfish.ai` | Renders JavaScript pages, extracts PDFs, pulls raw code blocks and diffs | **$0** |
| **Research** | `POST agent.tinyfish.ai/v1/automation/run-research` | Reasoning backend — source-backed synthesis when no OpenAI/Anthropic key is configured | **$0** |

*(Unit prices taken from the live `GET /v1/wallet` response on our own account.)*

### The agent call

```python
async with client.stream("POST", f"{BASE}/v1/automation/run-sse", json={
    "url": target_url,
    "goal": CRAWL_GOAL,
    "output_schema": CRAWL_OUTPUT_SCHEMA,   # guarantees typed fields
}) as response:
    async for line in response.aiter_lines():
        ...
```

### One integration detail worth documenting

TinyFish signals the event type **inside the JSON body** (`{"type": "COMPLETE", "result": {...}}`),
not as an SSE `event:` name. Parsing only the SSE event name silently discards every result and
makes a working agent look broken. `backend/app/services/tinyfish_agent.py` reads the body first
and only falls back to the SSE name.

### Graceful degradation — the agent is a bonus, not a dependency

The Agent API costs money per step and can be slow. Search + Fetch are free and always work, so
the scan **always completes with real live-web data**:

```
        ┌── Agent API ──────────────────┐   (time-boxed)
        │  drives a real cloud browser  │
        └──────────────┬────────────────┘
                       │  runs CONCURRENTLY with the fallback
        ┌──────────────┴────────────────┐
        │  Search  →  discover URLs      │
        │  Fetch   →  render + extract   │
        │  parse   →  CVSS / CWE /       │
        │             affected versions  │
        └──────────────┬────────────────┘
                       ▼
              full assessment
```

Three details that make the fallback a **first-class** path rather than a degraded one:

- **It runs concurrently with the agent.** The fallback is gathered in the background while the
  agent browses, so an agent timeout costs *no extra wall-clock time*. Total scan time is
  `max(agent, fetch)`, not `agent + fetch`.
- **It extracts vulnerability records, not just CVE IDs.** The raw advisory pages carry a CVSS
  score and severity, a CWE identifier, affected version ranges, a description and a verbatim
  evidence quote — all parsed out of the fetched markdown. Without this, an agent timeout
  silently produced a `0/100 "nothing found"` assessment even though the pages clearly
  described the vulnerability.
- **The agent path is capped by `AGENT_TIME_BUDGET`** (default 120 s). When the budget is
  exceeded we abandon the agent rather than stalling a live demo.

**A scan never returns empty.**

### Why there is an NVD enrichment step

Scraping advisory HTML turned out to be **inherently brittle**: the same page renders
differently between fetches, so a regex matching a CVSS score on one run matched a table of
contents on the next. Two consecutive runs of the same target disagreed on severity, CWE and even
the final risk score.

The fix is to stop asking HTML for structured facts. The **NVD JSON API** returns the same
severity, CVSS base score, CWE and affected-version ranges every time, so it is used to
*enrich* whatever the crawl discovered:

```python
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
→ severity: CRITICAL   baseScore: 10.0   cwe: CWE-20
  affected: "2.0.1 through 2.3.1; 2.4.0 through 2.12.2; 2.13.0 through 2.15.0; ..."
```

This is **enrichment, not replacement**. TinyFish still does the discovery and the context — the
agent browses the target, Search finds the advisories and PoC pages, Fetch pulls the code blocks
and diffs. The NVD record supplies the authoritative fields that HTML scraping cannot promise.
Findings are merged by CVE identity, most authoritative first, so a CVE named in the target URL
wins.

---

## 🧠 ML & AI layer

### CodeBERT (`microsoft/codebert-base`)

Loaded **lazily** — the service boots instantly and works without it.

CodeBERT is a masked language model, not a classifier, and we have no labelled CVE corpus to
fine-tune on. So we use it the way that is actually defensible: **embedding-similarity
classification**. Mean-pooled contextual embeddings of the snippet are compared, by cosine
similarity, against a curated set of *vulnerable* and *safe* exemplars:

```python
vuln_sim = max(cosine(embed(snippet), embed(e)) for e in VULNERABLE_EXEMPLARS)
safe_sim = max(cosine(embed(snippet), embed(e)) for e in SAFE_EXEMPLARS)
semantic_risk = clamp(0.5 + (vuln_sim - safe_sim) * 1.6)
```

The AST findings and the semantic signal are then fused:

```
risk_score = 0.78 × ast_score + 0.22 × (semantic_risk × 100)
```

> **Stated plainly, because it matters for the judging:** this is embedding similarity, *not* a
> fine-tuned classifier. The `engine` field in every response tells you which produced the score
> — `codebert+ast` or `ast`. The AST engine does the heavy lifting; CodeBERT is a second opinion.
>
> **CodeBERT runs on the self-hosted tier only.** A serverless function cannot load torch, so the
> Netlify tier reports `engine: ast` and uses the pattern analyser on its own. The API always
> tells you which produced the score, so nothing is overstated.

### AST / pattern static analyser

The fallback is not a toy — it is real static analysis.

- **Python** is parsed with the stdlib `ast` module, so it understands structure: `eval`/`exec`
  sinks, `pickle.loads` and unsafe `yaml.load` deserialisation, `subprocess(..., shell=True)`,
  SQL built by string concatenation, `md5`/`sha1`, `random` used for tokens, `verify=False`,
  hardcoded credentials, `assert` used as validation, swallowed exceptions, `mktemp` races.
- **C / C++ / Java / JavaScript** use a curated pattern table: `strcpy`/`strcat`/`sprintf`/
  `gets` buffer overflows, `system()`, `eval`/`new Function`, `innerHTML`/`dangerouslySetInnerHTML`
  XSS, `child_process.exec`, `Runtime.getRuntime().exec`, `ObjectInputStream`, `Class.forName`,
  MD5/SHA-1, disabled TLS verification.

Every finding carries a **CWE identifier** and is mapped to one of six analysis dimensions
(`code_injection`, `memory_safety`, `input_validation`, `crypto_weakness`, `auth_bypass`,
`data_exposure`).

### Reasoning engine chain

The narrative never hard-fails, because there is always a next engine:

```
OpenAI (GPT-4o)  ──▶  Anthropic (Claude)  ──▶  TinyFish Research  ──▶  deterministic template
```

The template is not a stub — it composes the executive summary from the harvested findings and
always produces a real remediation diff from the patch rulebook.

---

## 🩹 Patch generation

A **rulebook**, not a language model: each vulnerability class maps to a concrete before/after
unified diff with remediation steps.

| Detected | Generated fix |
|---|---|
| JNDI / Log4j | Upgrade to Log4j 2.17.1+ and set `log4j2.formatMsgNoLookups=true` |
| `pickle.loads` | Replace with `json.loads` (no code-execution semantics) |
| `yaml.load` | Switch to `yaml.safe_load` |
| `shell=True` | Argument list, `shell=False` |
| SQL concatenation | Parameter binding (`%s` + tuple) |
| `eval` / `exec` | `ast.literal_eval` or a dispatch table |
| `strcpy` / `sprintf` | `snprintf` with `sizeof` |
| `innerHTML` | `textContent` |
| MD5 / SHA-1 | SHA-256, and a slow KDF for passwords |
| `verify=False` | `verify=True` |
| Hardcoded secret | Environment variable + rotate the credential |
| `random` for tokens | `secrets.token_urlsafe(32)` |

If a real upstream diff was harvested from the advisory, **that vendor diff is preferred** and
shown as-is. If nothing matches, the tool says so rather than inventing a patch — an unverified
diff is worse than no diff.

---

## 🖥️ Architecture

```
        NETLIFY TIER — the live site (one deploy)          SELF-HOSTED TIER — full ML
┌───────────────────────────────┐                 ┌───────────────────────────────┐
│  Next.js 15 on Netlify       │                 │  Next.js 15 dashboard         │
│                               │                 │        │  SSE                  │
│  ┌─────────────────────────┐  │                 │        ▼                      │
│  │ /api/v1/scan  (POST)    │  │                 │  FastAPI (asyncio)            │
│  │   create job → after()  │  │                 │   ┌──────────────────────┐   │
│  └───────────┬─────────────┘  │                 │   │ TinyFishWebAgent     │   │
│              │                │                 │   │ CodeBETAstScanner    │   │
│  ┌───────────▼─────────────┐  │                 │   │ LLMOrchestrator      │   │
│  │ /api/v1/scan/{id} (GET) │  │                 │   └──────────────────────┘   │
│  │   events[] + assessment │  │                 └───────────────────────────────┘
│  └─────────────────────────┘  │
│                               │                 ┌───────────────────────────────┐
│  job state → Netlify Blobs   │                 │  torch + transformers         │
│  ┌─────────────────────────┐  │                 │  microsoft/codebert-base      │
│  │ src/lib/zeroday/       │  │                 │  (2.5GB, local only)          │
│  │  tinyfish · nvd         │  │                 └───────────────────────────────┘
│  │  scanner · scoring      │  │
│  │  pipeline · store       │  │
│  └─────────────────────────┘  │
└───────────────────────────────┘
```

**Backend** — FastAPI, asyncio, Pydantic v2, Uvicorn (self-hosted tier).
**Pipeline core** — TypeScript in `frontend/src/lib/zeroday/`, so the Netlify tier needs no
Python runtime. The Python services are the reference implementation of the same pipeline.
**ML** — HuggingFace Transformers + PyTorch (`microsoft/codebert-base`) and the stdlib `ast`
module, on the self-hosted tier; pattern-based static analysis on the serverless tier.
**Agent** — TinyFish Search, Fetch, Agent and Research APIs.

---

## 🛠️ Tech

**Netlify tier** — Next.js 15 (App Router) · TypeScript (strict, zero `any`) · Tailwind CSS 3 ·
Lucide · Framer Motion · Netlify Functions + Blobs · TinyFish Search / Fetch / Agent / Research.

**Self-hosted tier** — Python 3.12 · FastAPI · asyncio · Pydantic v2 · Uvicorn · httpx ·
HuggingFace Transformers + PyTorch (`microsoft/codebert-base`) · stdlib `ast`.

---

## 🚀 Quick start

### Option A — Netlify (the live site, recommended)

See **Deploy to Netlify** above. Three steps: import the repo, add `TINYFISH_API_KEY`, deploy.

To run it locally in the same mode:

```bash
cd frontend
npm install
cp .env.example .env.local      # add your TINYFISH_API_KEY
npm run dev                     # http://localhost:3000
```

### Option B — the self-hosted Python tier (full ML, local)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                    # then add your TinyFish key
python -m uvicorn app.main:app --reload --port 8000
```

API docs: <http://localhost:8000/docs>

> **Optional — enable the full CodeBERT engine** (downloads ~2.5 GB of torch):
> ```bash
> pip install -r requirements-ml.txt
> # smaller, CPU-only torch:
> pip install torch --index-url https://download.pytorch.org/whl/cpu
> ```
> Without it the service still works; `engine` simply reports `ast`.

### Or run the whole stack with Docker

```bash
cp backend/.env.example backend/.env     # add your TINYFISH_API_KEY
docker compose up --build
```

Backend on `:8000`, frontend on `:3000`.

### CI

`ci/ci.yml` runs the backend unit tests, the frontend build and type check, and a **secret scan**
that fails the build if a TinyFish API key is ever committed. To enable it:

```bash
mkdir -p .github/workflows && cp ci/ci.yml .github/workflows/ci.yml
```

(It lives in `ci/` because creating workflow files through the API needs a token with the
`workflow` scope.)

### Tests

```bash
cd backend
python -m unittest discover -s tests -v      # offline, 22 tests
python smoke_test.py "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"   # live end-to-end

cd ../frontend
./scripts/test-scan.ps1                      # live end-to-end of the job flow
```

---

## 🔑 Configuration

### Netlify tier (the live site)

| Variable | Required | Purpose |
|---|---|---|
| `TINYFISH_API_KEY` | ✅ **yes** | The TinyFish key. Without it the app runs in demo mode with simulated intelligence |
| `NEXT_PUBLIC_API_URL` | — | Only if the API is hosted separately. Unset = same origin, which is what a single deploy needs |

That is the whole list. No database URL, no queue, no third-party service — job state lives in
Netlify Blobs.

### Self-hosted tier (Python)

| Variable | Default | Purpose |
|---|---|---|
| `TINYFISH_API_KEY` | `demo` | **Required for live scans.** `demo` serves simulated intelligence with no network calls |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | — / `gpt-4o` | First choice for the narrative engine |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | — / `claude-3-5-sonnet-latest` | Second choice |
| `ENABLE_CODEBERT` | `true` | Set `false` to skip the model download entirely |
| `CODEBERT_MODEL` | `microsoft/codebert-base` | Any HuggingFace encoder checkpoint |
| `AGENT_TIME_BUDGET` | `120` | Seconds before abandoning the agent path |
| `RESEARCH_TIME_BUDGET` | `45` | Seconds before abandoning the Research stage |
| `CORS_ORIGINS` | `http://localhost:3000,…` | Comma-separated allowed origins |

Get a TinyFish key at <https://agent.tinyfish.ai/api-keys>.

> **Tip:** TinyFish runs a student program with wallet credit and office hours —
> see <https://www.tinyfish.ai/students>.

---

## 🔌 API

### Netlify tier (the live site) — job-based

A scan takes 75–130 seconds, which is longer than a synchronous serverless function can run, so
the API is job-based. The scan continues in the background after the response is sent
(`next/server` `after()`), and the client polls for progress.

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service status and effective config (no secrets) |
| `POST` | `/api/v1/scan` | Body `{ target_url }` → `{ jobId, status }` immediately |
| `GET` | `/api/v1/scan/{jobId}` | `{ status, events[], assessment, error }` |

The dashboard polls every 1.2 s and appends only the events it has not seen, so the run log
fills up live exactly as it would with SSE. Event writes are serialised server-side, so the
final trace line can never be lost to a write race with the `done` status update.

```bash
# create a job
curl -X POST https://<site>.netlify.app/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}'
# -> {"jobId":"b077e1f3-…","status":"queued"}

# poll it
curl https://<site>.netlify.app/api/v1/scan/b077e1f3-…
# -> {"status":"done","events":[…],"assessment":{…}}
```

### Self-hosted tier (Python) — streaming

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service status and effective config (no secrets) |
| `POST` | `/api/v1/scan` | Full scan → `{ assessment, events, elapsed_seconds }` |
| `GET` | `/api/v1/scan/stream?target_url=…` | **SSE** live agent trace + final assessment |
| `POST` | `/api/v1/scan/stream` | Same stream, POST body (for long URLs) |
| `GET` | `/api/v1/sample` | A ready-made target for a fast demo |

---

## 📁 Project structure

```
netlify.toml                     # Netlify build config (base: frontend)
docker-compose.yml               # runs the Python tier locally

backend/                         # ── self-hosted tier (Python, full ML) ──
├── app/
│   ├── main.py                       # FastAPI app, CORS, SSE endpoints
│   ├── config.py                     # env loader (+ BOM-safe .env parser)
│   ├── models/schemas.py             # Pydantic v2 request/response schemas
│   └── services/
│       ├── tinyfish_agent.py         # Agent + Search + Fetch integration
│       ├── ml_evaluator.py           # CodeBERT embeddings + AST scanner
│       └── llm_orchestrator.py       # reasoning chain + patch rulebook
├── requirements.txt                  # core runtime
├── requirements-ml.txt               # optional torch + transformers
├── .env.example
├── tests/                            # 22 offline unit tests
└── smoke_test.py                     # end-to-end test against the live API

frontend/                        # ── Netlify tier (the live site) ──
├── src/app/
│   ├── page.tsx                      # thin server wrapper -> <Workbench/>
│   ├── layout.tsx  globals.css       # fonts + design tokens
│   └── api/v1/
│       ├── health/route.ts           # service status
│       ├── scan/route.ts             # POST -> create job, run in background
│       └── scan/[jobId]/route.ts     # GET  -> job status + event trace
├── src/components/
│   ├── shell/                        # app chrome
│   │   ├── Sidebar.tsx               # nav, recent runs, engine status
│   │   ├── TopBar.tsx                # breadcrumbs, command trigger, health
│   │   ├── CommandPalette.tsx        # ⌘K palette (views, actions, runs)
│   │   └── ShortcutsDialog.tsx       # ? key reference
│   ├── ui/                           # primitives: Panel, Button, Badge, Kbd, Meter
│   └── workbench/
│       ├── Workbench.tsx             # client app: state, polling, shortcuts
│       ├── TargetComposer.tsx        # scan form (⌘↵ to run)
│       ├── ActivityLog.tsx           # levelled, filterable pipeline trace
│       ├── RiskSummary.tsx           # score, scale, six-dimension risk vector
│       ├── ExecutiveSummary.tsx      # reasoning-engine narrative + signals
│       ├── FindingsTable.tsx         # findings with expandable evidence
│       ├── PatchPanel.tsx            # diff / steps / references tabs
│       └── HistoryTable.tsx          # scans run from this browser
├── src/lib/
│   ├── types.ts                      # shared types + severity tokens
│   ├── format.ts                     # relative time, durations, URL helpers
│   ├── scans.ts                      # localStorage-backed scan history
│   ├── views.ts                      # view registry
│   └── zeroday/
│       ├── tinyfish.ts               # Search + Fetch + Agent + Research clients
│       ├── nvd.ts                    # authoritative CVE enrichment
│       ├── scanner.ts                # static analysis (pattern rules)
│       ├── scoring.ts                # verdict engine + patch rulebook
│       ├── pipeline.ts               # orchestration
│       └── store.ts                  # job store (Netlify Blobs + memory)
└── scripts/test-scan.ps1             # end-to-end test of the job flow
```

---

## ⚠️ Honest limitations

- **CodeBERT is embedding similarity, not a trained classifier.** The AST engine carries the
  analysis; CodeBERT is a second opinion. The `engine` field always tells you which ran. On the
  Netlify tier CodeBERT cannot run at all (no torch in a serverless function), so the response
  says `engine: ast` — the API never overstates what produced a score.
- **The Netlify tier uses pattern analysis; the Python tier uses full AST analysis** for Python
  source. Same rule set, same CWEs, but only the Python tier understands Python structure.
- **The agent path costs money per step** and is bounded by a time budget. Search + Fetch are
  free and carry the scan when the agent is unavailable.
- **CWE coverage is a curated rule set**, not an exhaustive static analyser. It targets the
  high-signal classes (injection, deserialisation, buffer overflow, weak crypto, hardcoded
  secrets) and misses language-specific frameworks.
- **Exploit maturity is inferred** from the presence of public PoC code, not validated by
  executing anything. **This tool never executes the code it finds.** It reads and analyses.
- **Authorisation matters.** Only scan targets you are permitted to assess. It does not attempt
  exploitation, but automated browsing of a target is still traffic against that target.

---

## 💰 Cost & pricing

Live unit prices from the TinyFish wallet API:

| Surface | Unit price |
|---|---|
| Search | **$0** / request |
| Fetch | **$0** / URL |
| Research | **$0** / run |
| Agent | $0.016 / step |
| Browser | $0.002 / minute |

A typical scan is ~10 agent steps (~$0.16) plus free search/fetch. That underpins the pricing:
**$29/month** for an individual analyst, **$199/month** for a team with API access, **$0.40 per
scan** for API-only usage — a security consultant's hour is $100+.

---

## 📄 License

MIT — see [LICENSE](./LICENSE).

---

<sub>Built for KRITICAL HACKS '26 · TinyFish Agent + Search + Fetch + Research · CodeBERT + AST ·
FastAPI · Next.js</sub>
