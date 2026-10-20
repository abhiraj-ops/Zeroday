# ZeroDay-Guard AI

> **Autonomous cybersecurity threat assessor.** Point it at a URL, and it crawls the live web
> with an AI browser agent, harvests real exploit intelligence, scores it with CodeBERT + AST
> static analysis, and hands you a risk verdict **and a working patch**.

[![Live](https://img.shields.io/badge/live-zeroday--guard--ai.netlify.app-1D4ED8?style=flat-square)](https://zeroday-guard-ai.netlify.app)
[![CI](https://github.com/abhiraj-ops/Zeroday/actions/workflows/ci.yml/badge.svg)](https://github.com/abhiraj-ops/Zeroday/actions/workflows/ci.yml)
[![Deploy](https://github.com/abhiraj-ops/Zeroday/actions/workflows/deploy.yml/badge.svg)](https://github.com/abhiraj-ops/Zeroday/actions/workflows/deploy.yml)
[![License](https://img.shields.io/badge/license-MIT-1D4ED8?style=flat-square)](./LICENSE)

```
Target URL  -->  TinyFish Web Agent  -->  CodeBERT + AST  -->  Risk Verdict + Diff
                (search . fetch . browse)  (semantic + static)  (streamed live)
```

**Live:** <https://zeroday-guard-ai.netlify.app> - a scan takes about 30 seconds and returns a
full assessment with findings and a remediation patch. Push to `main` and it redeploys itself.

**Demo:** [`docs/demo.mp4`](docs/demo.mp4) - 1 min 32 sec, recorded against the live site with a
real scan running against the real NVD page for CVE-2021-44228. Nothing in it is staged.

---

## What it does

1. **Autonomous reconnaissance** - hands TinyFish a natural-language goal ("find the advisory,
   the PoC, the affected versions and the patch"), and the agent drives a real cloud browser:
   dismisses cookie banners, expands collapsed sections, follows links, extracts.
2. **Intelligence harvesting** - pulls CVE IDs, affected versions, proof-of-concept code blocks
   and upstream patch diffs out of advisories, issue threads and release notes.
3. **ML risk scoring** - fuses CodeBERT contextual embeddings with a real AST/pattern static
   analyser into a normalised 0-100 risk score and a six-dimension risk vector.
4. **Reasoning + remediation** - synthesises an executive assessment and generates a concrete
   unified diff for the vulnerability class it found.

Every step streams to the dashboard, so you watch the agent work.

---

## The interface

The dashboard is a **workbench**, not a landing page: a persistent shell around a single scan,
because an analyst's loop is *scan -> read -> act -> compare*, and every step should keep the
previous result in view.

| Area | What it does |
|---|---|
| **Sidebar** | Workspace switcher, view navigation, the last six runs with their verdict, live engine status, account menu |
| **Top bar** | Breadcrumbs, global search (`⌘K`), engine heartbeat, primary action |
| **Target composer** | Labelled URL field with optional CVE ID and focus, inline validation, `⌘↵` to run |
| **Assessment** | Risk score on a labelled 0-100 scale, six-dimension risk vector, risk drivers, executive summary, findings |
| **Findings** | One row per vulnerability, expandable to show the evidence quote, code snippet and source link |
| **Remediation** | The generated diff with `+`/`-` counts, plus the manual steps and upstream references |
| **Run log** | Every pipeline stage, timestamped and level-filtered - the agent's trace, read as a log |
| **History** | Scans run from this browser, with target, verdict, finding count and timing |

### Design decisions

- **One accent, used sparingly.** `#1D4ED8` marks primary actions and active state only.
  Severity has its own muted ramp (`#B42318` -> `#0369A1`) so a CRITICAL finding never
  competes with the interface chrome.
- **Warm neutrals, hairline separation.** A `#F5F5F3` canvas, white surfaces and 1px
  `#E4E4E1` borders. Depth comes from `0 1px 2px` shadows, not from blur or glow.
- **Two typefaces with a rule.** Inter for everything a human reads, IBM Plex Mono for
  anything a machine wrote - URLs, CVEs, diffs, timestamps.
- **Bars, not radar polygons.** The six risk dimensions are labelled horizontal meters with
  printed values, so two dimensions can be compared without decoding an angle.
- **Honest labelling.** `Patch availability` measures fix *coverage* rather than risk, and
  the panel says so instead of colour-coding it like a risk axis.

### Keyboard

| Shortcut | Action |
|---|---|
| `⌘K` | Command palette - views, actions and recent runs |
| `⌘↵` | Run a scan on the current target |
| `/` | Focus the target URL field |
| `↑` `↓` `↵` | Move through and run palette results |
| `?` | Shortcut reference |

---

## Architecture

```
        NETLIFY TIER - the live site (one deploy)          SELF-HOSTED TIER - full ML
+-------------------------------+                 +-------------------------------+
|  Next.js 15 on Netlify       |                 |  Next.js 15 dashboard         |
|                               |                 |        |  SSE                  |
|  +-------------------------+  |                 |        v                      |
|  | /api/v1/scan  (POST)    |  |                 |  FastAPI (asyncio)            |
|  |   create job -> after()  |  |                 |   +----------------------+   |
|  +-----------+-------------+  |                 |   | TinyFishWebAgent     |   |
|              |                |                 |   | CodeBETAstScanner    |   |
|  +-----------v-------------+  |                 |   | LLMOrchestrator      |   |
|  | /api/v1/scan/{id} (GET) |  |                 |   +----------------------+   |
|  |   events[] + assessment |  |                 +-------------------------------+
|  +-------------------------+  |
|                               |                 +-------------------------------+
|  job state -> Netlify Blobs   |                 |  torch + transformers         |
|  +-------------------------+  |                 |  microsoft/codebert-base      |
|  | src/lib/zeroday/       |  |                 |  (2.5GB, local only)          |
|  |  tinyfish . nvd         |  |                 +-------------------------------+
|  |  scanner . scoring      |  |
|  |  pipeline . store       |  |
|  +-------------------------+  |
+-------------------------------+
```

Both tiers run **the same pipeline** and produce the same kind of assessment. The pipeline core
lives in TypeScript in `frontend/src/lib/zeroday/`, so the Netlify tier needs no Python runtime;
the Python services are the reference implementation.

| | Netlify tier (live site) | Self-hosted tier (full ML) |
|---|---|---|
| Runtime | Next.js 15 on Netlify Functions | Python 3.12, FastAPI, Uvicorn |
| Static analysis | Pattern analysis, all languages | `ast` module for true Python AST analysis |
| CodeBERT | No - torch cannot run serverless | Yes, `microsoft/codebert-base` embeddings |
| Run it | `netlify deploy` | `docker compose up --build` |

**Frontend** - Next.js 15 (App Router), TypeScript (strict), Tailwind CSS 3, Lucide, Netlify
Functions + Blobs.
**Backend** - FastAPI, asyncio, Pydantic v2, Uvicorn, httpx, HuggingFace Transformers + PyTorch.
**Agent** - TinyFish Search, Fetch, Agent and Research APIs.

---

## How it works

### TinyFish integration

TinyFish is load-bearing, not a mention. Four of its five API surfaces are used:

| Surface | Endpoint | How ZeroDay-Guard uses it |
|---|---|---|
| **Agent** | `POST agent.tinyfish.ai/v1/automation/run-sse` | Goal-driven browsing: navigates the target, dismisses modals, follows links, returns structured JSON validated against an `output_schema` |
| **Search** | `GET api.search.tinyfish.ai` | Discovers candidate advisory / PoC / release-note URLs for a target |
| **Fetch** | `POST api.fetch.tinyfish.ai` | Renders JavaScript pages, extracts PDFs, pulls raw code blocks and diffs |
| **Research** | `POST agent.tinyfish.ai/v1/automation/run-research` | Reasoning backend - source-backed synthesis when no OpenAI/Anthropic key is configured |

```python
async with client.stream("POST", f"{BASE}/v1/automation/run-sse", json={
    "url": target_url,
    "goal": CRAWL_GOAL,
    "output_schema": CRAWL_OUTPUT_SCHEMA,   # guarantees typed fields
}) as response:
    async for line in response.aiter_lines():
        ...
```

**One integration detail worth documenting:** TinyFish signals the event type *inside* the JSON
body (`{"type": "COMPLETE", "result": {...}}`), not as an SSE `event:` name. Parsing only the SSE
event name silently discards every result and makes a working agent look broken.
`backend/app/services/tinyfish_agent.py` reads the body first and only falls back to the SSE name.

### Graceful degradation - the agent is a bonus, not a dependency

The agent can be slow, so Search + Fetch run concurrently with it and the scan **always completes
with real live-web data**:

```
        +-- Agent API -----------------+   (time-boxed)
        |  drives a real cloud browser  |
        +--------------+----------------+
                       |  runs CONCURRENTLY with the fallback
        +--------------+----------------+
        |  Search  ->  discover URLs      |
        |  Fetch   ->  render + extract   |
        |  parse   ->  CVSS / CWE /       |
        |             affected versions  |
        +--------------+----------------+
                       v
              full assessment
```

Three details make the fallback a **first-class** path rather than a degraded one:

- **It runs concurrently with the agent.** The fallback is gathered in the background while the
  agent browses, so an agent timeout costs *no extra wall-clock time*. Total scan time is
  `max(agent, fetch)`, not `agent + fetch`.
- **It extracts vulnerability records, not just CVE IDs.** The raw advisory pages carry a CVSS
  score and severity, a CWE identifier, affected version ranges, a description and a verbatim
  evidence quote - all parsed out of the fetched markdown. Without this, an agent timeout
  silently produced a `0/100 "nothing found"` assessment even though the pages clearly
  described the vulnerability.
- **The agent path is capped by a time budget.** When the budget is exceeded we abandon the
  agent rather than stalling the scan. The abort signal carries the budget, so an agent that
  goes quiet is abandoned on time instead of hanging.

**A scan never returns empty.**

### Why there is an NVD enrichment step

Scraping advisory HTML turned out to be **inherently brittle**: the same page renders differently
between fetches, so a regex matching a CVSS score on one run matched a table of contents on the
next. Two consecutive runs of the same target disagreed on severity, CWE and even the final risk
score.

The fix is to stop asking HTML for structured facts. The **NVD JSON API** returns the same
severity, CVSS base score, CWE and affected-version ranges every time, so it is used to *enrich*
whatever the crawl discovered:

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
-> severity: CRITICAL   baseScore: 10.0   cwe: CWE-20
   affected: "2.0.1 through 2.3.1; 2.4.0 through 2.12.2; 2.13.0 through 2.15.0; ..."
```

This is **enrichment, not replacement**. TinyFish still does the discovery and the context - the
agent browses the target, Search finds the advisories and PoC pages, Fetch pulls the code blocks
and diffs. The NVD record supplies the authoritative fields that HTML scraping cannot promise.
Findings are merged by CVE identity, most authoritative first, so a CVE named in the target URL
wins.

### ML & AI layer

**CodeBERT** (`microsoft/codebert-base`) is loaded **lazily** - the service boots instantly and
works without it.

CodeBERT is a masked language model, not a classifier, and there is no labelled CVE corpus to
fine-tune on. So it is used the way that is actually defensible: **embedding-similarity
classification**. Mean-pooled contextual embeddings of the snippet are compared, by cosine
similarity, against a curated set of *vulnerable* and *safe* exemplars:

```python
vuln_sim = max(cosine(embed(snippet), embed(e)) for e in VULNERABLE_EXEMPLARS)
safe_sim = max(cosine(embed(snippet), embed(e)) for e in SAFE_EXEMPLARS)
semantic_risk = clamp(0.5 + (vuln_sim - safe_sim) * 1.6)
```

The AST findings and the semantic signal are then fused:

```
risk_score = 0.78 * ast_score + 0.22 * (semantic_risk * 100)
```

> **Stated plainly, because it matters:** this is embedding similarity, *not* a fine-tuned
> classifier. The `engine` field in every response tells you which produced the score -
> `codebert+ast` or `ast`. The AST engine does the heavy lifting; CodeBERT is a second opinion.
>
> **CodeBERT runs on the self-hosted tier only.** A serverless function cannot load torch, so the
> Netlify tier reports `engine: ast` and uses the pattern analyser on its own.

### AST / pattern static analyser

The fallback is not a toy - it is real static analysis.

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
OpenAI (GPT-4o)  ->  Anthropic (Claude)  ->  TinyFish Research  ->  deterministic template
```

The template is not a stub - it composes the executive summary from the harvested findings and
always produces a real remediation diff from the patch rulebook.

### Patch generation

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
shown as-is. If nothing matches, the tool says so rather than inventing a patch - an unverified
diff is worse than no diff.

---

## Run it locally

The serverless tier runs as one Next.js app, so local development is one command.

```bash
cd frontend
npm install
npm run dev            # http://localhost:3000
```

Without a key it runs in **demo mode** and serves simulated intelligence, which is enough to
exercise the whole interface. To get the live agent, add your key:

```bash
# frontend/.env.local   (gitignored - never commit the real key)
TINYFISH_API_KEY=sk-tinyfish-...
```

`GET /api/v1/health` reports `demo_mode` and `tinyfish_configured` so you can confirm at a
glance which mode you are in.

The self-hosted Python tier runs separately:

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env    # then fill in TINYFISH_API_KEY
uvicorn app.main:app --reload --port 8000
```

API docs: <http://localhost:8000/docs>

To enable the full CodeBERT engine (downloads about 2.5 GB of torch):

```bash
pip install -r requirements-ml.txt
# smaller, CPU-only torch:
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Without it the service still works; `engine` simply reports `ast`.

Or run the whole stack with Docker:

```bash
cp backend/.env.example backend/.env     # add your TINYFISH_API_KEY
docker compose up --build
```

Backend on `:8000`, frontend on `:3000`.

---

## Deploy

Push to `main`. The **Deploy** workflow builds the app and publishes it to Netlify.

| Workflow | What it does |
|---|---|
| **CI** | Backend unit tests, frontend production build and type check, and a **secret scan** that fails the build if a TinyFish API key is ever committed |
| **Deploy** | Builds the app and publishes it to the Netlify site |

The site needs two settings, both stored as Netlify environment variables:

| Key | Value |
|---|---|
| `TINYFISH_API_KEY` | `sk-tinyfish-...` (from <https://agent.tinyfish.ai/api-keys>) |
| `AGENT_TIME_BUDGET_MS` | Optional, default `12000` |
| `RESEARCH_TIME_BUDGET_MS` | Optional, default `15000` |

Search, Fetch and NVD enrichment together take about five seconds, so a scan completes in roughly
30 seconds. The two budgets cover the only slow phases - the browser agent and the reasoning pass
- and both are overridable per deployment. The self-hosted Python tier has no such limit and can
afford a 90-second agent budget.

---

## Configuration

### Netlify tier (the live site)

| Variable | Required | Purpose |
|---|---|---|
| `TINYFISH_API_KEY` | Yes | Enables the live agent. Without it the service runs in demo mode. |
| `NEXT_PUBLIC_API_URL` | No | Base URL of a separately hosted backend. Leave unset to use the routes in this same app. |
| `AGENT_TIME_BUDGET_MS` | No | How long the browser agent may run. Default `12000`. |
| `RESEARCH_TIME_BUDGET_MS` | No | How long the reasoning pass may run. Default `15000`. |
| `JOB_STALE_AFTER_MS` | No | When a job with no progress is considered dead. Default `90000`. |

### Self-hosted tier (Python)

| Variable | Required | Purpose |
|---|---|---|
| `TINYFISH_API_KEY` | Yes | Same key. `demo` simulates intelligence and makes no network calls. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | No | Override the reasoning backend. The chain falls through to TinyFish Research, then to the deterministic template. |
| `ENABLE_CODEBERT` | No | `true` to load the embedding model. `false` skips the download entirely. |
| `CODEBERT_MODEL` | No | Default `microsoft/codebert-base`. |
| `HOST` / `PORT` | No | Default `0.0.0.0:8000`. |
| `CORS_ORIGINS` | No | Comma-separated allowed origins. |

---

## API

### Netlify tier (the live site) - job-based

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service status, effective config and which job-store backend is live |
| `POST` | `/api/v1/scan` | Body `{ target_url }` -> `{ jobId, status }` immediately |
| `GET` | `/api/v1/scan/{jobId}` | `{ status, events[], assessment, error }` |

A scan takes about 30 seconds, which is longer than a synchronous serverless function can run, so
the API is job-based. The scan continues in the background after the response is sent
(`next/server` `after()`), and the client polls for progress.

```bash
# create a job
curl -X POST https://zeroday-guard-ai.netlify.app/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}'
# -> {"jobId":"b077e1f3-...","status":"queued"}

# poll it
curl https://zeroday-guard-ai.netlify.app/api/v1/scan/b077e1f3-...
# -> {"status":"done","events":[...],"assessment":{...}}
```

### Self-hosted tier (Python) - streaming

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service status and effective config |
| `POST` | `/api/v1/scan` | Full scan -> `{ assessment, events, elapsed_seconds }` |
| `GET` | `/api/v1/scan/stream?target_url=...` | **SSE** live agent trace + final assessment |
| `POST` | `/api/v1/scan/stream` | Same stream, POST body (for long URLs) |
| `GET` | `/api/v1/sample` | A ready-made target for a fast demo |

---

## Project structure

```
netlify.toml                     # Netlify build config (base: frontend)
docker-compose.yml               # runs the Python tier locally

backend/                         # self-hosted tier (Python, full ML)
├── app/
│   ├── main.py                       # FastAPI app, CORS, SSE endpoints
│   ├── config.py                     # env loader
│   ├── models/schemas.py             # Pydantic v2 request/response schemas
│   └── services/
│       ├── tinyfish_agent.py         # Agent + Search + Fetch integration
│       ├── ml_evaluator.py           # CodeBERT embeddings + AST scanner
│       └── llm_orchestrator.py       # reasoning chain + patch rulebook
├── requirements.txt                  # core runtime
├── requirements-ml.txt               # optional torch + transformers
├── tests/                            # 25 offline unit tests
└── smoke_test.py                     # end-to-end test against the live API

frontend/                        # Netlify tier (the live site)
├── src/app/
│   ├── page.tsx                      # thin server wrapper -> <Workbench/>
│   ├── layout.tsx  globals.css       # fonts + design tokens
│   └── api/v1/
│       ├── health/route.ts           # service status + store backend
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

.github/workflows/ci.yml       # tests, build, secret scan
.github/workflows/deploy.yml    # build and publish to Netlify

docs/
├── demo.mp4                   # 90-second product walkthrough
├── DEMO_SCRIPT.md             # timecodes and voice-over for the video
└── record-demo.mjs            # regenerates the video with Playwright
```

---

## Tests

```bash
cd backend
python -m pytest tests -q                             # offline, 25 tests
python smoke_test.py "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"   # live end-to-end

cd ../frontend
npm run typecheck
./scripts/test-scan.ps1                              # live end-to-end of the job flow
```

---

## Limitations

- **CodeBERT is embedding similarity, not a trained classifier.** The AST engine carries the
  score; CodeBERT is a second opinion, and the `engine` field says which one produced it.
- **The Netlify tier cannot run torch**, so it uses the pattern analyser only and reports
  `engine: ast`. The self-hosted tier is where CodeBERT runs.
- **A scan is bounded by the function's wall-clock ceiling**, because the background work is
  awaited inside the same invocation. The two slow phases are time-boxed; Search, Fetch and NVD
  enrichment are not.
- **The browser agent needs about 60 seconds** to finish its crawl, which does not fit the
  serverless window. The Netlify tier therefore usually exercises the Search + Fetch path, and
  the log says so. The self-hosted tier can afford the full agent budget.
- **A job is kept for an hour** after it is created. Re-open an older run and the server has
  already forgotten it.

---

## License

MIT - see [LICENSE](./LICENSE).
