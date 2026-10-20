# ZeroDay-Guard AI — Unstop Submission Kit (copy-paste ready)

Fill the `<brackets>`, submit **hours** before the deadline. Unstop gets slow at midnight.

---

## Field: Project name

```
ZeroDay-Guard AI — autonomous threat assessor with an AI web agent
```

## Field: One-line description

```
Point it at a URL: an AI browser agent crawls the live target, harvests real exploit
intelligence, scores it with CodeBERT + AST analysis, and generates a working patch.
```

## Field: GitHub repo link

```
https://github.com/abhiraj-ops/Zeroday
```

## Field: Demo video link

```
<your YouTube-unlisted or Loom link>
```

## Field: Social media post link

```
<your public LinkedIn or X post URL>
```

## Field: How is TinyFish used? (⚠️ worth up to 20 points — do not skip it)

```
TinyFish is the engine of this product, not an add-on. We use four of its five API
surfaces, and the product degrades gracefully if any of them are unavailable.

1. AGENT API (POST agent.tinyfish.ai/v1/automation/run-sse) — the primary path. We hand
   TinyFish a natural-language goal ("find the advisory, the affected versions, the PoC
   code and the patch diff, and return structured JSON"), and the agent drives a real
   cloud browser: it dismisses cookie banners, expands collapsed sections, follows links
   to the advisory and to the upstream security page, and returns a result validated
   against a JSON output_schema so the fields are typed rather than best-effort. Its
   progress events are streamed to the dashboard, so the user watches the reconnaissance
   happen instead of waiting on a spinner.

2. SEARCH API (GET api.search.tinyfish.ai) — discovers candidate advisory, PoC and
   release-note URLs for a target, including related CVEs.

3. FETCH API (POST api.fetch.tinyfish.ai) — renders JavaScript-heavy pages and extracts
   PDFs, which is what lets us pull raw code blocks, issue threads and unified patch diffs
   out of pages that resist naive scraping.

4. RESEARCH API (POST agent.tinyfish.ai/v1/automation/run-research) — the reasoning
   backend. When no OpenAI or Anthropic key is configured, it produces the source-backed
   executive synthesis, with citations, from the harvested intelligence.

Two implementation details worth calling out:

- The Agent API signals the event type INSIDE the JSON body, not as an SSE event: name.
  Parsing only the SSE event name silently discards every result and makes a working
  agent look broken. We read the body first and fall back to the SSE name.

- The agent path is wall-clock time-boxed (AGENT_TIME_BUDGET), and the Research stage is
  time-boxed too. Search and Fetch are free on TinyFish, so when the agent is slow,
  over budget or unavailable, the scan still completes with real live-web data. A scan
  never returns empty.

Cost: Search, Fetch and Research are all $0 on TinyFish; the Agent API is $0.016/step.
A typical scan is roughly $0.16-0.30, which is what makes a free tier viable.
```

## Field: Problem statement

```
When a CVE is published, the clock starts. But the advisory rarely tells you the thing
that matters: is it exploitable, does a public PoC exist, and is there a patch?

Today that triage is manual. An analyst opens five browser tabs, reads an advisory, finds
the PoC repository, checks the release notes for a fix, and squints at the diff — an hour
per CVE, if you have an hour and if you're allowed to run a browser against a live site.

ZeroDay-Guard AI does that autonomously. It browses the target with an AI web agent,
harvests the exploit intelligence that is already published, scores it, and tells you what
to do, including the patch.

The design principle is evidence over assertion: the advisory text in the findings panel is
harvested verbatim from the live page, and the remediation is a real unified diff. If
nothing matches, it says so rather than inventing a patch.
```

## Field: Who is it for?

```
Primary: application security engineers and vulnerability-management teams doing
first-pass triage across a large CVE feed.
Secondary: developers who get a dependency advisory and need to know "do I care, and what
do I actually change?" without reading three advisories.
Tertiary: security researchers and bug-bounty hunters looking for the public PoC and the
upstream fix for a specific CVE.
```

## Field: Tech stack

```
Backend: Python 3.11+, FastAPI, asyncio, Pydantic v2, Uvicorn, httpx
Agent:   TinyFish Agent + Search + Fetch + Research APIs
ML:      HuggingFace Transformers + PyTorch (microsoft/codebert-base), stdlib ast
LLM:     OpenAI / Anthropic, with TinyFish Research and a deterministic template as
         fallbacks
Frontend: Next.js 15 (App Router), TypeScript, Tailwind CSS, Lucide, Framer Motion

Server-Sent Events stream the agent trace live to the dashboard.
```

## Field: Team members

```
<your name> — <your role / college>
```

---

## ⏳ Final 10-minute check before you hit submit

- [ ] Repo is **public** and `README.md` renders properly on GitHub (Mermaid diagram!)
- [ ] No API key anywhere in the repo — check `git log -p | grep -i tinyfish`
- [ ] Demo video link plays in an incognito window
- [ ] Social post is **public** and opens without login
- [ ] Deployed app URL loads (and the backend URL is set via `NEXT_PUBLIC_API_URL`)
- [ ] All fields above filled — **especially the TinyFish one**
- [ ] ✅ Submitted

Then close the laptop. You need to be sharp for the finale on 31 Oct.
