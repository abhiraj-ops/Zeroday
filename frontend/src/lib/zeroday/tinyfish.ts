/**
 * TinyFish clients for the serverless (Netlify) tier.
 *
 * Ported from backend/app/services/tinyfish_agent.py so the same product runs
 * as one self-contained Next.js app on Netlify, with no Python runtime
 * required. Raw fetch rather than an SDK, so the README and demo video can
 * show the actual HTTP calls.
 */

export const TINYFISH_SEARCH_URL = "https://api.search.tinyfish.ai";
export const TINYFISH_FETCH_URL = "https://api.fetch.tinyfish.ai";
export const TINYFISH_AGENT_URL = "https://agent.tinyfish.ai";

export interface SearchHit {
  url: string;
  title: string | null;
  snippet: string | null;
  site: string | null;
}

export interface PageContent {
  url: string;
  title: string | null;
  description: string | null;
  text: string;
  highlights: string[];
}

export interface FetchBatch {
  pages: PageContent[];
  failed: { url: string; error: string }[];
  highlightsAvailable: boolean;
}

export class TinyFishError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "TinyFishError";
  }
}

export function apiKey(): string {
  const key = process.env.TINYFISH_API_KEY?.trim();
  if (!key) {
    throw new TinyFishError(
      "TINYFISH_API_KEY is not set. Add it in your Netlify environment variables.",
      undefined,
      "MISSING_KEY",
    );
  }
  return key;
}

export function isDemoMode(): boolean {
  const key = process.env.TINYFISH_API_KEY?.trim().toLowerCase();
  return !key || ["demo", "changeme", "your_key_here", "none"].includes(key);
}

function headers(): Record<string, string> {
  return { "X-API-Key": apiKey(), "Content-Type": "application/json" };
}

async function readError(res: Response): Promise<TinyFishError> {
  let code: string | undefined;
  try {
    const body = (await res.json()) as { error?: { code?: string } };
    code = body?.error?.code;
  } catch {
    /* ignore */
  }
  return new TinyFishError(
    `TinyFish ${res.status}${code ? ` (${code})` : ""}`,
    res.status,
    code,
  );
}

/* ------------------------------------------------------------------ Search */

export interface SearchOpts {
  domainType?: "web" | "news" | "research_paper";
  location?: string;
  language?: string;
  recencyMinutes?: number;
  purpose?: string;
}

/** GET https://api.search.tinyfish.ai — free tier: 12,000 requests/day. */
export async function search(
  query: string,
  opts: SearchOpts = {},
): Promise<SearchHit[]> {
  const params = new URLSearchParams({ query });
  if (opts.domainType) params.set("domain_type", opts.domainType);
  if (opts.location) params.set("location", opts.location);
  if (opts.language) params.set("language", opts.language);
  if (opts.recencyMinutes) params.set("recency_minutes", String(opts.recencyMinutes));
  if (opts.purpose) params.set("purpose", opts.purpose);

  try {
    const res = await fetch(`${TINYFISH_SEARCH_URL}?${params.toString()}`, {
      headers: headers(),
      signal: AbortSignal.timeout(25_000),
      cache: "no-store",
    });
    if (!res.ok) throw await readError(res);
    const data = (await res.json()) as {
      results?: {
        url?: string;
        title?: string | null;
        snippet?: string | null;
        site_name?: string | null;
      }[];
    };
    return (data.results ?? [])
      .filter((r) => r.url)
      .map((r) => ({
        url: r.url as string,
        title: r.title ?? null,
        snippet: r.snippet ?? null,
        site: r.site_name ?? null,
      }));
  } catch (err) {
    // A single failed angle must not sink the whole verification.
    console.warn("[tinyfish] search failed:", err);
    return [];
  }
}

/* ------------------------------------------------------------------- Fetch */

export interface FetchOpts {
  ttl?: number;
  highlightQuery?: string;
  maxSnippets?: number;
  includeSelectors?: string[];
}

/**
 * POST https://api.fetch.tinyfish.ai — up to 10 URLs per request.
 * Free tier: 1,000 URLs/day. Renders JS and extracts PDF text.
 */
export async function fetchPages(
  urls: string[],
  opts: FetchOpts = {},
): Promise<FetchBatch> {
  const target = urls.slice(0, 10);
  if (target.length === 0) {
    return { pages: [], failed: [], highlightsAvailable: false };
  }

  const body: Record<string, unknown> = { urls: target, format: "markdown" };
  if (opts.ttl === 0) body.ttl = 0;
  if (opts.includeSelectors?.length) {
    body.include_selectors = opts.includeSelectors.slice(0, 20);
  }
  if (opts.highlightQuery) {
    body.highlights = {
      query: opts.highlightQuery,
      max_snippets: opts.maxSnippets ?? 3,
    };
  }

  const res = await fetch(TINYFISH_FETCH_URL, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(90_000),
    cache: "no-store",
  });
  if (!res.ok) throw await readError(res);

  const data = (await res.json()) as {
    results?: {
      url?: string;
      final_url?: string;
      title?: string | null;
      description?: string | null;
      text?: string | Record<string, unknown>;
      highlights?: unknown;
    }[];
    errors?: { url?: string; error?: unknown }[];
  };

  const pages: PageContent[] = [];
  let highlightsAvailable = false;

  for (const item of data.results ?? []) {
    const highlights = normaliseHighlights(item.highlights);
    if (highlights.length > 0) highlightsAvailable = true;
    pages.push({
      url: item.url ?? "",
      title: item.title ?? null,
      description: item.description ?? null,
      text:
        typeof item.text === "string"
          ? item.text
          : item.text
            ? JSON.stringify(item.text)
            : "",
      highlights,
    });
  }

  const failed = (data.errors ?? []).map((e) => ({
    url: e.url ?? "",
    error:
      typeof e.error === "string" ? e.error : JSON.stringify(e.error ?? "error"),
  }));

  return { pages, failed, highlightsAvailable };
}

function normaliseHighlights(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((h) => {
      if (typeof h === "string") return h.trim();
      if (h && typeof h === "object") {
        const o = h as Record<string, unknown>;
        const t = o.text ?? o.quote ?? o.snippet ?? o.content;
        return typeof t === "string" ? t.trim() : "";
      }
      return "";
    })
    .filter((t) => t.length > 0);
}

/* ------------------------------------------------------------------ Agent */

export const CRAWL_GOAL =
  "You are a security analyst. Open the target page and extract the following, " +
  "returning a single JSON object:\n" +
  '{"cve_ids": [string], "vulnerabilities": [{"title": string, "severity": string, ' +
  '"cwe": string, "description": string, "affected_versions": string, "evidence_quote": string}], ' +
  '"code_snippets": [{"language": string, "code": string, "source": string}], ' +
  '"patch_diffs": [string], "summary": string}\n' +
  "Dismiss cookie banners, expand collapsed sections, then read the advisory text, " +
  "affected versions, proof-of-concept code and any patch diff. Quote text exactly as " +
  "written. Be efficient - read the main advisory rather than exploring every link.";

export const CRAWL_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    cve_ids: { type: "array", items: { type: "string" } },
    vulnerabilities: {
      type: "array",
      items: {
        type: "object",
        properties: {
          title: { type: "string" },
          severity: { type: "string" },
          cwe: { type: "string" },
          description: { type: "string" },
          affected_versions: { type: "string" },
          evidence_quote: { type: "string" },
        },
        required: ["title", "severity", "description"],
      },
    },
    code_snippets: {
      type: "array",
      items: {
        type: "object",
        properties: {
          language: { type: "string" },
          code: { type: "string" },
          source: { type: "string" },
        },
        required: ["language", "code"],
      },
    },
    patch_diffs: { type: "array", items: { type: "string" } },
    summary: { type: "string" },
  },
  required: [
    "cve_ids",
    "vulnerabilities",
    "code_snippets",
    "patch_diffs",
    "summary",
  ],
} as const;

export interface AgentStreamEvent {
  type: string;
  purpose?: string;
  message?: string;
  result?: unknown;
  research_run_id?: string;
}

/**
 * Stream SSE events from the TinyFish Agent API.
 *
 * TinyFish signals the event type INSIDE the JSON body, not as an SSE
 * `event:` name. Reading only the SSE name drops every result and makes a
 * working agent look broken - so the body is read first.
 */
export async function* streamAgent(
  url: string,
  goal: string,
  outputSchema?: unknown,
  budgetMs?: number,
): AsyncGenerator<AgentStreamEvent> {
  // The abort signal is the real enforcement of the time budget. Checking a
  // deadline between chunks is not enough: if the stream goes quiet, the
  // read never returns and the budget would never fire. Aborting the fetch
  // unblocks the reader, so a stalled agent is abandoned on time instead of
  // hanging until the function is killed.
  const res = await fetch(`${TINYFISH_AGENT_URL}/v1/automation/run-sse`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ url, goal, output_schema: outputSchema }),
    signal: AbortSignal.timeout(budgetMs ?? 240_000),
    cache: "no-store",
  });
  if (!res.ok) throw await readError(res);
  if (!res.body) throw new TinyFishError("Empty agent stream", undefined, "NO_BODY");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) continue;
      const payload = trimmed.slice(5).trim();
      if (!payload || payload === "[DONE]") continue;
      try {
        yield JSON.parse(payload) as AgentStreamEvent;
      } catch {
        /* keepalive */
      }
    }
  }
}

/** Pull the agent's final JSON out of a COMPLETE payload. */
export function extractResult(payload: AgentStreamEvent): Record<string, unknown> | null {
  if (!("result" in payload) || payload.result === undefined) return null;
  const result = payload.result;

  if (result && typeof result === "object" && !Array.isArray(result)) {
    const obj = result as Record<string, unknown>;
    if (obj.result && typeof obj.result === "object") return obj.result as Record<string, unknown>;
    return obj;
  }
  if (Array.isArray(result)) return { raw: result };
  if (typeof result === "string") {
    const text = result.trim();
    const fenced = /```(?:json)?\s*(\{[\s\S]*?\})\s*```/.exec(text);
    const candidate = fenced?.[1] ?? /\{[\s\S]*\}/.exec(text)?.[0];
    if (candidate) {
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === "object") return parsed;
      } catch {
        /* not JSON */
      }
    }
    return { summary: text.slice(0, 4000) };
  }
  return null;
}

/* --------------------------------------------------------------- Research */

/**
 * TinyFish Research as a reasoning backend — searches, evaluates sources and
 * returns a cited synthesis. Used when no OpenAI/Anthropic key is configured.
 *
 * Research routinely takes 5-20 minutes, so it is wall-clock budgeted and
 * the latest interim synthesis is used if the budget expires.
 */
export async function researchSummary(
  query: string,
  budgetMs: number,
): Promise<string> {
  const deadline = Date.now() + Math.max(10_000, budgetMs);
  let partial = "";

  try {
    const res = await fetch(`${TINYFISH_AGENT_URL}/v1/automation/run-research`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ query, mode: "deep", stream: true }),
      // Abort on the budget so a silent stream cannot hold the function
      // open past its ceiling.
      signal: AbortSignal.timeout(Math.max(10_000, budgetMs)),
      cache: "no-store",
    });
    if (!res.ok) return "";
    if (!res.body) return "";

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:")) continue;
        const raw = trimmed.slice(5).trim();
        if (!raw || raw === "[DONE]") continue;
        let payload: { event?: string; result?: unknown; summary?: unknown };
        try {
          payload = JSON.parse(raw);
        } catch {
          continue;
        }
        if (payload.event === "final_result") {
          return String(payload.result ?? "").trim();
        }
        if (payload.event === "partial_summary") {
          const candidate = String(payload.result ?? payload.summary ?? "");
          if (candidate.length > partial.length) partial = candidate;
        }
        if (Date.now() > deadline) return partial.trim();
      }
    }
  } catch {
    return partial.trim();
  }
  return partial.trim();
}
