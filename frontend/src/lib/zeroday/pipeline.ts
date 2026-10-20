/**
 * The scan pipeline (serverless tier).
 *
 * Ported from backend/app/services/tinyfish_agent.py + llm_orchestrator.py.
 *
 * Two paths run CONCURRENTLY:
 *   - the TinyFish Agent API, which drives a real cloud browser from a goal
 *   - Search + Fetch, which are free and always work
 *
 * The fallback is gathered in the background while the agent browses, so an
 * agent timeout costs no extra wall-clock time and the scan always completes
 * with real live-web data.
 */

import {
  CRAWL_GOAL,
  CRAWL_OUTPUT_SCHEMA,
  extractResult,
  fetchPages,
  isDemoMode,
  search,
  streamAgent,
  researchSummary,
} from "./tinyfish";
import { cveFromUrl, extractCves, fetchNvdRecords, type NvdRecord } from "./nvd";
import { analyzeMany } from "./scanner";
import { buildAssessment, type Assessment, type ExploitIntel } from "./scoring";

export type EventType = "stage" | "progress" | "intel" | "complete" | "error";
export type EventLevel = "info" | "success" | "warn" | "error" | "agent";

export interface PipelineEvent {
  type: EventType;
  step: string;
  message: string;
  level: EventLevel;
  timestamp: string;
  data?: Record<string, unknown> | null;
}

/** Read a positive integer from the environment, falling back when absent. */
function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  const value = raw ? Number.parseInt(raw, 10) : Number.NaN;
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

/**
 * Wall-clock budgets. A serverless function has a hard ceiling, so these
 * are deliberately conservative and overridable per deployment.
 *
 * The whole scan has to fit inside one function invocation, because the
 * background work is awaited by the same request. The agent and the
 * reasoning pass are the only two slow phases - Search, Fetch and NVD
 * enrichment together take about five seconds - so they are what the
 * budget has to cover.
 */
export const AGENT_TIME_BUDGET_MS = envInt("AGENT_TIME_BUDGET_MS", 12_000);
export const RESEARCH_TIME_BUDGET_MS = envInt("RESEARCH_TIME_BUDGET_MS", 15_000);

/**
 * How long a job may sit without progress before the poll endpoint gives up
 * on it. A function that is terminated mid-scan leaves the job "running"
 * forever, so the client needs a definite answer rather than an endless poll.
 */
export const JOB_STALE_AFTER_MS = envInt("JOB_STALE_AFTER_MS", 90_000);

const CODE_BLOCK_PATTERN = /```([\w+#.-]*)\n([\s\S]*?)```/g;
const DIFF_PATTERN = /^(diff --git .*?$|@@ .*?$|[+-](?![+-]).*?$)/gm;
const CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/gi;
const STEP_PATTERN =
  /^\s*(?:step\s*\d+[.):]|\d+[.)]\s+|[-*]\s+)(.{12,220})$/gm;

function now(): string {
  return new Date().toISOString();
}

function event(
  type: EventType,
  step: string,
  message: string,
  level: EventLevel = "info",
  data?: Record<string, unknown> | null,
): PipelineEvent {
  return { type, step, message, level, timestamp: now(), data };
}

/* ------------------------------------------------------------ extraction */

function extractCodeBlocks(
  page: { url: string; text: string },
): { language: string; code: string; source: string }[] {
  const blocks: { language: string; code: string; source: string }[] = [];
  const text = page.text ?? "";

  // Raw source files: the whole body IS the code.
  if (
    /raw\.githubusercontent\.com|\.(py|js|ts|java|c|cpp|go|rb|php|sh|ps1|yml|yaml)$/i.test(
      page.url,
    )
  ) {
    const body = text.trim();
    if (body.length > 20) {
      const ext = /\.([a-z]+)$/i.exec(page.url.split("?")[0]);
      blocks.push({
        language: ext ? ext[1].toLowerCase() : "text",
        code: body.slice(0, 12000),
        source: page.url,
      });
      return blocks;
    }
  }

  for (const match of text.matchAll(CODE_BLOCK_PATTERN)) {
    const code = (match[2] ?? "").trim();
    if (code.length < 12) continue;
    blocks.push({
      language: (match[1] ?? "unknown").trim() || "unknown",
      code: code.slice(0, 12000),
      source: page.url,
    });
  }
  return blocks;
}

function extractDiffs(page: { text: string }): string[] {
  const diffs: string[] = [];
  for (const match of (page.text ?? "").matchAll(DIFF_PATTERN)) {
    const chunk = match[0].trim();
    if (
      chunk.length > 40 &&
      chunk.split("\n").some((line) => line.startsWith("+") || line.startsWith("-"))
    ) {
      diffs.push(chunk.slice(0, 6000));
    }
  }
  return diffs.slice(0, 5);
}

function extractSteps(text: string): string[] {
  const steps: string[] = [];
  for (const match of (text ?? "").matchAll(STEP_PATTERN)) {
    const candidate = (match[1] ?? "").trim();
    if (candidate && !/^(http|note:)/i.test(candidate)) steps.push(candidate);
  }
  return steps.slice(0, 12);
}

function extractCvesFromText(text: string): string[] {
  return [...new Set((text.match(CVE_PATTERN) ?? []).map((c) => c.toUpperCase()))];
}

/* ------------------------------------------------------------ demo mode */

function mockIntel(targetUrl: string): ExploitIntel {
  return {
    target_url: targetUrl,
    summary:
      "Demonstration payload. The target's release notes and security advisory page " +
      "expose a deserialisation flaw in the configuration parser, tracked as " +
      "CVE-2024-3094, with a public proof-of-concept and an upstream fix available.",
    cve_ids: ["CVE-2024-3094"],
    vulnerabilities: [
      {
        title: "Remote code execution via unsafe deserialisation in config parser",
        severity: "CRITICAL",
        cwe: "CWE-502",
        description:
          "The configuration loader deserialises attacker-reachable objects without " +
          "validation, allowing arbitrary code execution on startup.",
        affected_versions: "<= 3.2.1",
        evidence_quote:
          "Deserialisation of untrusted data allows remote code execution when the " +
          "config file is processed.",
      },
    ],
    code_blocks: [
      {
        language: "python",
        code:
          "import pickle\n\n" +
          "def load_config(blob: bytes):\n" +
          "    # VULNERABLE: pickle executes arbitrary opcodes on load\n" +
          "    return pickle.loads(blob)\n",
        source: "demo://poc/loader.py",
      },
    ],
    patch_diffs: ["-    return pickle.loads(blob)\n+    return json.loads(blob.decode('utf-8'))"],
    reproduction_steps: [
      "Craft a payload that invokes os.system on deserialisation.",
      "Send the payload as the configuration blob to the loader.",
      "Observe command execution in the application context.",
    ],
    references: [
      "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
      "https://cwe.mitre.org/data/definitions/502.html",
    ],
    sources_searched: 6,
    pages_fetched: 3,
    engine: "demo",
  };
}

/* ------------------------------------------------------------ the pipeline */

async function gatherWebSources(
  targetUrl: string,
  cveId: string | null,
  focus: string | null,
): Promise<{ urls: string[]; pages: Awaited<ReturnType<typeof fetchPages>>["pages"]; searched: number }> {
  const targetCve = cveId || cveFromUrl(targetUrl);

  const queries: string[] = [];
  if (targetCve) {
    // PoC repositories carry real code - the ML engine needs it.
    queries.push(`${targetCve} proof of concept exploit github`);
  }
  queries.push(`${targetUrl} security advisory vulnerability`);
  if (focus) queries.push(`${targetUrl} ${focus} vulnerability`);
  if (targetCve) queries.push(`${targetCve} patch diff fix commit`);

  const urls: string[] = [];
  let searched = 0;
  for (const query of queries.slice(0, 4)) {
    const hits = await search(query);
    searched += hits.length;
    for (const hit of hits) if (!urls.includes(hit.url)) urls.push(hit.url);
  }
  if (!urls.includes(targetUrl)) urls.unshift(targetUrl);

  const batch = await fetchPages(urls.slice(0, 10), { ttl: 0 });
  return { urls, pages: batch.pages, searched };
}

function mergeVulnerabilities(
  nvd: NvdRecord[],
  agentRecords: Record<string, unknown>[],
  scraped: Record<string, unknown>[],
): Record<string, unknown>[] {
  const merged: Record<string, unknown>[] = [];
  const seenCves = new Set<string>();
  const seenTitles = new Set<string>();

  for (const raw of [...nvd, ...agentRecords, ...scraped]) {
    if (!raw || typeof raw !== "object") continue;
    const record = { ...raw } as Record<string, unknown>;

    let cves = (record.cve_ids as string[] | undefined) ?? [];
    if (!cves.length) {
      const haystack = `${record.title ?? ""} ${record.description ?? ""}`;
      cves = extractCvesFromText(haystack);
    }
    cves = cves.map((c) => c.toUpperCase());
    record.cve_ids = cves;

    const titleKey = String(record.title ?? "")
      .toLowerCase()
      .replace(/\W+/g, "")
      .slice(0, 60);

    if (cves.length && cves.every((c) => seenCves.has(c))) continue;
    if (!cves.length && seenTitles.has(titleKey)) continue;

    cves.forEach((c) => seenCves.add(c));
    seenTitles.add(titleKey);
    merged.push(record);
  }
  return merged.slice(0, 12);
}

/**
 * Run a complete scan, emitting events as it goes.
 * Returns the finished assessment.
 */
export async function runScan(
  targetUrl: string,
  cveId: string | null,
  focus: string | null,
  onEvent: (e: PipelineEvent) => void,
): Promise<Assessment> {
  const trace: string[] = [];
  const emit = (e: PipelineEvent) => {
    trace.push(e.message);
    onEvent(e);
  };

  // --- demo mode ---------------------------------------------------------
  if (isDemoMode()) {
    emit(
      event("stage", "init", "TINYFISH_API_KEY is 'demo' — serving simulated intelligence.", "warn"),
    );
    for (const message of [
      "Simulating navigation to target page…",
      "Bypassing dynamic JS modal…",
      "Extracting code snippet…",
      "Running static analysis…",
    ]) {
      await new Promise((r) => setTimeout(r, 300));
      emit(event("progress", "demo", message));
    }
    const intel = mockIntel(targetUrl);
    emit(event("intel", "complete", `Demo intelligence assembled for ${targetUrl}`, "success"));
    return buildAssessment(intel, analyzeMany(intel.code_blocks), trace);
  }

  // --- start the fallback concurrently -----------------------------------
  const fallbackPromise = gatherWebSources(targetUrl, cveId, focus);

  // --- 1. the agent ------------------------------------------------------
  let agentPayload: Record<string, unknown> | null = null;
  let agentError: string | null = null;
  const deadline = Date.now() + AGENT_TIME_BUDGET_MS;

  emit(event("stage", "navigate", `Navigating to ${targetUrl}…`, "agent"));

  try {
    for await (const payload of streamAgent(
      targetUrl,
      CRAWL_GOAL,
      CRAWL_OUTPUT_SCHEMA,
      AGENT_TIME_BUDGET_MS,
    )) {
      if (Date.now() > deadline) {
        agentError = `agent exceeded its ${AGENT_TIME_BUDGET_MS / 1000}s budget`;
        break;
      }
      if (payload.type === "STARTED" || payload.type === "PROGRESS") {
        const purpose = String(payload.purpose ?? payload.message ?? "");
        if (purpose) emit(event("progress", "navigate", purpose.slice(0, 220), "agent"));
      } else if (payload.type === "COMPLETE" || payload.type === "RESULT") {
        agentPayload = extractResult(payload);
      } else if (payload.type === "ERROR") {
        agentError = String(payload.message ?? "agent error");
      }
    }
  } catch (err) {
    // The abort that enforces the budget surfaces here. Report it as a
    // budget overrun rather than a transport failure, because that is what
    // it is.
    const name = err instanceof Error ? err.name : "";
    if (name === "AbortError" || name === "TimeoutError") {
      agentError = `agent exceeded its ${Math.round(AGENT_TIME_BUDGET_MS / 1000)}s budget`;
    } else {
      agentError = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    }
  }

  if (agentPayload) {
    emit(event("stage", "navigate", "Agent extracted structured intelligence from the target.", "success"));
  } else {
    const reason = agentError ?? "agent returned no structured result";
    emit(
      event(
        "stage",
        "navigate",
        `Agent path unavailable (${reason.slice(0, 120)}) — falling back to Search + Fetch.`,
        "warn",
      ),
    );
  }

  // --- 2. search + fetch -------------------------------------------------
  const intel: ExploitIntel = {
    target_url: targetUrl,
    summary: "",
    cve_ids: [],
    vulnerabilities: [],
    code_blocks: [],
    patch_diffs: [],
    reproduction_steps: [],
    references: [],
    sources_searched: 0,
    pages_fetched: 0,
    engine: "tinyfish-agent",
  };

  if (agentPayload) {
    intel.summary = String(agentPayload.summary ?? "");
    intel.vulnerabilities = (agentPayload.vulnerabilities ?? []) as Record<string, unknown>[];
    intel.cve_ids = ((agentPayload.cve_ids ?? []) as string[]).map((c) => c.toUpperCase());
    for (const block of (agentPayload.code_snippets ?? []) as Record<string, unknown>[]) {
      if (block?.code) {
        intel.code_blocks.push({
          language: String(block.language ?? "unknown"),
          code: String(block.code).slice(0, 12000),
          source: String(block.source ?? targetUrl),
        });
      }
    }
    for (const diff of (agentPayload.patch_diffs ?? []) as string[]) intel.patch_diffs.push(diff);
  }

  const { urls, pages, searched } = await fallbackPromise;
  intel.sources_searched = searched;
  intel.pages_fetched = pages.length;

  emit(
    event(
      "stage",
      "discover",
      `Discovered ${urls.length} candidate sources across the live web.`,
      "agent",
    ),
  );

  for (const page of pages) {
    emit(
      event(
        "progress",
        "extract",
        `Extracting artefacts from ${page.title || page.url}…`,
      ),
    );
    intel.code_blocks.push(...extractCodeBlocks(page));
    intel.patch_diffs.push(...extractDiffs(page));
    for (const cve of extractCvesFromText(page.text ?? "")) {
      if (!intel.cve_ids.includes(cve)) intel.cve_ids.push(cve);
    }
    intel.reproduction_steps.push(...extractSteps(page.text ?? ""));
    if (page.url && !intel.references.includes(page.url)) intel.references.push(page.url);
  }

  // --- 3. NVD enrichment -------------------------------------------------
  const targetCve = cveFromUrl(targetUrl);
  const cveOrder = [
    ...(targetCve ? [targetCve] : []),
    ...intel.cve_ids.filter((c) => c !== targetCve),
  ];
  const nvdRecords = await fetchNvdRecords(cveOrder.slice(0, 4));
  if (nvdRecords.length) {
    emit(
      event(
        "stage",
        "enrich",
        `Enriched ${nvdRecords.length} CVE record(s) with authoritative NVD data ` +
          "(severity, CWE, affected versions).",
        "success",
      ),
    );
  }

  intel.vulnerabilities = mergeVulnerabilities(
    nvdRecords,
    intel.vulnerabilities,
    [],
  );

  // De-duplicate while preserving order.
  intel.code_blocks = intel.code_blocks.filter(
    (block, i, all) => all.findIndex((b) => b.code === block.code) === i,
  );
  intel.reproduction_steps = [...new Set(intel.reproduction_steps)].slice(0, 12);
  intel.patch_diffs = [...new Set(intel.patch_diffs)].slice(0, 8);
  intel.references = [...new Set(intel.references)].slice(0, 15);

  if (!intel.summary) {
    intel.summary =
      `Analysed ${intel.vulnerabilities.length} vulnerability records and ` +
      `${intel.code_blocks.length} code artefacts harvested from ${intel.pages_fetched} ` +
      `live pages for ${targetUrl}.`;
  }
  if (cveId) {
    const normalised = cveId.toUpperCase();
    if (!intel.cve_ids.includes(normalised)) intel.cve_ids.unshift(normalised);
  }

  emit(
    event(
      "intel",
      "complete",
      `Harvested ${intel.code_blocks.length} code artefacts and ${intel.cve_ids.length} CVE identifiers.`,
      "success",
    ),
  );

  // --- 4. ML --------------------------------------------------------------
  emit(event("stage", "ml", "Running static analysis (CodeBERT / AST) over the harvested code…", "agent"));
  const ml = analyzeMany(intel.code_blocks);
  emit(
    event(
      "stage",
      "ml",
      `Static analysis complete — risk ${ml.risk_score}/100 (${ml.severity_label}), engine=${ml.engine}.`,
      "success",
    ),
  );

  // --- 5. reasoning -------------------------------------------------------
  emit(event("stage", "reason", "Synthesising the executive assessment…", "agent"));
  let summary: string | null = null;
  try {
    const question =
      "Act as a security analyst and write a concise executive security assessment " +
      "for the following collected intelligence. Cite sources where relevant.\n\n" +
      `TARGET: ${targetUrl}\n` +
      `CVEs: ${intel.cve_ids.join(", ") || "none identified"}\n` +
      `ML RISK SCORE: ${ml.risk_score}/100 (${ml.severity_label})\n` +
      `ENGINE FACTORS: ${ml.factors.slice(0, 6).join("; ")}\n\n` +
      `FINDINGS:\n${intel.vulnerabilities
        .slice(0, 10)
        .map(
          (v) =>
            `- [${String(v.severity ?? "")}] ${String(v.title ?? "")} ` +
            `(${String(v.cwe ?? "n/a")}): ${String(v.description ?? "").slice(0, 220)}`,
        )
        .join("\n")}\n\n` +
      `ADVISORY SUMMARY: ${intel.summary.slice(0, 1200)}\n`;
    summary = await researchSummary(question, RESEARCH_TIME_BUDGET_MS);
  } catch {
    summary = null;
  }

  const assessment = buildAssessment(intel, ml, trace, summary ?? undefined);
  emit(
    event(
      "complete",
      "complete",
      `Assessment ready — ${assessment.risk.risk_score}/100 ` +
        `(${assessment.risk.severity_label}).`,
      "success",
      { assessment: assessment as unknown as Record<string, unknown> },
    ),
  );
  return assessment;
}
