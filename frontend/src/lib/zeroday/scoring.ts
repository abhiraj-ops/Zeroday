/**
 * Verdict engine and patch generator (serverless tier).
 *
 * Ported from backend/app/services/llm_orchestrator.py. The patch generator
 * is a rulebook, not a language model: each vulnerability class maps to a
 * concrete before/after unified diff with remediation steps.
 */

import type { RadarDimension, ScanResult, Severity, StaticFinding } from "./scanner";
import type { Finding } from "../types";

// The Finding shape is the shared contract in ../types (it mirrors the
// Pydantic model). Re-exported here so the verdict engine and the dashboard
// can never drift apart on the field list.
export type { Finding };

export interface PatchFix {
  title: string;
  description: string;
  diff: string;
  language: string;
  cwe: string | null;
  steps: string[];
  references: string[];
}

export interface RiskVector {
  attack_surface: number;
  exploit_maturity: number;
  patch_availability: number;
  code_injection: number;
  authentication_bypass: number;
  data_exposure: number;
}

export interface Assessment {
  executive_summary: string;
  vulnerability_breakdown: Finding[];
  risk_vector: RiskVector;
  patch: PatchFix | null;
  risk: {
    risk_score: number;
    severity_label: Severity;
    confidence: number;
    engine: string;
    factors: string[];
    vector: Record<string, number>;
    signals: Record<string, unknown>;
  };
  target: string;
  generated_at: string;
  reasoning_engine: string;
  agent_trace: string[];
}

export interface ExploitIntel {
  target_url: string;
  summary: string;
  cve_ids: string[];
  vulnerabilities: Record<string, unknown>[];
  code_blocks: { language: string; code: string; source: string }[];
  patch_diffs: string[];
  reproduction_steps: string[];
  references: string[];
  sources_searched: number;
  pages_fetched: number;
  engine: string;
}

interface PatchRule {
  match: string[];
  cwe: string;
  language: string;
  title: string;
  description: string;
  diff: string;
  steps: string[];
}

export const PATCH_RULES: PatchRule[] = [
  {
    match: ["jndi", "log4j", "log4shell", "lookup expansion"],
    cwe: "CWE-502",
    language: "java",
    title: "Upgrade Log4j and disable JNDI message lookups",
    description:
      "JNDI lookups in log messages let an attacker-controlled string trigger remote " +
      "class loading. The vulnerability class was fixed in Log4j 2.17.1; disabling " +
      "lookups entirely removes the sink.",
    diff:
      "-<!-- pom.xml -->\n" +
      "-    <log4j2.version>2.14.1</log4j2.version>\n" +
      "+<!-- pom.xml - 2.17.1+ removes the JNDI lookup vulnerability class -->\n" +
      "+    <log4j2.version>2.17.1</log4j2.version>\n" +
      "+\n" +
      "+    <!-- defence in depth: disable ${...} expansion in log messages -->\n" +
      "+    <log4j2.formatMsgNoLookups>true</log4j2.formatMsgNoLookups>",
    steps: [
      "Upgrade log4j-core and log4j-api to 2.17.1 or later (3.x preferred).",
      "Set -Dlog4j2.formatMsgNoLookups=true as defence in depth.",
      "Never log unvalidated user input; use ParameterizedMessage with pre-formatted values.",
      "Hunt for ${jndi:ldap://} in logs and unexpected outbound LDAP/DNS from the host.",
    ],
  },
  {
    match: ["pickle", "deserialis", "deserializ"],
    cwe: "CWE-502",
    language: "python",
    title: "Replace unsafe deserialisation with a safe format",
    description:
      "pickle.loads executes arbitrary opcodes embedded in the payload. Use JSON (or " +
      "yaml.safe_load) so the payload is inert data rather than code.",
    diff:
      "-import pickle\n" +
      "-def load_config(blob: bytes):\n" +
      "-    return pickle.loads(blob)\n" +
      "+import json\n" +
      "+def load_config(blob: bytes):\n" +
      "+    # JSON has no code-execution semantics, so a hostile payload is inert.\n" +
      "+    return json.loads(blob.decode('utf-8'))\n",
    steps: [
      "Replace pickle with json (or yaml.safe_load) at every deserialisation site.",
      "Reject payloads that fail schema validation before use.",
      "If legacy pickle payloads must be supported, isolate them in a sandbox process.",
    ],
  },
  {
    match: ["yaml.load", "unsafe yaml"],
    cwe: "CWE-502",
    language: "python",
    title: "Use yaml.safe_load",
    description: "yaml.load can instantiate arbitrary Python objects unless SafeLoader is used.",
    diff:
      "-import yaml\n" +
      "-config = yaml.load(payload)\n" +
      "+import yaml\n" +
      "+config = yaml.safe_load(payload)\n",
    steps: [
      "Switch every yaml.load call to yaml.safe_load.",
      "Run the linter rule Bandit B506 in CI to prevent regressions.",
    ],
  },
  {
    match: ["shell=true", "shell command", "subprocess", "os.system"],
    cwe: "CWE-78",
    language: "python",
    title: "Remove the shell from command execution",
    description:
      "Passing a command string to a shell lets metacharacters in any input become " +
      "extra commands. Pass an argument list instead and let the OS exec directly.",
    diff:
      "-import subprocess\n" +
      "-subprocess.run(f'ls {user_path}', shell=True)\n" +
      "+import subprocess\n" +
      "+# Argument list + no shell: no metacharacter interpretation.\n" +
      "+subprocess.run(['ls', user_path], shell=False, check=True)\n",
    steps: [
      "Replace shell=True with an explicit argument list.",
      "Validate user_path against an allow-list of directories.",
      "Run the service with a non-root user and a read-only filesystem where possible.",
    ],
  },
  {
    match: ["sql injection", "sql query", "sql.execute"],
    cwe: "CWE-89",
    language: "python",
    title: "Use parameter binding instead of string concatenation",
    description:
      "Concatenating user input into SQL allows the input to change the query's meaning.",
    diff:
      "-cursor.execute('SELECT * FROM users WHERE id=' + uid)\n" +
      "+cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n",
    steps: [
      "Bind every value as a query parameter.",
      "Use an ORM's parameterised API where available.",
      "Add a regression test that submits a quote character in the input.",
    ],
  },
  {
    match: ["eval", "dynamic code"],
    cwe: "CWE-95",
    language: "python",
    title: "Replace eval with ast.literal_eval or a dispatch table",
    description:
      "eval executes arbitrary code. literal_eval only parses literals; a dispatch table avoids parsing entirely.",
    diff:
      "-result = eval(user_expression)\n" +
      "+import ast\n" +
      "+# literal_eval accepts literals only - never calls functions.\n" +
      "+result = ast.literal_eval(user_expression)\n",
    steps: [
      "Replace eval/exec with ast.literal_eval or an explicit allow-list dispatcher.",
      "Never build code strings from request data.",
    ],
  },
  {
    match: ["strcpy", "strcat", "sprintf", "buffer", "gets"],
    cwe: "CWE-120",
    language: "c",
    title: "Use bounded string operations",
    description:
      "strcpy/strcat/sprintf copy without checking the destination size, causing stack buffer overflows.",
    diff:
      "-char buf[32];\n" +
      "-strcpy(buf, user_input);\n" +
      "+char buf[32];\n" +
      "+snprintf(buf, sizeof(buf), \"%s\", user_input);\n",
    steps: [
      "Replace strcpy/strcat with strncpy/strncat using the real destination size.",
      "Prefer snprintf over sprintf so truncation is explicit.",
      "Enable -Wall -Wextra -Wformat-security and -fstack-protector-strong.",
    ],
  },
  {
    match: ["innerhtml", "xss", "dangerouslysetinnerhtml"],
    cwe: "CWE-79",
    language: "javascript",
    title: "Render untrusted content as text, not HTML",
    description:
      "Assigning to innerHTML lets markup in the value become live DOM, which is stored XSS.",
    diff:
      "-element.innerHTML = userInput;\n" +
      "+// textContent never interprets markup.\n" +
      "+element.textContent = userInput;\n",
    steps: [
      "Use textContent for plain text; sanitise with a vetted library if HTML is required.",
      "Add a Content-Security-Policy header to block inline script as defence in depth.",
    ],
  },
  {
    match: ["md5", "sha1", "weak hash", "weak crypt"],
    cwe: "CWE-328",
    language: "python",
    title: "Move to SHA-256 or better",
    description:
      "MD5 and SHA-1 are broken for collision resistance and must not protect passwords or signatures.",
    diff:
      "-import hashlib\n" +
      "-digest = hashlib.md5(data).hexdigest()\n" +
      "+import hashlib\n" +
      "+digest = hashlib.sha256(data).hexdigest()\n",
    steps: [
      "Use SHA-256 for integrity and a slow KDF (argon2/bcrypt/scrypt) for passwords.",
      "Rotate any secret that was hashed with a broken algorithm.",
    ],
  },
  {
    match: ["verify=false", "tls", "certificate"],
    cwe: "CWE-295",
    language: "python",
    title: "Re-enable TLS certificate verification",
    description:
      "Disabling verification allows a man-in-the-middle to impersonate the server.",
    diff:
      "-requests.get(url, verify=False)\n" +
      "+requests.get(url, verify=True)\n",
    steps: [
      "Remove verify=False.",
      "If an internal CA is required, install the CA bundle and point verify at it.",
    ],
  },
  {
    match: ["hardcoded", "secret", "credential", "api key"],
    cwe: "CWE-798",
    language: "python",
    title: "Move secrets into environment configuration",
    description:
      "Hardcoded secrets leak through source control, images and logs.",
    diff:
      "-API_KEY = \"sk-live-9f2b7c1d4e6a\"\n" +
      "+import os\n" +
      "+API_KEY = os.environ[\"API_KEY\"]  # injected at deploy time\n",
    steps: [
      "Move the value into a secret manager or environment variable.",
      "Rotate the exposed credential immediately — treat it as compromised.",
      "Purge it from git history.",
    ],
  },
  {
    match: ["random", "predictable"],
    cwe: "CWE-330",
    language: "python",
    title: "Use a CSPRNG for tokens and secrets",
    description:
      "random is a predictable Mersenne Twister and must not generate security tokens.",
    diff:
      "-import random\n" +
      "-token = random.randint(0, 10**9)\n" +
      "+import secrets\n" +
      "+token = secrets.token_urlsafe(32)\n",
    steps: ["Use the secrets module for tokens, nonces and salts."],
  },
];

/** Word-boundary match — a naive substring search made "sql" match "excluding". */
function ruleFor(text: string): PatchRule | null {
  const lowered = text.toLowerCase();
  for (const rule of PATCH_RULES) {
    for (const token of rule.match) {
      const pattern = new RegExp(`(?<![a-z0-9])${token.toLowerCase()}(?![a-z0-9])`);
      if (pattern.test(lowered)) return rule;
    }
  }
  return null;
}

function ruleForCwe(cwe: string | null): PatchRule | null {
  if (!cwe) return null;
  const normalised = cwe.toUpperCase();
  return PATCH_RULES.find((r) => r.cwe.toUpperCase() === normalised) ?? null;
}

const SEVERITY_FROM_TEXT: Record<string, Severity> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  moderate: "MEDIUM",
  low: "LOW",
  informational: "INFO",
  info: "INFO",
};

function toSeverity(value: unknown): Severity {
  if (typeof value !== "string") return "MEDIUM";
  return SEVERITY_FROM_TEXT[value.trim().toLowerCase()] ?? "MEDIUM";
}

function cleanCwe(value: unknown): string | null {
  if (!value) return null;
  const match = /CWE-\d+/i.exec(String(value));
  return match ? match[0].toUpperCase() : null;
}

export function buildFindings(intel: ExploitIntel, ml: ScanResult): Finding[] {
  const findings: Finding[] = [];

  for (const vuln of intel.vulnerabilities.slice(0, 10)) {
    if (!vuln || typeof vuln !== "object") continue;
    const v = vuln as Record<string, unknown>;
    const title = String(v.title ?? "Unspecified vulnerability");
    findings.push({
      title,
      severity: toSeverity(v.severity),
      cwe: cleanCwe(v.cwe),
      description: String(v.description ?? ""),
      location: String(v.affected_versions ?? "") || null,
      code_snippet: null,
      language: null,
      source_url: intel.target_url,
      confidence: v.evidence_quote ? 0.7 : 0.5,
      evidence: String(v.evidence_quote ?? "") || null,
      occurrences: 1,
    });
  }

  for (const item of ml.findings.slice(0, 10)) {
    findings.push({
      title: item.title,
      severity: item.severity,
      cwe: item.cwe,
      description: item.description,
      location: item.line ? `line ${item.line}` : null,
      code_snippet: item.snippet || null,
      language: (ml.signals.language as string) ?? null,
      source_url: intel.target_url,
      confidence: Number((ml.confidence * 0.9).toFixed(3)),
      evidence: item.snippet || null,
      occurrences: item.occurrences ?? 1,
    });
  }

  if (!findings.length) {
    findings.push({
      title: "No exploitable pattern confirmed",
      severity: "INFO",
      cwe: null,
      description:
        "The target was crawled and no high-confidence vulnerability artefact could be " +
        "extracted. This is not a clean bill of health — it means the public surface did " +
        "not expose a directly exploitable pattern.",
      location: null,
      code_snippet: null,
      language: null,
      source_url: intel.target_url,
      confidence: 0.4,
      evidence: null,
      occurrences: 1,
    });
  }
  return findings;
}

export function buildRisk(ml: ScanResult, findings: Finding[]): Assessment["risk"] {
  let score = ml.risk_score;
  let severity = ml.severity_label;
  if (findings.some((f) => f.severity === "CRITICAL")) {
    severity = "CRITICAL";
    score = Math.max(score, 78);
  }
  return {
    risk_score: Math.max(0, Math.min(100, score)),
    severity_label: severity,
    // The ML engine has nothing to say when no code was harvested, but a
    // well-evidenced set of web findings is not zero-confidence.
    confidence: Number(Math.max(ml.confidence, findings.length ? 0.45 : 0).toFixed(3)),
    engine: ml.engine,
    factors: ml.factors.slice(0, 8),
    vector: ml.vector,
    signals: ml.signals,
  };
}

export function buildVector(
  ml: ScanResult,
  intel: ExploitIntel,
  findings: Finding[],
): RiskVector {
  const v = ml.vector ?? {};
  const codeInjection = Number(v.code_injection ?? 0);
  const memory = Number(v.memory_safety ?? 0);
  const authBypass = Number(v.auth_bypass ?? 0);
  const dataExposure = Number(v.data_exposure ?? 0);
  const validation = Number(v.input_validation ?? 0);
  const crypto = Number(v.crypto_weakness ?? 0);

  const attackSurface = Math.min(
    100,
    18 * Math.max(1, intel.pages_fetched) + 8 * intel.references.length + 4 * findings.length,
  );
  const exploitMaturity = Math.min(
    100,
    30 * intel.code_blocks.length + 12 * intel.reproduction_steps.length,
  );
  const patchAvailability = Math.min(100, 34 * intel.patch_diffs.length);

  return {
    attack_surface: round(attackSurface),
    exploit_maturity: round(exploitMaturity),
    patch_availability: round(patchAvailability),
    code_injection: round(Math.min(100, Math.max(codeInjection, memory))),
    authentication_bypass: round(Math.min(100, authBypass)),
    data_exposure: round(Math.min(100, Math.max(dataExposure, crypto + validation * 0.6))),
  };
}

function round(n: number): number {
  return Number(Math.min(100, Math.max(0, n)).toFixed(2));
}

export function buildPatch(
  intel: ExploitIntel,
  findings: Finding[],
): PatchFix | null {
  // Title first (most specific), then CWE, then description.
  for (const finding of findings) {
    const rule = ruleFor(finding.title) ?? ruleForCwe(finding.cwe) ?? ruleFor(finding.description);
    if (!rule) continue;
    return {
      title: rule.title,
      description: rule.description,
      diff: rule.diff,
      language: rule.language,
      cwe: rule.cwe,
      steps: rule.steps,
      references: intel.references.slice(0, 6),
    };
  }

  // A real upstream diff harvested from the live page.
  if (intel.patch_diffs.length) {
    return {
      title: "Upstream remediation diff (harvested from the live advisory)",
      description:
        "This diff was extracted verbatim from the target's advisory or release notes " +
        "by the TinyFish web agent, so it is the vendor's own fix.",
      diff: intel.patch_diffs[0],
      language: "text",
      cwe: null,
      steps: [
        "Apply the diff on a branch and run the project's test suite.",
        "Confirm the vulnerable code path is no longer reachable.",
        "Backport to any other deployed version in the same release family.",
      ],
      references: intel.references.slice(0, 6),
    };
  }

  return {
    title: "No automated patch available for this finding",
    description:
      "The harvested artefacts did not match a known-remediable pattern, so no " +
      "confident automatic patch is proposed. Applying an unverified diff would be " +
      "worse than no diff.",
    diff: "",
    language: "text",
    cwe: null,
    steps: [
      "Review the referenced advisory for the vendor's recommended remediation.",
      "Reduce exposure on the affected path until a fix is validated.",
      "Add a regression test that reproduces the reported behaviour.",
    ],
    references: intel.references.slice(0, 8),
  };
}

/** Deterministic executive summary — always available, never wrong. */
export function templateSummary(
  intel: ExploitIntel,
  ml: ScanResult,
  findings: Finding[],
  risk: Assessment["risk"],
): string {
  const critical = findings.filter((f) => f.severity === "CRITICAL");
  const high = findings.filter((f) => f.severity === "HIGH");
  const cves = intel.cve_ids.slice(0, 4).join(", ") || "no CVE identifier";

  let headline: string;
  if (risk.risk_score >= 70 && (critical.length || high.length)) {
    headline =
      `Immediate action required. The assessment scores ${risk.risk_score}/100 ` +
      `(${risk.severity_label}) and identified ${critical.length} critical and ` +
      `${high.length} high-severity issues`;
  } else if (risk.risk_score >= 40) {
    headline =
      `Remediation required. The assessment scores ${risk.risk_score}/100 ` +
      `(${risk.severity_label}) with ${findings.length} findings of varying severity`;
  } else {
    headline =
      `Low observed risk. The assessment scores ${risk.risk_score}/100 ` +
      `(${risk.severity_label}) across ${findings.length} findings`;
  }

  const sources =
    `The TinyFish web agent crawled ${intel.pages_fetched} live page(s) and ` +
    `${intel.sources_searched} candidate source(s), harvesting ${intel.code_blocks.length} ` +
    `code artefact(s)` +
    (intel.patch_diffs.length ? ` and ${intel.patch_diffs.length} upstream diff(s)` : "") +
    `. Identified identifiers: ${cves}.`;

  const engines = risk.factors.length ? risk.factors.slice(0, 4).join(", ") : "no dominant risk factor";
  const factors = `The static analysis engine (${risk.engine}) weighted the following: ${engines}.`;

  const nextSteps: string[] = [];
  if (critical.length) {
    nextSteps.push(
      `Fix ${critical[0].title} first` +
        (critical[0].cwe ? ` (${critical[0].cwe})` : "") +
        " — it is the highest-impact path to code execution.",
    );
  }
  if (intel.reproduction_steps.length) {
    nextSteps.push(
      "Reproduce in an isolated environment using the harvested proof-of-concept " +
        "before touching production.",
    );
  }
  if (intel.patch_diffs.length) {
    nextSteps.push(
      "An upstream fix was located — apply and verify it against the reported " +
        "reproduction steps.",
    );
  }
  nextSteps.push(
    "Re-run this scan after the fix to confirm the risk score drops; the pipeline is " +
      "deterministic, so the change is measurable.",
  );

  return [headline + ".", sources, factors, "Recommended next steps: " + nextSteps.join(" ")].join(" ");
}

export function buildAssessment(
  intel: ExploitIntel,
  ml: ScanResult,
  trace: string[],
  executiveSummary?: string,
): Assessment {
  const findings = buildFindings(intel, ml);
  const risk = buildRisk(ml, findings);
  const vector = buildVector(ml, intel, findings);
  const patch = buildPatch(intel, findings);

  return {
    executive_summary: executiveSummary || templateSummary(intel, ml, findings, risk),
    vulnerability_breakdown: findings,
    risk_vector: vector,
    patch,
    risk,
    target: intel.target_url,
    generated_at: new Date().toISOString(),
    reasoning_engine: executiveSummary ? "tinyfish-research" : "deterministic",
    agent_trace: trace,
  };
}

export type { RadarDimension, ScanResult, Severity, StaticFinding };
