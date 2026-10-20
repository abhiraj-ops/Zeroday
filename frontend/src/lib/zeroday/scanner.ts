/**
 * Static vulnerability analyser (serverless tier).
 *
 * Ported from backend/app/services/ml_evaluator.py. The Python tier uses the
 * stdlib `ast` module for true structural analysis of Python; this tier uses
 * pattern analysis across every supported language, which is what runs on
 * Netlify where no Python runtime is available.
 *
 * Every finding carries a CWE identifier and maps to one of six radar
 * dimensions, so the two tiers produce comparable results.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 32,
  HIGH: 20,
  MEDIUM: 10,
  LOW: 5,
  INFO: 1,
};

export const RADAR_DIMENSIONS = [
  "code_injection",
  "memory_safety",
  "input_validation",
  "crypto_weakness",
  "auth_bypass",
  "data_exposure",
] as const;

export type RadarDimension = (typeof RADAR_DIMENSIONS)[number];

export interface StaticFinding {
  title: string;
  severity: Severity;
  cwe: string | null;
  dimension: RadarDimension;
  description: string;
  line: number | null;
  snippet: string;
  /**
   * How many times this weakness class was observed. The same flaw usually
   * appears in several harvested artefacts; the dashboard reports the class
   * once and says how many places it turned up.
   */
  occurrences: number;
}

export interface ScanResult {
  risk_score: number;
  severity_label: Severity;
  confidence: number;
  engine: string;
  findings: StaticFinding[];
  factors: string[];
  vector: Record<string, number>;
  signals: Record<string, unknown>;
}

interface PatternRule {
  re: RegExp;
  langs: string[];
  cwe: string;
  severity: Severity;
  dimension: RadarDimension;
  title: string;
}

const PATTERN_RULES: PatternRule[] = [
  // --- JavaScript / TypeScript ------------------------------------------
  { re: /\beval\s*\(/, langs: ["js", "ts"], cwe: "CWE-95", severity: "CRITICAL", dimension: "code_injection", title: "eval() executes a string as code" },
  { re: /new\s+Function\s*\(/, langs: ["js", "ts"], cwe: "CWE-95", severity: "CRITICAL", dimension: "code_injection", title: "new Function() is equivalent to eval()" },
  { re: /\.innerHTML\s*=/, langs: ["js", "ts"], cwe: "CWE-79", severity: "HIGH", dimension: "code_injection", title: "innerHTML assignment can inject scripts" },
  { re: /dangerouslySetInnerHTML/, langs: ["js", "ts"], cwe: "CWE-79", severity: "HIGH", dimension: "code_injection", title: "dangerouslySetInnerHTML can inject scripts" },
  { re: /document\.write\s*\(/, langs: ["js", "ts"], cwe: "CWE-79", severity: "HIGH", dimension: "code_injection", title: "document.write can inject markup" },
  { re: /child_process\.exec\s*\(/, langs: ["js", "ts"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "child_process.exec runs a shell command" },
  { re: /require\(['"]child_process/, langs: ["js", "ts"], cwe: "CWE-78", severity: "HIGH", dimension: "code_injection", title: "child_process imported" },
  { re: /rejectUnauthorized\s*:\s*false/, langs: ["js", "ts"], cwe: "CWE-295", severity: "HIGH", dimension: "auth_bypass", title: "TLS verification disabled" },
  { re: /Math\.random\s*\(\s*\)/, langs: ["js", "ts"], cwe: "CWE-330", severity: "MEDIUM", dimension: "crypto_weakness", title: "Math.random is not cryptographically secure" },
  { re: /createHash\s*\(\s*['"](?:md5|sha1)['"]/i, langs: ["js", "ts"], cwe: "CWE-328", severity: "MEDIUM", dimension: "crypto_weakness", title: "MD5/SHA-1 are broken hash algorithms" },

  // --- Python ------------------------------------------------------------
  { re: /\beval\s*\(/, langs: ["python"], cwe: "CWE-95", severity: "CRITICAL", dimension: "code_injection", title: "Dynamic code execution via eval()" },
  { re: /\bexec\s*\(/, langs: ["python"], cwe: "CWE-95", severity: "CRITICAL", dimension: "code_injection", title: "Dynamic code execution via exec()" },
  { re: /pickle\.loads?\s*\(/, langs: ["python"], cwe: "CWE-502", severity: "CRITICAL", dimension: "code_injection", title: "Unsafe deserialisation" },
  { re: /marshal\.loads?\s*\(/, langs: ["python"], cwe: "CWE-502", severity: "CRITICAL", dimension: "code_injection", title: "Unsafe deserialisation" },
  { re: /yaml\.load\s*\((?![^)]*Safe)/, langs: ["python"], cwe: "CWE-502", severity: "CRITICAL", dimension: "code_injection", title: "Unsafe YAML deserialisation" },
  { re: /subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/s, langs: ["python"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "Shell command injection (shell=True)" },
  { re: /os\.system\s*\(/, langs: ["python"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "Shell command execution" },
  { re: /__import__\s*\(/, langs: ["python"], cwe: "CWE-95", severity: "HIGH", dimension: "code_injection", title: "Dynamic import via __import__()" },
  { re: /hashlib\.(md5|sha1)\s*\(/, langs: ["python"], cwe: "CWE-328", severity: "MEDIUM", dimension: "crypto_weakness", title: "Weak hash algorithm" },
  { re: /tempfile\.mktemp\s*\(/, langs: ["python"], cwe: "CWE-377", severity: "MEDIUM", dimension: "data_exposure", title: "Insecure temporary file (mktemp)" },
  { re: /verify\s*=\s*False/, langs: ["python"], cwe: "CWE-295", severity: "HIGH", dimension: "auth_bypass", title: "TLS certificate verification disabled" },
  { re: /random\.(random|randint|choice|uniform)\s*\(/, langs: ["python"], cwe: "CWE-330", severity: "MEDIUM", dimension: "crypto_weakness", title: "Non-cryptographic randomness" },
  { re: /\bassert\s+/, langs: ["python"], cwe: "CWE-617", severity: "LOW", dimension: "input_validation", title: "assert used as a validation check" },

  // --- C / C++ -----------------------------------------------------------
  { re: /\bstrcpy\s*\(/, langs: ["c", "cpp"], cwe: "CWE-120", severity: "CRITICAL", dimension: "memory_safety", title: "strcpy has no bounds checking" },
  { re: /\bstrcat\s*\(/, langs: ["c", "cpp"], cwe: "CWE-120", severity: "CRITICAL", dimension: "memory_safety", title: "strcat has no bounds checking" },
  { re: /\bgets\s*\(/, langs: ["c", "cpp"], cwe: "CWE-242", severity: "CRITICAL", dimension: "memory_safety", title: "gets() cannot be used safely" },
  { re: /\bvsprintf\s*\(/, langs: ["c", "cpp"], cwe: "CWE-120", severity: "CRITICAL", dimension: "memory_safety", title: "vsprintf can overflow the destination buffer" },
  { re: /\bsprintf\s*\(/, langs: ["c", "cpp"], cwe: "CWE-120", severity: "HIGH", dimension: "memory_safety", title: "sprintf can overflow the destination buffer" },
  { re: /\bmemcpy\s*\(/, langs: ["c", "cpp"], cwe: "CWE-120", severity: "HIGH", dimension: "memory_safety", title: "memcpy size must be validated" },
  { re: /\balloca\s*\(/, langs: ["c", "cpp"], cwe: "CWE-770", severity: "MEDIUM", dimension: "memory_safety", title: "alloca can overflow the stack" },
  { re: /\bsystem\s*\(/, langs: ["c", "cpp"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "system() invokes a shell" },
  { re: /\batoi\s*\(/, langs: ["c", "cpp"], cwe: "CWE-20", severity: "MEDIUM", dimension: "input_validation", title: "atoi does not report conversion errors" },

  // --- Java --------------------------------------------------------------
  { re: /Runtime\.getRuntime\(\)\.exec\s*\(/, langs: ["java"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "Runtime.exec runs an OS command" },
  { re: /new\s+ObjectInputStream\s*\(/, langs: ["java"], cwe: "CWE-502", severity: "CRITICAL", dimension: "code_injection", title: "Java deserialisation of untrusted data" },
  { re: /Class\.forName\s*\(/, langs: ["java"], cwe: "CWE-470", severity: "HIGH", dimension: "code_injection", title: "Reflective class loading from untrusted input" },
  { re: /getInstance\s*\(\s*["']MD5["']/i, langs: ["java"], cwe: "CWE-328", severity: "MEDIUM", dimension: "crypto_weakness", title: "MD5 is a broken hash algorithm" },
  { re: /getInstance\s*\(\s*["']SHA-?1["']/i, langs: ["java"], cwe: "CWE-328", severity: "MEDIUM", dimension: "crypto_weakness", title: "SHA-1 is a broken hash algorithm" },
  { re: /TrustManager|HostnameVerifier|setDefaultHostnameVerifier/, langs: ["java"], cwe: "CWE-295", severity: "HIGH", dimension: "auth_bypass", title: "Custom TLS trust manager may disable verification" },

  // --- exploit indicators (every language) --------------------------------
  { re: /\$\{\s*jndi\s*:/, langs: ["any"], cwe: "CWE-917", severity: "CRITICAL", dimension: "code_injection", title: "JNDI lookup payload (Log4Shell-style remote class loading)" },
  { re: /(?:ldap|rmi|dns|ldaps):\/\//, langs: ["any"], cwe: "CWE-918", severity: "HIGH", dimension: "code_injection", title: "External reference to a remote endpoint" },
  { re: /\/bin\/(?:ba)?sh\s+-i/, langs: ["any"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "Reverse shell payload" },
  { re: /\bnc\s+(?:-[a-z]*e\b|-e\s)/, langs: ["any"], cwe: "CWE-78", severity: "CRITICAL", dimension: "code_injection", title: "Netcat reverse shell payload" },
  { re: /b64decode\s*\(/, langs: ["any"], cwe: "CWE-506", severity: "MEDIUM", dimension: "code_injection", title: "Encoded payload decoded at runtime" },
  { re: /exec\s*\(\s*(?:compile|base64|bytes|request|payload|cmd)/, langs: ["any"], cwe: "CWE-95", severity: "CRITICAL", dimension: "code_injection", title: "Dynamic execution of a constructed payload" },
  { re: /socket\.socket\s*\(/, langs: ["python"], cwe: "CWE-78", severity: "MEDIUM", dimension: "code_injection", title: "Raw socket usage" },
  { re: /(?<![a-z0-9])(?:password|passwd|secret|api[_-]?key|token|private[_-]?key|credential)\s*[:=]\s*['"][^'"]{8,}['"]/i, langs: ["any"], cwe: "CWE-798", severity: "HIGH", dimension: "data_exposure", title: "Hardcoded credential in source" },
];

const SEVERITY_ORDER: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const SCORE_FLOOR: Record<Severity, number> = {
  CRITICAL: 78,
  HIGH: 62,
  MEDIUM: 45,
  LOW: 25,
  INFO: 0,
};

export function detectLanguage(code: string): string {
  if (/^\s*#include\s*[<"]/m.test(code)) return "c";
  if (
    /(import\s+java\.|public\s+(static\s+)?(class|interface|enum)\b|System\.out\.print|public\s+static\s+void\s+main)/.test(code)
  ) {
    return "java";
  }
  if (
    /^\s*(def|class)\s+\w+\s*[(:]/m.test(code) ||
    /^\s*(from\s+\S+\s+)?import\s+\w+/m.test(code)
  ) {
    if (/\bself\.|\belif\b|\bNone\b|\bTrue\b/.test(code)) return "python";
  }
  if (
    /(=>|\bfunction\s*[\w]*\s*\(|\b(?:var|let|const)\s+\w+\s*=|\brequire\s*\(|console\.log|document\.|window\.|\.innerHTML|\.textContent|\bexport\s+(?:default|\{|const|function)|\bimport\s+.*\bfrom\s+['"])/.test(
      code,
    )
  ) {
    return "js";
  }
  if (/\bfunc\s+\w+\s*\(/.test(code)) return "go";
  if (/\bfn\s+\w+\s*\(|let\s+mut\s+/.test(code)) return "rust";
  if (/^\s*(def|class|import)\s/m.test(code)) return "python";
  return code.trim() ? "python" : "unknown";
}

function lineAt(code: string, lineNo: number): string {
  const lines = code.split("\n");
  return lineNo >= 1 && lineNo <= lines.length ? lines[lineNo - 1].trim() : "";
}

function analysePatterns(code: string, language: string): StaticFinding[] {
  const findings: StaticFinding[] = [];
  for (const rule of PATTERN_RULES) {
    if (!rule.langs.includes("any") && !rule.langs.includes(language)) continue;
    const match = rule.re.exec(code);
    if (!match) continue;
    const lineNo = code.slice(0, match.index).split("\n").length;
    findings.push({
      title: rule.title,
      severity: rule.severity,
      cwe: rule.cwe,
      dimension: rule.dimension,
      description: `Pattern matched \`${match[0].trim()}\` in a ${language} snippet.`,
      line: lineNo,
      snippet: lineAt(code, lineNo),
      occurrences: 1,
    });
  }
  return findings;
}

/**
 * Collapse findings that describe the same weakness class.
 *
 * The key is the class (title + CWE), not the position in the file. The same
 * JNDI payload turns up in every harvested proof-of-concept, so keying on
 * the line number reported one bug once per artefact and the findings list
 * read as a wall of duplicates. Occurrences are counted instead, so the
 * information survives the collapse.
 */
function mergeByClass(findings: StaticFinding[]): StaticFinding[] {
  const merged = new Map<string, StaticFinding>();
  for (const finding of findings) {
    const key = `${finding.title}|${finding.cwe ?? ""}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...finding, occurrences: finding.occurrences || 1 });
      continue;
    }
    existing.occurrences += finding.occurrences || 1;
  }
  return [...merged.values()];
}

/** Analyse one snippet and return a normalised risk assessment. */
export function analyzeCodeSnippet(code: string): ScanResult {
  if (!code || !code.trim()) {
    return {
      risk_score: 0,
      severity_label: "INFO",
      confidence: 0,
      engine: "ast",
      findings: [],
      factors: ["No code supplied for analysis."],
      vector: Object.fromEntries(RADAR_DIMENSIONS.map((d) => [d, 0])) as Record<string, number>,
      signals: { language: "unknown", lines: 0, characters: 0 },
    };
  }

  const snippet = code.slice(0, 4000);
  const language = detectLanguage(snippet);
  const findings = analysePatterns(snippet, language);

  // Collapse repeated occurrences of the same weakness class.
  const unique = mergeByClass(findings);

  // Weighting by occurrence count keeps the score identical to the
  // pre-merge behaviour, where each hit was its own row.
  const total = unique.reduce(
    (sum, f) => sum + SEVERITY_WEIGHT[f.severity] * f.occurrences,
    0,
  );
  // Saturating curve: many findings raise the score but never past 100.
  const astScore = 100 * (1 - Math.exp(-total / 55));
  let riskScore = Math.round(Math.min(100, Math.max(0, astScore)));

  let maxSev: Severity = "INFO";
  for (const f of unique) {
    if (SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(maxSev)) maxSev = f.severity;
  }
  const severityLabel = severityFromScore(riskScore, maxSev);

  // Keep the number and the label consistent.
  riskScore = Math.max(riskScore, SCORE_FLOOR[severityLabel]);

  const vector: Record<string, number> = Object.fromEntries(
    RADAR_DIMENSIONS.map((d) => [d, 0]),
  ) as Record<string, number>;
  for (const f of unique) {
    vector[f.dimension] = Math.min(
      100,
      (vector[f.dimension] ?? 0) + SEVERITY_WEIGHT[f.severity] * 2.2 * f.occurrences,
    );
  }

  const observed = unique.reduce((sum, f) => sum + f.occurrences, 0);
  const confidence = Math.min(0.95, 0.35 + 0.12 * observed);

  return {
    risk_score: riskScore,
    severity_label: severityLabel,
    confidence: Number(confidence.toFixed(3)),
    engine: "ast",
    findings: unique,
    factors: unique.length
      ? unique.slice(0, 6).map((f) => f.title)
      : ["No dangerous patterns detected in this snippet."],
    vector: Object.fromEntries(
      Object.entries(vector).map(([k, v]) => [k, Number(v.toFixed(2))]),
    ) as Record<string, number>,
    signals: {
      language,
      lines: snippet.split("\n").length,
      characters: snippet.length,
      ast_weight: Number(total.toFixed(2)),
    },
  };
}

function severityFromScore(score: number, maxFindingSeverity: Severity): Severity {
  if (maxFindingSeverity === "CRITICAL") return "CRITICAL";
  if (score >= 72) return maxFindingSeverity === "HIGH" && score >= 82 ? "CRITICAL" : "HIGH";
  if (score >= 48) return "MEDIUM";
  if (score >= 22) return "LOW";
  return "INFO";
}

/** Analyse several blocks and return the aggregate worst case. */
export function analyzeMany(blocks: { code?: string }[]): ScanResult {
  const analyses = blocks
    .filter((b) => b.code)
    .map((b) => analyzeCodeSnippet(b.code as string));
  if (!analyses.length) {
    return {
      risk_score: 0,
      severity_label: "INFO",
      confidence: 0,
      engine: "ast",
      findings: [],
      factors: ["No code blocks were harvested from the target."],
      vector: Object.fromEntries(RADAR_DIMENSIONS.map((d) => [d, 0])) as Record<string, number>,
      signals: { blocks: 0 },
    };
  }

  const worst = analyses.reduce((a, b) => (b.risk_score > a.risk_score ? b : a));
  const merged: Record<string, number> = Object.fromEntries(
    RADAR_DIMENSIONS.map((d) => [d, 0]),
  ) as Record<string, number>;
  for (const a of analyses) {
    for (const [k, v] of Object.entries(a.vector)) {
      merged[k] = Math.max(merged[k] ?? 0, v);
    }
  }

  const seen = new Set<string>();
  const findings: StaticFinding[] = [];
  for (const a of analyses) {
    for (const f of a.findings) {
      const key = `${f.title}|${f.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }

  // Collapse the same weakness class seen in several harvested artefacts.
  const mergedFindings = mergeByClass(findings);

  return {
    risk_score: worst.risk_score,
    severity_label: worst.severity_label,
    confidence: worst.confidence,
    engine: worst.engine,
    findings: mergedFindings,
    factors: worst.factors,
    vector: Object.fromEntries(
      Object.entries(merged).map(([k, v]) => [k, Number(v.toFixed(2))]),
    ) as Record<string, number>,
    signals: {
      blocks: analyses.length,
      worst_score: worst.risk_score,
    },
  };
}
