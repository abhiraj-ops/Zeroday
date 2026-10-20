/**
 * Types shared by the dashboard and the serverless pipeline.
 * Mirrors the Pydantic schemas in backend/app/models/schemas.py.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type EventLevel = "info" | "success" | "warn" | "error" | "agent";
export type EventType = "stage" | "finding" | "progress" | "intel" | "complete" | "error";

export interface AgentEvent {
  type: EventType;
  step: string;
  message: string;
  level: EventLevel;
  timestamp: string;
  data?: Record<string, unknown> | null;
}

export interface Finding {
  title: string;
  severity: Severity;
  cwe: string | null;
  description: string;
  location: string | null;
  code_snippet: string | null;
  language: string | null;
  source_url: string | null;
  confidence: number;
  evidence: string | null;
  /**
   * How many harvested artefacts showed this weakness. One vulnerability
   * class usually appears in several proof-of-concept files; the dashboard
   * reports the class once and says how often it turned up.
   */
  occurrences: number;
}

export interface RiskScore {
  risk_score: number;
  severity_label: Severity;
  confidence: number;
  engine: string;
  factors: string[];
  vector: Record<string, number>;
  signals: Record<string, unknown>;
}

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
  risk: RiskScore;
  target: string;
  generated_at: string;
  reasoning_engine: string;
  agent_trace: string[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  tier?: string;
  config: {
    app_name: string;
    version: string;
    demo_mode: boolean;
    tinyfish_configured: boolean;
    llm_provider: string;
    codebert_enabled: boolean;
    codebert_model: string;
  };
}

/* ------------------------------------------------------------------ *
 * Presentation tokens
 *
 * Severity is a muted, legible ramp on warm neutrals — no neon, no
 * glow. The single accent (blue) is reserved for primary actions and
 * active state, so it never collides with a finding's severity colour.
 * ------------------------------------------------------------------ */

export interface SeverityToken {
  /** Text colour for the label itself. */
  text: string;
  /** Very light background for the badge. */
  bg: string;
  /** Hairline border for the badge. */
  border: string;
  /** Solid fill used for meter bars and dots. */
  solid: string;
  /** Human label. */
  label: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityToken> = {
  CRITICAL: {
    text: "text-critical-fg",
    bg: "bg-critical-bg",
    border: "border-critical-line",
    solid: "#D92D20",
    label: "Critical",
  },
  HIGH: {
    text: "text-high-fg",
    bg: "bg-high-bg",
    border: "border-high-line",
    solid: "#DC6803",
    label: "High",
  },
  MEDIUM: {
    text: "text-medium-fg",
    bg: "bg-medium-bg",
    border: "border-medium-line",
    solid: "#DC6803",
    label: "Medium",
  },
  LOW: {
    text: "text-low-fg",
    bg: "bg-low-bg",
    border: "border-low-line",
    solid: "#0BA5EC",
    label: "Low",
  },
  INFO: {
    text: "text-ink-2",
    bg: "bg-surface-3",
    border: "border-line-strong",
    solid: "#A1A1AA",
    label: "Info",
  },
};

/** Most severe first — used for sorting and for the legend order. */
export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function severityToken(severity: string): SeverityToken {
  return SEVERITY_STYLES[severity as Severity] ?? SEVERITY_STYLES.INFO;
}

/* ------------------------------------------------------------------ *
 * Event levels
 * ------------------------------------------------------------------ */

export interface EventLevelToken {
  label: string;
  /** Dot colour used in the activity log gutter. */
  dot: string;
  text: string;
}

export const LEVEL_STYLES: Record<EventLevel, EventLevelToken> = {
  agent: { label: "AGENT", dot: "bg-accent", text: "text-accent" },
  success: { label: "OK", dot: "bg-emerald-600", text: "text-emerald-700" },
  info: { label: "INFO", dot: "bg-sky-600", text: "text-sky-700" },
  warn: { label: "WARN", dot: "bg-amber-600", text: "text-amber-700" },
  error: { label: "ERR", dot: "bg-red-600", text: "text-red-700" },
};
