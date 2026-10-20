"use client";

import { Fragment, useMemo, useState } from "react";
import { ListTree, ChevronRight, ExternalLink } from "lucide-react";

import Panel from "@/components/ui/Panel";
import { SEVERITY_ORDER, severityToken } from "@/lib/types";
import type { Finding, Severity } from "@/lib/types";

/**
 * Findings are a table, not a stack of cards. Each row is one vulnerability
 * and expands in place to reveal the evidence the agent actually extracted.
 */
export default function FindingsTable({
  findings,
  className = "",
}: {
  findings: Finding[];
  className?: string;
}) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [expanded, setExpanded] = useState<number | null>(null);

  const counts = useMemo(() => {
    const acc = {} as Record<string, number>;
    for (const finding of findings) acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
    return acc;
  }, [findings]);

  const visible = useMemo(
    () => (filter === "all" ? findings : findings.filter((f) => f.severity === filter)),
    [findings, filter],
  );

  const chips: { key: Severity | "all"; label: string; count: number }[] = [
    { key: "all", label: "All", count: findings.length },
    ...SEVERITY_ORDER.filter((sev) => (counts[sev] ?? 0) > 0).map((sev) => ({
      key: sev as Severity | "all",
      label: severityToken(sev).label,
      count: counts[sev] ?? 0,
    })),
  ];

  return (
    <Panel
      className={className}
      eyebrow="Extracted by the agent"
      title="Findings"
      icon={<ListTree className="h-4 w-4 text-faint" />}
      actions={
        <div className="hidden items-center gap-1.5 sm:flex">
          {chips.map((chip) => {
            const active = filter === chip.key;
            const token = chip.key === "all" ? null : severityToken(chip.key);
            return (
              <button
                key={chip.key}
                type="button"
                onClick={() => setFilter(chip.key)}
                className={[
                  "inline-flex items-center gap-1.5 rounded-[5px] border px-2 py-[3px] text-[11.5px] font-medium transition-colors duration-150",
                  active
                    ? "border-accent-line bg-accent-soft text-accent"
                    : "border-line bg-surface text-muted hover:bg-surface-2 hover:text-ink",
                ].join(" ")}
              >
                {token && (
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ backgroundColor: token.solid }}
                    aria-hidden
                  />
                )}
                {chip.label}
                <span className="font-mono text-[10.5px] opacity-70">{chip.count}</span>
              </button>
            );
          })}
        </div>
      }
      bodyClassName=""
    >
      {findings.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
          <ListTree className="h-5 w-5 text-line-strong" />
          <p className="text-[13px] text-muted">No findings extracted yet.</p>
          <p className="max-w-xs text-[12px] text-faint">
            The agent records a finding for every vulnerability it can evidence from the
            advisory, release notes or proof-of-concept it read.
          </p>
        </div>
      ) : (
        <div className="scroll-slim overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse text-left">
            <thead>
              <tr className="border-b border-line bg-surface-2">
                <th className="w-[104px] px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Severity
                </th>
                <th className="px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Finding
                </th>
                <th className="w-[104px] px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.07em] text-faint">
                  CWE
                </th>
                <th className="w-[92px] px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Confidence
                </th>
                <th className="w-[76px] px-3 py-2 text-right text-[10.5px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Source
                </th>
              </tr>
            </thead>
            <tbody>
              {visible.map((finding, index) => {
                const token = severityToken(finding.severity);
                const isOpen = expanded === index;
                return (
                  <Fragment key={`${finding.title}-${index}`}>
                    <tr
                      onClick={() => setExpanded(isOpen ? null : index)}
                      className={[
                        "cursor-pointer border-b border-line/70 align-top transition-colors duration-150 last:border-b-0",
                        isOpen ? "bg-surface-2" : "hover:bg-surface-2/70",
                      ].join(" ")}
                    >
                      <td className="px-3 py-2.5">
                        <span
                          className={[
                            "inline-flex items-center gap-1.5 rounded-[4px] border px-1.5 py-[1px] text-[10.5px] font-semibold uppercase tracking-[0.05em]",
                            token.bg,
                            token.text,
                            token.border,
                          ].join(" ")}
                        >
                          <span
                            className="h-1.5 w-1.5 rounded-full"
                            style={{ backgroundColor: token.solid }}
                            aria-hidden
                          />
                          {token.label}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-start gap-1.5">
                          <ChevronRight
                            className={[
                              "mt-[3px] h-3.5 w-3.5 shrink-0 text-faint transition-transform duration-200 ease-swift",
                              isOpen ? "rotate-90" : "",
                            ].join(" ")}
                          />
                          <span className="text-[13px] font-medium leading-5 text-ink">
                            {finding.title}
                          </span>
                          {finding.occurrences > 1 && (
                            <span
                              title={`Found in ${finding.occurrences} harvested artefacts`}
                              className="mt-[1px] shrink-0 rounded-[4px] border border-line-strong bg-surface-3 px-1.5 py-[1px] font-mono text-[10px] text-muted"
                            >
                              ×{finding.occurrences}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        {finding.cwe ? (
                          <span className="font-mono text-[11.5px] text-low-fg">{finding.cwe}</span>
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="font-mono text-[11.5px] tabular-nums text-ink-2">
                          {Math.round(finding.confidence * 100)}%
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        {finding.source_url ? (
                          <a
                            href={finding.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            title={finding.source_url}
                            className="inline-flex items-center gap-1 rounded-[4px] px-1 py-0.5 text-[11.5px] text-muted transition-colors duration-150 hover:bg-surface-3 hover:text-accent"
                          >
                            Open
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </td>
                    </tr>

                    {isOpen && (
                      <tr className="border-b border-line/70">
                        <td colSpan={5} className="bg-surface-2/60 px-3 pb-4 pl-[38px]">
                          {finding.description && (
                            <p className="max-w-3xl text-[12.5px] leading-5 text-ink-2">
                              {finding.description}
                            </p>
                          )}

                          {finding.evidence && (
                            <figure className="mt-2.5 max-w-3xl rounded-[6px] border border-line bg-surface px-3 py-2">
                              <figcaption className="text-[10.5px] font-semibold uppercase tracking-[0.07em] text-faint">
                                Evidence from the source
                              </figcaption>
                              <blockquote className="mt-1 font-mono text-[11.5px] leading-[1.6] text-ink-2">
                                {finding.evidence}
                              </blockquote>
                            </figure>
                          )}

                          {finding.code_snippet && (
                            <pre className="scroll-slim mt-2.5 max-w-3xl overflow-x-auto rounded-[6px] border border-line bg-surface-3 px-3 py-2 font-mono text-[11.5px] leading-[1.6] text-ink-2">
                              <code>{finding.code_snippet}</code>
                            </pre>
                          )}

                          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-muted">
                            {finding.location && <span>Location: {finding.location}</span>}
                            {finding.language && <span>Language: {finding.language}</span>}
                            {finding.occurrences > 1 && (
                              <span>
                                Seen in {finding.occurrences} harvested artefacts
                              </span>
                            )}
                            {finding.source_url && (
                              <a
                                href={finding.source_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="truncate font-mono text-accent underline-offset-2 hover:underline"
                              >
                                {finding.source_url}
                              </a>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
