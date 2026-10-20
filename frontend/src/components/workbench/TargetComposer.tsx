"use client";

import { useState } from "react";
import { Crosshair, Play, ChevronDown, Info, Loader2 } from "lucide-react";

import Button from "@/components/ui/Button";
import Kbd from "@/components/ui/Kbd";

/**
 * The scan composer.
 *
 * A labelled field with an explicit label beats a placeholder-as-label, and
 * the run shortcut is advertised rather than hidden.
 */
export default function TargetComposer({
  target,
  cveId,
  focus,
  onTargetChange,
  onCveChange,
  onFocusChange,
  onRun,
  running,
  error,
}: {
  target: string;
  cveId: string;
  focus: string;
  onTargetChange: (value: string) => void;
  onCveChange: (value: string) => void;
  onFocusChange: (value: string) => void;
  onRun: () => void;
  running: boolean;
  error: string | null;
}) {
  const [advanced, setAdvanced] = useState(false);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onRun();
      }}
      className="surface shadow-sm"
    >
      <div className="p-4">
        <div className="flex items-center justify-between gap-3">
          <label
            htmlFor="target-url"
            className="text-[12.5px] font-medium text-ink"
          >
            Target URL
            <span className="ml-1.5 text-faint">· advisory, release notes or product page</span>
          </label>
          <button
            type="button"
            onClick={() => setAdvanced((v) => !v)}
            className="flex items-center gap-1 text-[12px] text-muted transition-colors duration-150 hover:text-ink"
          >
            Advanced
            <ChevronDown
              className={[
                "h-3.5 w-3.5 transition-transform duration-200 ease-swift",
                advanced ? "" : "-rotate-90",
              ].join(" ")}
            />
          </button>
        </div>

        <div className="mt-2 flex flex-col gap-2 sm:flex-row">
          <div
            className={[
              "flex min-w-0 flex-1 items-center gap-2 rounded-[7px] border bg-surface px-3 transition-[border-color,box-shadow] duration-150",
              error
                ? "border-red-400 focus-within:border-red-500 focus-within:shadow-[0_0_0_3px_rgba(220,38,38,0.12)]"
                : "border-line-strong focus-within:border-accent focus-within:shadow-[0_0_0_3px_rgba(29,78,216,0.12)]",
            ].join(" ")}
          >
            <Crosshair className="h-4 w-4 shrink-0 text-faint" />
            <input
              id="target-url"
              value={target}
              onChange={(e) => onTargetChange(e.target.value)}
              spellCheck={false}
              autoComplete="off"
              placeholder="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
              className="h-10 min-w-0 flex-1 bg-transparent font-mono text-[13px] text-ink outline-none placeholder:font-sans placeholder:text-faint"
            />
          </div>
          <Button
            type="submit"
            variant="primary"
            size="md"
            disabled={running}
            className="h-10 shrink-0 px-4"
          >
            {running ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Analysing
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" />
                Run scan
              </>
            )}
          </Button>
        </div>

        {advanced && (
          <div className="mt-3 grid gap-3 border-t border-line pt-3 sm:grid-cols-2">
            <div>
              <label htmlFor="cve-id" className="text-[12px] font-medium text-ink-2">
                CVE ID
                <span className="ml-1.5 font-normal text-faint">optional</span>
              </label>
              <input
                id="cve-id"
                value={cveId}
                onChange={(e) => onCveChange(e.target.value)}
                spellCheck={false}
                placeholder="CVE-2021-44228"
                className="field mt-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="focus" className="text-[12px] font-medium text-ink-2">
                Focus
                <span className="ml-1.5 font-normal text-faint">optional</span>
              </label>
              <input
                id="focus"
                value={focus}
                onChange={(e) => onFocusChange(e.target.value)}
                spellCheck={false}
                placeholder="deserialisation, RCE, auth bypass…"
                className="field mt-1.5"
              />
            </div>
          </div>
        )}

        <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-muted">
          <span className="flex items-center gap-1.5">
            <Info className="h-3.5 w-3.5 text-faint" />
            <Kbd>⌘</Kbd>
            <Kbd>↵</Kbd>
            <span>to run</span>
          </span>
          <span className="text-line-strong">|</span>
          <span>Search + Fetch run on every target; the browser agent is time-boxed and optional.</span>
        </div>

        {error && (
          <p className="mt-2.5 rounded-[6px] border border-red-200 bg-red-50 px-3 py-2 text-[12.5px] text-red-700">
            {error}
          </p>
        )}
      </div>
    </form>
  );
}
