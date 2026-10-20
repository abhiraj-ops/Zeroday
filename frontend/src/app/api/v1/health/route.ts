import { NextResponse } from "next/server";
import { isDemoMode } from "@/lib/zeroday/tinyfish";
import { storeDiagnostics } from "@/lib/zeroday/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Service status and effective configuration (never leaks the key). */
export async function GET() {
  // The job store has to survive between function invocations, otherwise the
  // first poll after a scan 404s. Report which backend is actually in use so
  // a silent fallback to process memory is visible.
  const store = await storeDiagnostics();

  return NextResponse.json(
    {
      status: "ok",
      service: "ZeroDay-Guard AI",
      version: "1.0.0",
      tier: "netlify-serverless",
      config: {
        app_name: "ZeroDay-Guard AI",
        version: "1.0.0",
        demo_mode: isDemoMode(),
        tinyfish_configured: !isDemoMode(),
        llm_provider: "tinyfish-research",
        codebert_enabled: false,
        codebert_model: "microsoft/codebert-base (self-hosted Python tier)",
      },
      store,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
