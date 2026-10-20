import { randomUUID } from "node:crypto";
import { after, NextResponse } from "next/server";
import { runScan, type PipelineEvent } from "@/lib/zeroday/pipeline";
import { appendEvent, newJob, putJob, updateJob } from "@/lib/zeroday/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** How often the job is touched while a scan is running. */
const HEARTBEAT_INTERVAL_MS = 8_000;

/**
 * Create a scan job and run it in the background.
 *
 * The scan takes longer than a synchronous serverless function can run, so
 * the request returns immediately with a job id and the client polls
 * GET /api/v1/scan/[jobId] for progress. The agent trace is written to the
 * job as it happens, so the terminal still fills up live.
 */
export async function POST(req: Request) {
  let targetUrl = "";
  let cveId: string | null = null;
  let focus: string | null = null;

  try {
    const body = (await req.json()) as {
      target_url?: string;
      cve_id?: string | null;
      focus?: string | null;
    };
    targetUrl = String(body.target_url ?? "").trim();
    cveId = body.cve_id ?? null;
    focus = body.focus ?? null;
  } catch {
    /* handled below */
  }

  if (targetUrl.length < 3) {
    return NextResponse.json(
      { error: "Enter a fuller target URL to scan." },
      { status: 400 },
    );
  }
  if (targetUrl.length > 2048) {
    return NextResponse.json(
      { error: "That target URL is too long (max 2048 characters)." },
      { status: 400 },
    );
  }
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = `https://${targetUrl}`;

  const id = randomUUID();
  const job = newJob(id, targetUrl);
  await putJob(job);

  const execute = async () => {
    await updateJob(id, (j) => ({ ...j, status: "running" }));

    // Event writes are serialised. The pipeline emits without awaiting, so
    // two concurrent read-modify-write cycles on the same job would race and
    // drop events — including the final one, which the client polls for
    // right as the job flips to "done".
    let writes: Promise<unknown> = Promise.resolve();

    const emit = (e: PipelineEvent) => {
      writes = writes.then(() => updateJob(id, (j) => appendEvent(j, e)));
      return writes;
    };

    // A heartbeat, so the job looks alive while a long phase is running.
    // It goes through the same chain as the event writes, otherwise it
    // could write back a stale copy of the job and lose an event.
    const heartbeat = setInterval(() => {
      writes = writes.then(() => updateJob(id, (j) => ({ ...j })));
    }, HEARTBEAT_INTERVAL_MS);

    try {
      const assessment = await runScan(targetUrl, cveId, focus, (e) => {
        void emit(e);
      });
      // Flush every pending event before the job is marked complete.
      await writes;
      await updateJob(id, (j) => ({
        ...j,
        status: "done",
        assessment,
        updatedAt: Date.now(),
      }));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await updateJob(id, (j) => ({
        ...j,
        status: "error",
        error: message,
        updatedAt: Date.now(),
      }));
    } finally {
      clearInterval(heartbeat);
    }
  };

  // `after` runs the job once the response has been sent. Netlify supports
  // it fully; if the runtime does not, fall back to awaiting inline.
  try {
    after(execute);
  } catch {
    void execute();
  }

  return NextResponse.json({ jobId: id, status: "queued", target: targetUrl });
}
