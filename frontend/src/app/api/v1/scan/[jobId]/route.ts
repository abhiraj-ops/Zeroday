import { NextResponse } from "next/server";
import { getJob, updateJob } from "@/lib/zeroday/store";
import { JOB_STALE_AFTER_MS } from "@/lib/zeroday/pipeline";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Poll a scan job.
 *
 * Returns the full event trace so far plus the assessment once it is ready.
 * The client appends only the events it has not seen yet, which is what
 * makes the run log fill up live.
 */
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ jobId: string }> },
) {
  const { jobId } = await params;
  let job = await getJob(jobId);

  if (!job) {
    return NextResponse.json({ error: "Unknown or expired job id." }, { status: 404 });
  }

  // A serverless function that is terminated mid-scan leaves the job stuck
  // on "running" forever. The heartbeat stops when that happens, so a job
  // with no progress for longer than the stale window is dead. Fail it
  // explicitly rather than letting the client poll a job that will never
  // finish.
  if (
    job.status === "running" &&
    Date.now() - job.updatedAt > JOB_STALE_AFTER_MS
  ) {
    const failed = await updateJob(job.id, (j) => ({
      ...j,
      status: "error",
      error:
        "The scan was interrupted before it finished — the analysis runtime stopped " +
        "mid-run. Start a new scan to try again.",
      updatedAt: Date.now(),
    }));
    if (failed) job = failed;
  }

  return NextResponse.json(
    {
      jobId: job.id,
      status: job.status,
      target: job.target,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
      events: job.events,
      assessment: job.assessment,
      error: job.error,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
