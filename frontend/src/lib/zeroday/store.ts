/**
 * Scan job store.
 *
 * On Netlify, a scan takes longer than a synchronous function can run, so the
 * API is job-based: create a job, run it in the background, poll for status.
 * Job state lives in Netlify Blobs so it survives between function
 * invocations. Locally (no Netlify runtime) an in-memory store is used, so
 * `npm run dev` works with no extra setup.
 */

import type { Assessment } from "./scoring";
import type { PipelineEvent } from "./pipeline";

export interface ScanJob {
  id: string;
  status: "queued" | "running" | "done" | "error";
  target: string;
  createdAt: number;
  updatedAt: number;
  events: PipelineEvent[];
  assessment: Assessment | null;
  error: string | null;
}

const STORE_NAME = "zeroday-scan-jobs";
const JOB_TTL_MS = 60 * 60 * 1000; // an hour is plenty for a demo
const MAX_EVENTS = 400;

/* ------------------------------------------------------- in-memory store */

/**
 * The map lives on globalThis on purpose.
 *
 * Each Next.js route handler gets its own module instance - both in dev and
 * in a production build, where every route is a separate function bundle. A
 * module-level Map would therefore be a *different* map in the route that
 * creates a job and the route that reads it, and every poll would 404.
 * globalThis is shared within the process, so the dev fallback works.
 */
const globalStore = globalThis as typeof globalThis & {
  __zerodayJobs?: Map<string, ScanJob>;
};

const memory: Map<string, ScanJob> = (globalStore.__zerodayJobs ??= new Map<
  string,
  ScanJob
>());

function pruneMemory(): void {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of memory) {
    if (job.updatedAt < cutoff) memory.delete(id);
  }
}

/* --------------------------------------------------------- netlify blobs */

type BlobsStore = {
  setJSON(key: string, data: unknown): Promise<unknown>;
  get(key: string, options: { type: "json" }): Promise<unknown>;
  delete(key: string): Promise<void>;
};

let blobsStore: BlobsStore | null = null;
let blobsChecked = false;
let blobsError: string | null = null;

async function getBlobsStore(): Promise<BlobsStore | null> {
  if (blobsChecked) return blobsStore;
  blobsChecked = true;
  try {
    // Only resolvable inside the Netlify runtime; elsewhere this throws and
    // we fall back to the in-memory store.
    const mod = (await import("@netlify/blobs")) as unknown as {
      getStore: (name: string) => BlobsStore;
    };
    if (typeof mod.getStore !== "function") {
      throw new Error(
        "the installed @netlify/blobs does not export getStore - the job store needs version 7 or newer",
      );
    }
    blobsStore = mod.getStore(STORE_NAME);
  } catch (err) {
    blobsError = err instanceof Error ? err.message : String(err);
    console.warn("[store] blob store unavailable, using memory:", blobsError);
    blobsStore = null;
  }
  return blobsStore;
}

function isNetlifyRuntime(): boolean {
  return Boolean(
    process.env.NETLIFY ||
      process.env.NETLIFY_BUILD_BASE ||
      process.env.NETLIFY_SITE_ID ||
      process.env.AWS_LAMBDA_FUNCTION_NAME,
  );
}

/**
 * How the job store is currently backed.
 *
 * Surfaced by the health endpoint so a store that has silently fallen back
 * to process memory is visible, instead of showing up as unexplained 404s
 * on the first poll.
 */
export async function storeDiagnostics(): Promise<{
  backend: "blobs" | "memory";
  durable: boolean;
  error: string | null;
}> {
  if (!isNetlifyRuntime()) {
    return { backend: "memory", durable: false, error: null };
  }
  const store = await getBlobsStore();
  return {
    backend: store ? "blobs" : "memory",
    durable: Boolean(store),
    error: blobsError,
  };
}

/* ------------------------------------------------------------- public API */

export async function putJob(job: ScanJob): Promise<void> {
  const store = isNetlifyRuntime() ? await getBlobsStore() : null;
  if (store) {
    try {
      await store.setJSON(job.id, job);
      return;
    } catch (err) {
      console.warn("[store] blob write failed, using memory:", err);
    }
  }
  memory.set(job.id, job);
  pruneMemory();
}

export async function getJob(id: string): Promise<ScanJob | null> {
  const store = isNetlifyRuntime() ? await getBlobsStore() : null;
  if (store) {
    try {
      const value = await store.get(id, { type: "json" });
      if (value) {
        return value as ScanJob;
      }
      return null;
    } catch (err) {
      console.warn("[store] blob read failed, using memory:", err);
    }
  }
  return memory.get(id) ?? null;
}

export async function updateJob(
  id: string,
  mutate: (job: ScanJob) => ScanJob,
): Promise<ScanJob | null> {
  const current = await getJob(id);
  if (!current) return null;
  const next = mutate({ ...current, updatedAt: Date.now() });
  await putJob(next);
  return next;
}

export function newJob(id: string, target: string): ScanJob {
  return {
    id,
    status: "queued",
    target,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    events: [],
    assessment: null,
    error: null,
  };
}

export function appendEvent(job: ScanJob, e: PipelineEvent): ScanJob {
  const events = [...job.events, e];
  return {
    ...job,
    events: events.length > MAX_EVENTS ? events.slice(-MAX_EVENTS) : events,
    updatedAt: Date.now(),
  };
}
