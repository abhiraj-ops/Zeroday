// ZeroDay-Guard AI — 90-second product walkthrough.
//
// Drives the real app against the live site and records it. Every action is
// a real interaction: a real scan runs, the real pipeline events stream in,
// the real assessment lands.
//
//   npm i -D playwright && npx playwright install chromium
//   node docs/record-demo.mjs out/
//
// Produces a WebM in the output directory. Convert it to MP4 with any
// ffmpeg build that has libx264:
//
//   ffmpeg -i out/page@*.webm -c:v libx264 -crf 24 -pix_fmt yuv420p \
//          -movflags +faststart demo.mp4
//
// The captions are the on-screen narration. Delete the caption() calls to
// record a clean take with your own voice-over.

import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const OUT = process.argv[2] ?? ".";
const SITE = "https://zeroday-guard-ai.netlify.app";
const VIEWPORT = { width: 1440, height: 900 };

await mkdir(OUT, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: VIEWPORT,
  recordVideo: { dir: OUT, size: VIEWPORT },
  deviceScaleFactor: 1,
});
const page = await context.newPage();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

console.log("-> loading", SITE);
await page.goto(SITE, { waitUntil: "networkidle", timeout: 90_000 });
await sleep(2600);

// A caption in the bottom-left, styled like the app itself, so the video
// reads on its own if nobody narrates it. Injected after the navigation,
// because the first document is replaced by the goto.
await page.addStyleTag({
  content: `
    #__cap {
      position: fixed; left: 300px; bottom: 24px; z-index: 99999;
      font: 500 12.5px/1.45 Inter, ui-sans-serif, system-ui, sans-serif;
      letter-spacing: 0.01em; color: #17171a;
      background: rgba(255,255,255,0.95);
      border: 1px solid #e4e4e1;
      border-radius: 8px; padding: 9px 13px;
      box-shadow: 0 2px 6px rgba(16,16,20,0.06);
      max-width: 470px; opacity: 0; transition: opacity 320ms ease;
    }
    #__cap.on { opacity: 1; }
    #__cap b { display: block; font-size: 10.5px; letter-spacing: 0.08em;
      text-transform: uppercase; color: #1d4ed8; margin-bottom: 3px; }
  `,
});
await page.evaluate(() => {
  const el = document.createElement("div");
  el.id = "__cap";
  document.body.appendChild(el);
});

async function caption(label, text, hold = 2600) {
  await page.evaluate(
    ([l, t]) => {
      const el = document.getElementById("__cap");
      el.innerHTML = `<b>${l}</b>${t}`;
      el.classList.add("on");
    },
    [label, text],
  );
  await sleep(hold);
}

async function captionOff() {
  await page.evaluate(() => document.getElementById("__cap")?.classList.remove("on"));
  await sleep(400);
}

/** Move the pointer the way a person does, so the motion is not a teleport. */
async function glide(x, y) {
  await page.mouse.move(x, y, { steps: 18 });
  await sleep(260);
}

// --- 0:00 the workbench -------------------------------------------------
await caption(
  "ZeroDay-Guard AI",
  "Point it at a URL. It crawls the live web, harvests exploit intelligence, scores the risk and writes the patch.",
  4200,
);
await captionOff();
await sleep(700);

// --- 0:09 type the target ----------------------------------------------
await glide(700, 288);
const field = page.locator("#target-url");
await field.click();
await field.press("Control+a");
await field.press("Delete");
await field.type("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", {
  delay: 42,
});
await sleep(900);
await caption(
  "1. Target",
  "An advisory page, a release note, a product page. The same input drives the whole pipeline.",
  3600,
);
await captionOff();
await sleep(700);

// --- 0:18 run the scan --------------------------------------------------
await glide(1310, 288);
await page.getByRole("button", { name: /^Run scan$/ }).click();
await caption(
  "2. Scan",
  "Search finds the advisories, Fetch renders the pages, the static analyser scores the harvested code.",
  3800,
);
await captionOff();
// Put the pointer on the run log so the eye follows the events as they land.
await glide(1150, 430);

// --- 0:22 the pipeline runs --------------------------------------------
const scanStart = Date.now();
let landed = false;

for (let attempt = 1; attempt <= 2 && !landed; attempt++) {
  if (attempt > 1) {
    console.log("-> scan did not land, retrying");
    await page.getByRole("button", { name: /^Run scan$/ }).click();
    await sleep(1500);
  }
  const waitFrom = Date.now();
  while (Date.now() - waitFrom < 150_000) {
    if (
      await page
        .getByText("Risk assessment", { exact: true })
        .first()
        .isVisible()
        .catch(() => false)
    ) {
      landed = true;
      break;
    }
    await sleep(700);
  }
}

if (!landed) {
  const text = await page.evaluate(() => document.body.innerText.slice(0, 1200));
  throw new Error(`scan never produced an assessment. page says:\n${text}`);
}
await sleep(3200);

// --- 0:52 the assessment ------------------------------------------------
await glide(620, 380);
await caption(
  "3. Assessment",
  "78/100, CRITICAL. Six dimensions, each one printed and comparable - no guessing at a radar angle.",
  4200,
);
await captionOff();
await sleep(1600);
await glide(880, 545);
await sleep(1800);

// --- 1:00 the findings, and the evidence --------------------------------
await glide(80, 258);
await page.getByRole("button", { name: /^Findings/ }).click();
await page.locator("tbody tr").first().waitFor({ state: "visible", timeout: 30_000 });
await sleep(1500);
await caption(
  "4. Findings",
  "One row per weakness, expandable to the verbatim evidence and the source it came from. Harvested, not generated.",
  4000,
);
await captionOff();
await glide(700, 385);
await page.locator("tbody tr").first().click();
await sleep(1500);
await caption(
  "Harvested, not generated",
  "That paragraph is the live advisory text, lifted from the page. The source link is right there.",
  3600,
);
await captionOff();
await sleep(1800);

// --- 1:12 the patch -----------------------------------------------------
await glide(80, 243);
await page.getByRole("button", { name: /^Remediation/ }).click();
await sleep(1700);
await caption(
  "5. Remediation",
  "A concrete unified diff for the class it found, with the manual steps and the upstream references.",
  4000,
);
await captionOff();
await glide(700, 570);
await sleep(1800);

// --- 1:22 the full trace ------------------------------------------------
await glide(80, 277);
await page.getByRole("button", { name: /^Run log$/ }).click();
await sleep(1600);
await caption(
  "6. Run log",
  "Every stage, timestamped and levelled. The whole trace of what the pipeline actually did.",
  3800,
);
await captionOff();
await sleep(1500);

// --- 1:30 close ---------------------------------------------------------
await glide(80, 171);
await page.getByRole("button", { name: /^Assessment$/ }).click();
await sleep(2000);
await caption(
  "github.com/abhiraj-ops/Zeroday",
  "Open source. The live site is zeroday-guard-ai.netlify.app.",
  3600,
);
await captionOff();
await sleep(1200);

await context.close();
await browser.close();

// Playwright names the file after the context; find it and report it.
const { readdir } = await import("node:fs/promises");
const files = await readdir(OUT);
const video = files.find((f) => f.endsWith(".webm"));
console.log("VIDEO:", path.join(OUT, video ?? "not-found"));
