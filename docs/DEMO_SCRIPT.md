# ZeroDay-Guard AI — Demo video

![Demo](demo.mp4)

**`docs/demo.mp4`** — 1 min 32 sec, 1440x900, 25 fps. Recorded against the live site
(<https://zeroday-guard-ai.netlify.app>) with a real scan running against the real NVD page
for CVE-2021-44228. Nothing in it is staged.

Regenerate it with `docs/record-demo.mjs`.

---

## Timecodes

The video carries its own on-screen captions, so it plays on its own. This is the same
walkthrough with the voice-over that fits each beat, if you want to record your own take over
it.

| Time | On screen | Voice-over |
|---|---|---|
| 0:00-0:08 | The workbench, empty target field | "A new CVE drops. How long before anyone knows if it's actually exploitable? For most teams, hours. That's the gap this closes." |
| 0:08-0:18 | The NVD URL typed into the target field | "Give it a URL. An advisory, a release note, a product page — the same input drives the whole pipeline." |
| 0:18-0:22 | **Run scan** clicked, the button flips to *Analysing* | "It's not a scraper. It drives a real browser agent and streams its plan back to you as it works." |
| 0:22-0:52 | The run log filling with real pipeline events | "Search finds the advisories and the proof-of-concept pages. Fetch renders them. Each artefact is extracted as it lands — timestamps, levels, the source it came from." |
| 0:52-1:00 | The assessment: 78/100, CRITICAL, the risk vector | "A real AST analyser scores the harvested code. Six dimensions, each one printed with its value, so you can compare them without decoding a radar angle." |
| 1:00-1:12 | A finding expanded to its evidence block | "Every finding carries the evidence it was derived from — lifted from the live page, with the source link right there. Harvested, not generated." |
| 1:12-1:22 | The remediation diff, `+5 -2` | "And it doesn't just say this is dangerous. It gives you the fix: upgrade Log4j to 2.17.1, disable JNDI lookups, as a concrete unified diff with the manual steps and the upstream references." |
| 1:22-1:32 | The full run log, then the closing frame | "Every stage is recorded. Open source at github.com/abhiraj-ops/Zeroday." |

---

## Recording your own take

```bash
npm i -D playwright && npx playwright install chromium
node docs/record-demo.mjs out/
```

The script drives the live site, waits for a real scan to land, and records the whole
workflow. It will not fake a result — if the scan does not produce an assessment, it fails
loudly rather than recording an empty screen.

To record a clean take without the burned-in captions, delete the `caption()` and
`captionOff()` calls in the script.

---

## Tips for a clean take

- **Start the scan first, then talk.** A scan takes about 30 seconds — use that time.
- One clean take per section, then stitch. You will not nail 90 seconds in one go.
- Speak ~20% slower than feels natural.
- The run log is the star — make sure the text is readable on the recording.
- **Total runtime target: 1:30.**

## After recording

- [ ] Watch it end-to-end **once**, sound on
- [ ] Upload → YouTube *unlisted*, or share the file directly
- [ ] Play the shared link in an incognito window to confirm it works
