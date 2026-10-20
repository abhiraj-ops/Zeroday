# ZeroDay-Guard AI — Ready-to-Paste Social Posts

Both must be **public** — the jury has to open them without logging in.
Verify each in an **incognito window** before you submit the link on Unstop.

Replace `<demo-link>` with your video link.

---

## LinkedIn (best single choice)

```
A new CVE drops. How long before anyone knows if it's actually exploitable?

For most teams: hours. That's the gap I built ZeroDay-Guard AI to close.

Give it a URL. It:
→ drives an AI browser agent (TinyFish) over the live target — dismissing modals,
  expanding sections, following links to the advisory and the PoC
→ harvests real exploit intelligence: CVE IDs, affected versions, proof-of-concept
  code, and the upstream patch diff
→ scores it with CodeBERT embeddings fused with a real AST static analyser
→ and generates a concrete remediation patch, not just a scary number

The part I'm happiest with: the evidence is HARVESTED, not generated. The advisory text in
the findings panel is verbatim from the live page, and the patch is a real unified diff with
steps to hunt for exploitation.

It also degrades gracefully. The agent path is time-boxed; if it's slow, TinyFish Search +
Fetch (both free) carry the scan on their own. A scan never comes back empty.

Built for the gap between "a CVE was published" and "someone actually checked if we care".

🧑‍💻 Open source → github.com/abhiraj-ops/Zeroday
🎥 2-min demo → <demo-link>

#CyberSecurity #AppSec #AI #ThreatIntelligence #OpenSource
```

**Attach:** a GIF of the terminal filling up, plus screenshots of the risk radar and the
patch diff. A post with media gets far more attention than text alone.

---

## X / Twitter (shorter, punchier)

```
built ZeroDay-Guard AI: give it a URL, it browses the target with an AI web agent,
harvests real exploit intel, scores it with CodeBERT + AST, and writes the patch.

the evidence is harvested, not generated — it's verbatim from the live advisory.
the patch is a real diff, not advice.

🧑‍💻 github.com/abhiraj-ops/Zeroday
🎥 <demo-link>
```

---

## If you have extra time — a reply comment that shows technical depth

Post this as the first comment on your own LinkedIn post:

```
A few things I'd defend in a code review:

1. The CodeBERT path is embedding-similarity classification, not a fine-tuned
   classifier. CodeBERT is a masked LM and we have no labelled CVE corpus, so we
   mean-pool its embeddings and compare by cosine similarity against curated
   vulnerable/safe exemplars. The API always reports which engine scored it
   (codebert+ast or ast).

2. The AST engine is the real work. Python goes through the stdlib ast module, so
   it understands structure — eval/exec sinks, pickle.loads, shell=True, SQL built
   by concatenation, md5, hardcoded credentials — not just regex. C/C++/Java/JS
   use a curated pattern table. Every finding carries a CWE.

3. The agent is time-boxed, and the fallback is a real path, not a stub. Search
   and Fetch are free on TinyFish, so a scan always completes with live-web data.

4. It never executes the code it finds. It reads and analyses.

5. The patch is a rulebook with real diffs, and a real upstream vendor diff is
   preferred when we harvested one. If nothing matches, it says so rather than
   inventing a patch — an unverified diff is worse than no diff.
```

---

## Checklist before you submit the links

- [ ] Post is **public** (not "connections only")
- [ ] Repo link present and the repo is **public**
- [ ] Video link plays
- [ ] Opens correctly in an incognito window
- [ ] Screenshots/GIF attached
- [ ] You've copied the post URL for the Unstop form
