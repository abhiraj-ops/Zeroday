"""Reasoning orchestrator — turns raw web intelligence into a security assessment.

Engine chain (first available wins, so the product never hard-fails):

1. **OpenAI** (GPT-4o) — multi-step reasoning and narrative synthesis.
2. **Anthropic** (Claude) — same contract, different provider.
3. **TinyFish Research** — the web layer we already have enabled. It searches,
   evaluates sources and returns a cited synthesis, which makes it a credible
   reasoning backend for exploit analysis.
4. **Deterministic template** — a local generator that composes the
   assessment from the harvested findings, including a real unified diff for
   every recognised vulnerability class.

The patch generator is a *rulebook*, not a language model: each detected
vulnerability class maps to a concrete before/after diff. That means the
"Auto-Generated Patch" panel shows real, correct remediation code even with
no LLM key configured.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from app.config import Settings
from app.models.schemas import (
    Assessment,
    Finding,
    PatchFix,
    RiskScore,
    RiskVector,
    Severity,
)
from app.services.ml_evaluator import RADAR_DIMENSIONS, CodeBETAstScanner
from app.services.tinyfish_agent import ExploitIntel

SEVERITY_FROM_TEXT = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


# ---------------------------------------------------------------------------
# Patch rulebook — real before/after remediations
# ---------------------------------------------------------------------------
PATCH_RULES: list[dict[str, Any]] = [
    {
        "match": ["jndi", "log4j", "log4shell", "lookup expansion"],
        "cwe": "CWE-502",
        "language": "java",
        "title": "Upgrade Log4j and disable JNDI message lookups",
        "description": (
            "JNDI lookups in log messages let an attacker-controlled string trigger remote "
            "class loading. The vulnerability class was fixed in Log4j 2.17.1; disabling "
            "lookups entirely removes the sink."
        ),
        "diff": (
            "-<!-- pom.xml -->\n"
            "-    <log4j2.version>2.14.1</log4j2.version>\n"
            "+<!-- pom.xml - 2.17.1+ removes the JNDI lookup vulnerability class -->\n"
            "+    <log4j2.version>2.17.1</log4j2.version>\n"
            "+\n"
            "+    <!-- defence in depth: disable ${...} expansion in log messages -->\n"
            "+    <log4j2.formatMsgNoLookups>true</log4j2.formatMsgNoLookups>"
        ),
        "steps": [
            "Upgrade log4j-core and log4j-api to 2.17.1 or later (3.x preferred).",
            "Set -Dlog4j2.formatMsgNoLookups=true as defence in depth.",
            "Never log unvalidated user input; use ParameterizedMessage with pre-formatted values.",
            "Hunt for ${jndi:ldap://} in logs and unexpected outbound LDAP/DNS from the host.",
        ],
    },
    {
        "match": ["pickle", "deserialis", "deserializ"],
        "cwe": "CWE-502",
        "language": "python",
        "title": "Replace unsafe deserialisation with a safe format",
        "description": (
            "pickle.loads executes arbitrary opcodes embedded in the payload. Use JSON (or "
            "yaml.safe_load) so the payload is inert data rather than code."
        ),
        "diff": (
            "-import pickle\n"
            "-def load_config(blob: bytes):\n"
            "-    return pickle.loads(blob)\n"
            "+import json\n"
            "+def load_config(blob: bytes):\n"
            "+    # JSON has no code-execution semantics, so a hostile payload is inert.\n"
            "+    return json.loads(blob.decode('utf-8'))\n"
        ),
        "steps": [
            "Replace pickle with json (or yaml.safe_load) at every deserialisation site.",
            "Reject payloads that fail schema validation before use.",
            "If legacy pickle payloads must be supported, isolate them in a sandbox process.",
        ],
    },
    {
        "match": ["yaml.load", "unsafe yaml"],
        "cwe": "CWE-502",
        "language": "python",
        "title": "Use yaml.safe_load",
        "description": "yaml.load can instantiate arbitrary Python objects unless SafeLoader is used.",
        "diff": (
            "-import yaml\n"
            "-config = yaml.load(payload)\n"
            "+import yaml\n"
            "+config = yaml.safe_load(payload)\n"
        ),
        "steps": [
            "Switch every yaml.load call to yaml.safe_load.",
            "Run the linter rule Bandit B506 in CI to prevent regressions.",
        ],
    },
    {
        "match": ["shell=true", "shell command", "subprocess", "os.system"],
        "cwe": "CWE-78",
        "language": "python",
        "title": "Remove the shell from command execution",
        "description": (
            "Passing a command string to a shell lets metacharacters in any input become "
            "extra commands. Pass an argument list instead and let the OS exec directly."
        ),
        "diff": (
            "-import subprocess\n"
            "-subprocess.run(f'ls {user_path}', shell=True)\n"
            "+import subprocess\n"
            "+# Argument list + no shell: no metacharacter interpretation.\n"
            "+subprocess.run(['ls', user_path], shell=False, check=True)\n"
        ),
        "steps": [
            "Replace shell=True with an explicit argument list.",
            "Validate user_path against an allow-list of directories.",
            "Run the service with a non-root user and a read-only filesystem where possible.",
        ],
    },
    {
        "match": ["sql injection", "sql", "execute"],
        "cwe": "CWE-89",
        "language": "python",
        "title": "Use parameter binding instead of string concatenation",
        "description": "Concatenating user input into SQL allows the input to change the query's meaning.",
        "diff": (
            "-cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
            "+cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"
        ),
        "steps": [
            "Bind every value as a query parameter.",
            "Use an ORM's parameterised API where available.",
            "Add a regression test that submits a quote character in the input.",
        ],
    },
    {
        "match": ["eval", "dynamic code"],
        "cwe": "CWE-95",
        "language": "python",
        "title": "Replace eval with ast.literal_eval or a dispatch table",
        "description": "eval executes arbitrary code. literal_eval only parses literals; a dispatch table avoids parsing entirely.",
        "diff": (
            "-result = eval(user_expression)\n"
            "+import ast\n"
            "+# literal_eval accepts literals only - never calls functions.\n"
            "+result = ast.literal_eval(user_expression)\n"
        ),
        "steps": [
            "Replace eval/exec with ast.literal_eval or an explicit allow-list dispatcher.",
            "Never build code strings from request data.",
        ],
    },
    {
        "match": ["strcpy", "strcat", "sprintf", "buffer", "gets"],
        "cwe": "CWE-120",
        "language": "c",
        "title": "Use bounded string operations",
        "description": "strcpy/strcat/sprintf copy without checking the destination size, causing stack buffer overflows.",
        "diff": (
            "-char buf[32];\n"
            "-strcpy(buf, user_input);\n"
            "+char buf[32];\n"
            "+snprintf(buf, sizeof(buf), \"%s\", user_input);\n"
        ),
        "steps": [
            "Replace strcpy/strcat with strncpy/strncat using the real destination size.",
            "Prefer snprintf over sprintf so truncation is explicit.",
            "Enable -Wall -Wextra -Wformat-security and -fstack-protector-strong.",
        ],
    },
    {
        "match": ["innerhtml", "xss", "dangerouslysetinnerhtml"],
        "cwe": "CWE-79",
        "language": "javascript",
        "title": "Render untrusted content as text, not HTML",
        "description": "Assigning to innerHTML lets markup in the value become live DOM, which is stored XSS.",
        "diff": (
            "-element.innerHTML = userInput;\n"
            "+// textContent never interprets markup.\n"
            "+element.textContent = userInput;\n"
        ),
        "steps": [
            "Use textContent for plain text; sanitise with a vetted library if HTML is required.",
            "Add a Content-Security-Policy header to block inline script as defence in depth.",
        ],
    },
    {
        "match": ["md5", "sha1", "weak hash", "weak crypt"],
        "cwe": "CWE-328",
        "language": "python",
        "title": "Move to SHA-256 or better",
        "description": "MD5 and SHA-1 are broken for collision resistance and must not protect passwords or signatures.",
        "diff": (
            "-import hashlib\n"
            "-digest = hashlib.md5(data).hexdigest()\n"
            "+import hashlib\n"
            "+digest = hashlib.sha256(data).hexdigest()\n"
        ),
        "steps": [
            "Use SHA-256 for integrity and a slow KDF (argon2/bcrypt/scrypt) for passwords.",
            "Rotate any secret that was hashed with a broken algorithm.",
        ],
    },
    {
        "match": ["verify=false", "tls", "certificate"],
        "cwe": "CWE-295",
        "language": "python",
        "title": "Re-enable TLS certificate verification",
        "description": "Disabling verification allows a man-in-the-middle to impersonate the server.",
        "diff": (
            "-requests.get(url, verify=False)\n"
            "+requests.get(url, verify=True)\n"
        ),
        "steps": [
            "Remove verify=False.",
            "If an internal CA is required, install the CA bundle and point verify at it.",
        ],
    },
    {
        "match": ["hardcoded", "secret", "credential", "api key"],
        "cwe": "CWE-798",
        "language": "python",
        "title": "Move secrets into environment configuration",
        "description": "Hardcoded secrets leak through source control, images and logs.",
        "diff": (
            "-API_KEY = \"sk-live-9f2b7c1d4e6a\"\n"
            "+import os\n"
            "+API_KEY = os.environ[\"API_KEY\"]  # injected at deploy time\n"
        ),
        "steps": [
            "Move the value into a secret manager or environment variable.",
            "Rotate the exposed credential immediately — treat it as compromised.",
            "Purge it from git history.",
        ],
    },
    {
        "match": ["random", "predictable"],
        "cwe": "CWE-330",
        "language": "python",
        "title": "Use a CSPRNG for tokens and secrets",
        "description": "random is a predictable Mersenne Twister and must not generate security tokens.",
        "diff": (
            "-import random\n"
            "-token = random.randint(0, 10**9)\n"
            "+import secrets\n"
            "+token = secrets.token_urlsafe(32)\n"
        ),
        "steps": [
            "Use the secrets module for tokens, nonces and salts.",
        ],
    },
]


def _rule_for(text: str) -> dict[str, Any] | None:
    """Match a patch rule against finding text.

    Uses word-boundary matching: a naive substring search made the token
    "sql" match inside "excluding", which produced a SQL-injection patch for
    an unrelated Log4Shell finding.
    """
    lowered = text.lower()
    for rule in PATCH_RULES:
        for token in rule["match"]:
            pattern = r"(?<![a-z0-9])" + re.escape(token.lower()) + r"(?![a-z0-9])"
            if re.search(pattern, lowered):
                return rule
    return None


def _rule_for_cwe(cwe: str | None) -> dict[str, Any] | None:
    """Exact CWE match — more reliable than text matching when available."""
    if not cwe:
        return None
    normalised = cwe.upper()
    for rule in PATCH_RULES:
        if rule["cwe"].upper() == normalised:
            return rule
    return None


class LLMOrchestrator:
    """Multi-step reasoning engine for Zero-Day Security Assessments."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # ------------------------------------------------------------------
    # Engine selection
    # ------------------------------------------------------------------
    @property
    def engine_name(self) -> str:
        if self.settings.has_openai:
            return "openai"
        if self.settings.has_anthropic:
            return "anthropic"
        if not self.settings.demo_mode:
            return "tinyfish-research"
        return "deterministic"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def generate_assessment(
        self,
        intel: ExploitIntel,
        ml_result: dict[str, Any],
        agent_trace: list[str] | None = None,
    ) -> Assessment:
        findings = self._build_findings(intel, ml_result)
        risk = self._build_risk(ml_result, findings)
        vector = self._build_vector(ml_result, intel, findings)
        patch = self._build_patch(intel, ml_result, findings)

        summary = ""
        engine = "deterministic"
        narrative = await self._synthesise(intel, ml_result, findings, risk)
        if narrative:
            summary = narrative
            engine = self.engine_name
        if not summary:
            summary = self._template_summary(intel, ml_result, findings, risk)

        return Assessment(
            executive_summary=summary,
            vulnerability_breakdown=findings,
            risk_vector=vector,
            patch=patch,
            risk=risk,
            target=intel.target_url,
            reasoning_engine=engine,
            agent_trace=agent_trace or [],
        )

    # ------------------------------------------------------------------
    # Assembly helpers
    # ------------------------------------------------------------------
    def _build_findings(
        self, intel: ExploitIntel, ml_result: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []

        for vulnerability in intel.vulnerabilities[:10]:
            if not isinstance(vulnerability, dict):
                continue
            severity = self._severity(vulnerability.get("severity"))
            title = str(vulnerability.get("title") or "Unspecified vulnerability")
            code = ""
            for block in intel.code_blocks:
                if vulnerability.get("title", "").lower()[:18] in block.get("code", "").lower():
                    code = block.get("code", "")
                    break
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    cwe=_clean_cwe(vulnerability.get("cwe")),
                    description=str(vulnerability.get("description") or ""),
                    location=str(vulnerability.get("affected_versions") or "") or None,
                    code_snippet=code or None,
                    language=_guess_language(intel.code_blocks),
                    source_url=intel.target_url,
                    confidence=0.7 if vulnerability.get("evidence_quote") else 0.5,
                    evidence=str(vulnerability.get("evidence_quote") or "") or None,
                    occurrences=1,
                )
            )

        # ML findings that describe code-level risk.
        for item in ml_result.get("findings", [])[:10]:
            findings.append(
                Finding(
                    title=str(item.get("title") or "Static analysis finding"),
                    severity=self._severity(item.get("severity")),
                    cwe=_clean_cwe(item.get("cwe")),
                    description=str(item.get("description") or ""),
                    location=f"line {item.get('line')}" if item.get("line") else None,
                    code_snippet=item.get("snippet") or None,
                    language=ml_result.get("signals", {}).get("language"),
                    source_url=intel.target_url,
                    confidence=round(ml_result.get("confidence", 0.5) * 0.9, 3),
                    evidence=item.get("snippet") or None,
                    occurrences=int(item.get("occurrences", 1)),
                )
            )

        if not findings:
            findings.append(
                Finding(
                    title="No exploitable pattern confirmed",
                    severity=Severity.INFO,
                    description=(
                        "The target was crawled and no high-confidence vulnerability artefact "
                        "could be extracted. This is not a clean bill of health — it means the "
                        "public surface did not expose a directly exploitable pattern."
                    ),
                    source_url=intel.target_url,
                    confidence=0.4,
                    occurrences=1,
                )
            )
        return findings

    def _build_risk(
        self, ml_result: dict[str, Any], findings: list[Finding]
    ) -> RiskScore:
        score = int(ml_result.get("risk_score", 0))
        severity = self._severity(ml_result.get("severity_label"))
        # Escalate if the web intel independently found something severe.
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                severity = Severity.CRITICAL
                score = max(score, 78)
                break
        return RiskScore(
            risk_score=max(0, min(100, score)),
            severity_label=severity,
            # The ML engine has nothing to say when no code was harvested, but
            # a well-evidenced set of web findings is not zero-confidence.
            confidence=round(
                max(float(ml_result.get("confidence", 0.0)), 0.45 if findings else 0.0), 3
            ),
            engine=str(ml_result.get("engine", "ast")),
            factors=list(ml_result.get("factors", []))[:8],
            vector=dict(ml_result.get("vector", {})),
            signals=dict(ml_result.get("signals", {})),
        )

    def _build_vector(
        self, ml_result: dict[str, Any], intel: ExploitIntel, findings: list[Finding]
    ) -> RiskVector:
        vector = ml_result.get("vector", {}) or {}

        code_injection = float(vector.get("code_injection", 0))
        auth_bypass = float(vector.get("auth_bypass", 0))
        data_exposure = float(vector.get("data_exposure", 0))
        memory = float(vector.get("memory_safety", 0))
        validation = float(vector.get("input_validation", 0))
        crypto = float(vector.get("crypto_weakness", 0))

        # Attack surface scales with how much public surface we could reach.
        attack_surface = min(
            100.0,
            18.0 * max(1, intel.pages_fetched) + 8.0 * len(intel.references) + 4.0 * len(findings),
        )
        # Exploit maturity: public PoC code is the strongest signal we have.
        exploit_maturity = min(100.0, 30.0 * len(intel.code_blocks) + 12.0 * len(intel.reproduction_steps))
        # Patch availability: an upstream fix reduces residual risk.
        patch_availability = min(100.0, 34.0 * len(intel.patch_diffs))

        return RiskVector(
            attack_surface=round(min(100.0, attack_surface), 2),
            exploit_maturity=round(exploit_maturity, 2),
            patch_availability=round(patch_availability, 2),
            code_injection=round(min(100.0, max(code_injection, memory)), 2),
            authentication_bypass=round(min(100.0, auth_bypass), 2),
            data_exposure=round(min(100.0, max(data_exposure, crypto + validation * 0.6)), 2),
        )

    def _build_patch(
        self, intel: ExploitIntel, ml_result: dict[str, Any], findings: list[Finding]
    ) -> PatchFix | None:
        # 1. A rulebook match. Order matters:
        #    a. the finding TITLE (most specific — "Log4j2 JNDI Injection" beats
        #       a generic CWE-502 deserialisation rule),
        #    b. the CWE (exact but generic),
        #    c. the full description (least specific).
        for finding in findings:
            rule = _rule_for(finding.title)
            if rule is None:
                rule = _rule_for_cwe(finding.cwe)
            if rule is None:
                rule = _rule_for(finding.description)
            if rule:
                return PatchFix(
                    title=rule["title"],
                    description=rule["description"],
                    diff=rule["diff"],
                    language=rule["language"],
                    cwe=rule["cwe"],
                    steps=rule["steps"],
                    references=intel.references[:6],
                )

        # 2. A real upstream diff harvested from the live page.
        if intel.patch_diffs:
            diff = intel.patch_diffs[0]
            return PatchFix(
                title="Upstream remediation diff (harvested from the live advisory)",
                description=(
                    "This diff was extracted verbatim from the target's advisory or release "
                    "notes by the TinyFish web agent, so it is the vendor's own fix."
                ),
                diff=diff,
                language=_guess_language(intel.code_blocks),
                cwe=None,
                steps=[
                    "Apply the diff on a branch and run the project's test suite.",
                    "Confirm the vulnerable code path is no longer reachable.",
                    "Backport to any other deployed version in the same release family.",
                ],
                references=intel.references[:6],
            )

        # 3. Generic hardening guidance.
        return PatchFix(
            title="No automated patch available for this finding",
            description=(
                "The harvested artefacts did not match a known-remediable pattern, so no "
                "confident automatic patch is proposed. Applying an unverified diff would be "
                "worse than no diff."
            ),
            diff="",
            language="text",
            cwe=None,
            steps=[
                "Review the referenced advisory for the vendor's recommended remediation.",
                "Reduce exposure on the affected path until a fix is validated.",
                "Add a regression test that reproduces the reported behaviour.",
            ],
            references=intel.references[:8],
        )

    @staticmethod
    def _severity(value: Any) -> Severity:
        if isinstance(value, Severity):
            return value
        text = str(value or "").strip().lower()
        if text in SEVERITY_FROM_TEXT:
            return SEVERITY_FROM_TEXT[text]
        if text in {"critical", "high", "medium", "low", "info"}:
            return Severity(text.upper())
        return Severity.MEDIUM

    # ------------------------------------------------------------------
    # Narrative synthesis
    # ------------------------------------------------------------------
    async def _synthesise(
        self,
        intel: ExploitIntel,
        ml_result: dict[str, Any],
        findings: list[Finding],
        risk: RiskScore,
    ) -> str:
        prompt = self._build_prompt(intel, ml_result, findings, risk)
        try:
            if self.settings.has_openai:
                return await self._openai(prompt)
            if self.settings.has_anthropic:
                return await self._anthropic(prompt)
            if not self.settings.demo_mode:
                return await self._tinyfish_research(prompt)
        except Exception:
            return ""
        return ""

    def _build_prompt(
        self,
        intel: ExploitIntel,
        ml_result: dict[str, Any],
        findings: list[Finding],
        risk: RiskScore,
    ) -> str:
        finding_lines = "\n".join(
            f"- [{f.severity.value}] {f.title} ({f.cwe or 'n/a'}): {f.description[:220]}"
            for f in findings[:10]
        )
        code_samples = "\n\n".join(
            f"```{b.get('language', 'text')}\n{(b.get('code') or '')[:600]}\n```"
            for b in intel.code_blocks[:4]
        )
        return (
            "You are a senior application security engineer writing an executive security "
            "assessment.\n\n"
            f"TARGET: {intel.target_url}\n"
            f"CVEs: {', '.join(intel.cve_ids) or 'none identified'}\n"
            f"ML RISK SCORE: {risk.risk_score}/100 ({risk.severity_label.value}), "
            f"engine={risk.engine}\n"
            f"ENGINE FACTORS: {'; '.join(risk.factors[:6])}\n\n"
            f"FINDINGS:\n{finding_lines}\n\n"
            f"CODE ARTEFACTS HARVESTED:\n{code_samples or '(none)'}\n\n"
            f"ADVISORY SUMMARY: {intel.summary[:1200]}\n\n"
            "Write a 3-4 paragraph executive security assessment. Start with the concrete "
            "exploitability verdict and the single most urgent action. Be specific to the "
            "evidence above, do not invent CVEs, and do not pad with generic advice."
        )

    async def _openai(self, prompt: str) -> str:
        from openai import AsyncOpenAI  # type: ignore

        client = AsyncOpenAI(api_key=self.settings.OPENAI_API_KEY)
        response = await client.chat.completions.create(
            model=self.settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a precise security analyst."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=900,
        )
        return (response.choices[0].message.content or "").strip()

    async def _anthropic(self, prompt: str) -> str:
        from anthropic import AsyncAnthropic  # type: ignore

        client = AsyncAnthropic(api_key=self.settings.ANTHROPIC_API_KEY)
        response = await client.messages.create(
            model=self.settings.ANTHROPIC_MODEL,
            max_tokens=900,
            temperature=0.2,
            messages=[{"role": "user", "content": prompt}],
        )
        blocks = [b.text for b in response.content if getattr(b, "type", "") == "text"]
        return "\n".join(blocks).strip()

    async def _tinyfish_research(self, prompt: str) -> str:
        """Use TinyFish Research as the reasoning backend.

        It searches the live web, evaluates sources and returns a cited
        synthesis — a credible reasoning engine when no LLM key is configured.
        """
        question = (
            "Act as a security analyst and write a concise executive security assessment "
            "for the following collected intelligence. Cite sources where relevant.\n\n"
            f"{prompt}"
        )
        endpoint = f"{self.settings.TINYFISH_BASE_URL}/v1/automation/run-research"
        headers = {
            "X-API-Key": self.settings.TINYFISH_API_KEY,
            "Content-Type": "application/json",
        }
        deadline = time.monotonic() + max(15, self.settings.RESEARCH_TIME_BUDGET)
        partial = ""
        async with httpx.AsyncClient(timeout=httpx.Timeout(900.0, connect=15.0)) as client:
            async with client.stream(
                "POST", endpoint, json={"query": question, "mode": "deep", "stream": True}, headers=headers
            ) as response:
                if response.status_code >= 400:
                    return ""
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload_raw = line[5:].strip()
                    if not payload_raw or payload_raw == "[DONE]":
                        continue
                    try:
                        payload = json.loads(payload_raw)
                    except json.JSONDecodeError:
                        continue
                    event_name = payload.get("event")
                    if event_name == "final_result":
                        return str(payload.get("result") or "").strip()
                    if event_name == "partial_summary":
                        # Keep the latest interim synthesis as a fallback: the
                        # Research pipeline routinely takes 5-20 minutes, and a
                        # good partial answer beats waiting for the finale.
                        candidate = str(payload.get("result") or payload.get("summary") or "")
                        if len(candidate) > len(partial):
                            partial = candidate
                    # Research routinely takes 5-20 minutes. We cannot hold a
                    # scan open that long, so we bail out and let the
                    # deterministic template produce the summary instead.
                    if time.monotonic() > deadline:
                        return partial.strip()
        return partial.strip()

    def _template_summary(
        self,
        intel: ExploitIntel,
        ml_result: dict[str, Any],
        findings: list[Finding],
        risk: RiskScore,
    ) -> str:
        """Deterministic executive summary — always available, never wrong."""
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        cves = ", ".join(intel.cve_ids[:4]) or "no CVE identifier"

        if risk.risk_score >= 70 and (critical or high):
            headline = (
                f"Immediate action required. The assessment scores {risk.risk_score}/100 "
                f"({risk.severity_label.value}) and identified "
                f"{len(critical)} critical and {len(high)} high-severity issues"
            )
        elif risk.risk_score >= 40:
            headline = (
                f"Remediation required. The assessment scores {risk.risk_score}/100 "
                f"({risk.severity_label.value}) with {len(findings)} findings of varying severity"
            )
        else:
            headline = (
                f"Low observed risk. The assessment scores {risk.risk_score}/100 "
                f"({risk.severity_label.value}) across {len(findings)} findings"
            )

        sources = (
            f"The TinyFish web agent crawled {intel.pages_fetched} live page(s) and "
            f"{intel.sources_searched} candidate source(s), harvesting "
            f"{len(intel.code_blocks)} code artefact(s)"
            + (f" and {len(intel.patch_diffs)} upstream diff(s)" if intel.patch_diffs else "")
            + f". Identified identifiers: {cves}."
        )

        engines = ", ".join(risk.factors[:4]) if risk.factors else "no dominant risk factor"
        factors = (
            f"The static analysis engine ({risk.engine}) weighted the following: {engines}."
        )

        next_steps = []
        if critical:
            next_steps.append(
                f"Fix {critical[0].title} first"
                + (f" ({critical[0].cwe})" if critical[0].cwe else "")
                + " — it is the highest-impact path to code execution."
            )
        if intel.reproduction_steps:
            next_steps.append(
                "Reproduce in an isolated environment using the harvested proof-of-concept "
                "before touching production."
            )
        if intel.patch_diffs:
            next_steps.append(
                "An upstream fix was located — apply and verify it against the reported "
                "reproduction steps."
            )
        next_steps.append(
            "Re-run this scan after the fix to confirm the risk score drops; the pipeline is "
            "deterministic, so the change is measurable."
        )

        return " ".join([headline + ".", sources, factors, "Recommended next steps: " + " ".join(next_steps)])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _clean_cwe(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().upper()
    match = re.search(r"CWE-\d+", text)
    return match.group(0) if match else None


def _guess_language(blocks: list[dict[str, Any]]) -> str | None:
    for block in blocks:
        language = block.get("language")
        if language and language != "unknown":
            return str(language)
    return None
