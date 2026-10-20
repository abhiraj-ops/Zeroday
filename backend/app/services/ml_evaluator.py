"""CodeBERT + AST vulnerability evaluator.

Two engines, fused into one normalised risk score:

1. **AST / pattern scanner** — real static analysis. Python is parsed with
   the stdlib ``ast`` module (so it understands structure, not just text);
   C/C++/JavaScript/TypeScript use a curated pattern table. This engine does
   the heavy lifting and is always available.

2. **CodeBERT embeddings** (``microsoft/codebert-base``) — mean-pooled
   contextual embeddings are compared against a small set of curated
   *vulnerable* and *safe* exemplars using cosine similarity. A snippet that
   looks semantically closer to known-vulnerable code than to known-safe code
   raises the risk score.

   Honest framing: this is embedding-similarity classification, **not** a
   fine-tuned classifier, because we have no labelled CVE corpus to train on.
   The README says so explicitly. The model is loaded lazily so the service
   boots instantly and works with the AST engine alone when torch/transformers
   or the model weights are unavailable.
"""

from __future__ import annotations

import ast
import math
import re
import threading
from typing import Any

from app.config import Settings

# ---------------------------------------------------------------------------
# Risk taxonomy
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {
    "CRITICAL": 32.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 5.0,
    "INFO": 1.0,
}

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

RADAR_DIMENSIONS = [
    "code_injection",
    "memory_safety",
    "input_validation",
    "crypto_weakness",
    "auth_bypass",
    "data_exposure",
]

# ---------------------------------------------------------------------------
# Python AST rules
# ---------------------------------------------------------------------------
# Each rule: (node-name, cwe, severity, dimension, title, description)
PYTHON_RULES: list[tuple[str, str, str, str, str, str]] = [
    ("Eval", "CWE-95", "CRITICAL", "code_injection",
     "Dynamic code evaluation", "eval()/exec() executes attacker-controllable strings as code."),
    ("Exec", "CWE-95", "CRITICAL", "code_injection",
     "Dynamic code execution", "eval()/exec() executes attacker-controllable strings as code."),
    ("Import", "CWE-95", "HIGH", "code_injection",
     "Dynamic module import", "__import__() can be redirected to load arbitrary modules."),
    ("Lambda", "CWE-95", "LOW", "code_injection",
     "Lambda expression", "Lambdas are not directly exploitable but often appear in injection sinks."),
    ("Assert", "CWE-617", "LOW", "input_validation",
     "assert used as validation", "assert is stripped under -O, so it is not a real security check."),
]


class CodeBETAstScanner:
    """Static vulnerability analysis with optional CodeBERT semantic scoring."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._tokenizer: Any = None
        self._model: Any = None
        self._torch: Any = None
        self._lock = threading.Lock()
        self._load_attempted = False
        self._exemplars: dict[str, list[Any]] = {}

    # ------------------------------------------------------------------
    # CodeBERT lifecycle
    # ------------------------------------------------------------------
    @property
    def codebert_available(self) -> bool:
        return self._model is not None

    def _ensure_codebert(self) -> bool:
        """Lazily load CodeBERT. Never raises — failure means 'AST only'."""
        if self._model is not None:
            return True
        with self._lock:
            if self._model is not None:
                return True
            if self._load_attempted or not self.settings.ENABLE_CODEBERT:
                return False
            self._load_attempted = True
            try:
                import torch  # type: ignore
                from transformers import AutoModel, AutoTokenizer  # type: ignore

                torch.set_num_threads(max(1, self.settings.TORCH_THREADS))
                tokenizer = AutoTokenizer.from_pretrained(self.settings.CODEBERT_MODEL)
                model = AutoModel.from_pretrained(self.settings.CODEBERT_MODEL)
                model.eval()

                self._torch = torch
                self._tokenizer = tokenizer
                self._model = model
                return True
            except Exception:
                # Missing weights, no network, or torch absent — AST still works.
                self._model = None
                return False

    def _embed(self, texts: list[str]) -> list[Any]:
        """Mean-pooled CodeBERT embeddings for a list of snippets."""
        if not self._ensure_codebert():
            return []
        torch = self._torch
        encoded = self._tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=256,
            return_tensors="pt",
        )
        with torch.no_grad():
            output = self._model(**encoded)
        hidden = output.last_hidden_state
        mask = encoded["attention_mask"].unsqueeze(-1).float()
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        return pooled

    @staticmethod
    def _cosine(a: Any, b: Any) -> float:
        num = float((a * b).sum())
        den = float(a.norm() * b.norm())
        return num / den if den > 1e-9 else 0.0

    # ------------------------------------------------------------------------
    # Curated exemplars for embedding-similarity classification
    # ------------------------------------------------------------------------
    VULNERABLE_EXEMPLARS = [
        "import os\nos.system('ls ' + user_input)",
        "import subprocess\nsubprocess.run(cmd, shell=True)",
        "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
        "data = pickle.loads(untrusted_bytes)",
        "config = yaml.load(payload, Loader=yaml.Loader)",
        "eval(user_supplied_expression)",
        "strcpy(dest, user_supplied_string)",
        "char buf[16]; gets(buf);",
        "char buf[32]; sprintf(buf, '%s', input);",
    ]

    SAFE_EXEMPLARS = [
        "import subprocess\nsubprocess.run(['ls', path], check=True)",
        "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
        "data = json.loads(payload.decode('utf-8'))",
        "config = yaml.safe_load(payload)",
        "result = ast.literal_eval(user_supplied_expression)",
        "snprintf(buf, sizeof(buf), '%s', input);",
        "hashlib.sha256(password.encode()).hexdigest()",
        "secrets.token_urlsafe(32)",
    ]

    def _semantic_risk(self, code: str) -> tuple[float | None, str]:
        """Cosine-similarity classification of the snippet against exemplars.

        Returns ``(score, engine_note)``. ``score`` is 0-1.
        """
        if not self._ensure_codebert():
            return None, "codebert unavailable — AST engine only"

        snippet = code[:2000]
        try:
            if not self._exemplars:
                vuln_emb = self._embed(self.VULNERABLE_EXEMPLARS)
                safe_emb = self._embed(self.SAFE_EXEMPLARS)
                if not vuln_emb or not safe_emb:
                    return None, "codebert embedding failed"
                self._exemplars = {"vuln": vuln_emb, "safe": safe_emb}

            target = self._embed([snippet])[0]
            vuln_sim = max(self._cosine(target, e) for e in self._exemplars["vuln"])
            safe_sim = max(self._cosine(target, e) for e in self._exemplars["safe"])

            # Map the similarity margin into 0-1.
            margin = vuln_sim - safe_sim
            score = max(0.0, min(1.0, 0.5 + margin * 1.6))
            return score, f"codebert similarity: vulnerable={vuln_sim:.3f} safe={safe_sim:.3f}"
        except Exception as exc:
            return None, f"codebert error: {type(exc).__name__}"

    # ------------------------------------------------------------------
    # Python AST analysis
    # ------------------------------------------------------------------
    def _analyse_python(self, code: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # A parse failure is not a vulnerability. Returning nothing here
            # keeps a Java or shell snippet from polluting the findings list.
            return findings

        def add(title, severity, cwe, dimension, description, node):
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "dimension": dimension,
                    "description": description,
                    "line": getattr(node, "lineno", None),
                    "snippet": _snippet_for(code, node),
                    "occurrences": 1,
                }
            )

        for node in ast.walk(tree):
            # --- eval / exec / compile / __import__ --------------------
            if isinstance(node, ast.Call):
                fn = _called_name(node.func)

                if fn in {"eval", "exec", "compile"}:
                    add(
                        f"Dynamic code execution via {fn}()",
                        "CRITICAL", "CWE-95", "code_injection",
                        f"{fn}() executes a string as code. If any part of the argument is "
                        "attacker-influenced this is remote code execution.",
                        node,
                    )

                if fn == "__import__":
                    add(
                        "Dynamic import via __import__()",
                        "HIGH", "CWE-95", "code_injection",
                        "__import__() loads a module chosen at runtime.",
                        node,
                    )

                # --- dangerous deserialisation --------------------------
                if fn in {"loads", "load"}:
                    container = _called_name(node.func, dotted=True)
                    if "pickle" in container or "marshal" in container:
                        add(
                            "Unsafe deserialisation",
                            "CRITICAL", "CWE-502", "code_injection",
                            "pickle/marshal deserialisation executes attacker-controlled opcodes.",
                            node,
                        )
                    if "yaml" in container and not _yaml_safe_loader(node):
                        add(
                            "Unsafe YAML deserialisation",
                            "CRITICAL", "CWE-502", "code_injection",
                            "yaml.load() without SafeLoader can construct arbitrary Python objects.",
                            node,
                        )

                # --- command injection ---------------------------------
                if fn in {"system", "popen", "spawnl", "spawnv"} and "os" in _called_name(node.func, dotted=True):
                    add(
                        "Shell command execution",
                        "CRITICAL", "CWE-78", "code_injection",
                        "OS command execution with potentially untrusted arguments.",
                        node,
                    )

                if "subprocess" in _called_name(node.func, dotted=True):
                    shell_true = any(
                        kw.arg == "shell" and _is_true(kw.value) for kw in node.keywords
                    )
                    if shell_true:
                        add(
                            "Shell command injection (shell=True)",
                            "CRITICAL", "CWE-78", "code_injection",
                            "shell=True passes the command through a shell, so metacharacters "
                            "in any input become command injection.",
                            node,
                        )
                    else:
                        add(
                            "Subprocess invocation",
                            "LOW", "CWE-78", "code_injection",
                            "subprocess call — verify arguments are passed as a list, not a string.",
                            node,
                        )

                # --- SQL injection --------------------------------------
                if fn == "execute" and _looks_like_sql(node):
                    if _has_concatenated_argument(node):
                        add(
                            "SQL injection via string concatenation",
                            "CRITICAL", "CWE-89", "input_validation",
                            "SQL query is built by concatenating values instead of using "
                            "parameter binding.",
                            node,
                        )
                    else:
                        add(
                            "SQL execution",
                            "LOW", "CWE-89", "input_validation",
                            "Query execution — confirm it uses parameter binding.",
                            node,
                        )

                # --- weak crypto ----------------------------------------
                if fn in {"md5", "sha1"} and "hashlib" in _called_name(node.func, dotted=True):
                    add(
                        f"Weak hash algorithm ({fn})",
                        "MEDIUM", "CWE-328", "crypto_weakness",
                        f"{fn.upper()} is broken for collision resistance. Use SHA-256+.",
                        node,
                    )

                if fn == "mktemp" and "tempfile" in _called_name(node.func, dotted=True):
                    add(
                        "Insecure temporary file (mktemp)",
                        "MEDIUM", "CWE-377", "data_exposure",
                        "mktemp is race-prone. Use tempfile.NamedTemporaryFile.",
                        node,
                    )

                # --- TLS verification disabled --------------------------
                if kw_is_true(node, "verify", False):
                    add(
                        "TLS certificate verification disabled",
                        "HIGH", "CWE-295", "auth_bypass",
                        "verify=False disables certificate validation and enables MITM attacks.",
                        node,
                    )

                # --- assert used as validation --------------------------
                if fn == "assert":
                    add(
                        "assert used as a validation check",
                        "LOW", "CWE-617", "input_validation",
                        "assert is removed when Python runs with -O.",
                        node,
                    )

            # --- random used for security tokens -----------------------
            if isinstance(node, ast.Attribute) and node.attr in {"random", "randint", "choice", "uniform"}:
                if isinstance(node.value, ast.Name) and node.value.id == "random":
                    add(
                        "Non-cryptographic randomness",
                        "MEDIUM", "CWE-330", "crypto_weakness",
                        "random is predictable and must not be used for tokens or secrets.",
                        node,
                    )

            # --- hardcoded credentials ---------------------------------
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _secret_name(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            if len(node.value.value) >= 8:
                                add(
                                    f"Hardcoded credential ({target.id})",
                                    "HIGH", "CWE-798", "data_exposure",
                                    "A secret appears to be hardcoded in source.",
                                    node,
                                )

            # --- broad exception swallowing -----------------------------
            if isinstance(node, ast.ExceptHandler):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    add(
                        "Silently swallowed exception",
                        "LOW", "CWE-390", "input_validation",
                        "Errors are discarded, hiding failed validation and security checks.",
                        node,
                    )

            # --- XML parsing (XXE) --------------------------------------
            if isinstance(node, ast.Call):
                fn = _called_name(node.func, dotted=True)
                if "etree" in fn and "fromstring" in fn or "parse" in fn and "etree" in fn:
                    add(
                        "XML parsing without defusedxml",
                        "MEDIUM", "CWE-611", "input_validation",
                        "xml parsers can resolve external entities. Use defusedxml.",
                        node,
                    )

        return findings

    # ------------------------------------------------------------------
    # Multi-language pattern rules
    # ------------------------------------------------------------------
    PATTERN_RULES: list[tuple[str, str, str, str, str, str]] = [
        # (regex, language-set, cwe, severity, dimension, title)
        (r"\beval\s*\(", "js,ts", "CWE-95", "CRITICAL", "code_injection", "eval() executes a string as code"),
        (r"new\s+Function\s*\(", "js,ts", "CWE-95", "CRITICAL", "code_injection", "new Function() is equivalent to eval()"),
        (r"\.innerHTML\s*=", "js,ts", "CWE-79", "HIGH", "code_injection", "innerHTML assignment can inject scripts"),
        (r"dangerouslySetInnerHTML", "js,ts", "CWE-79", "HIGH", "code_injection", "dangerouslySetInnerHTML can inject scripts"),
        (r"document\.write\s*\(", "js,ts", "CWE-79", "HIGH", "code_injection", "document.write can inject markup"),
        (r"child_process\.exec\s*\(", "js,ts", "CWE-78", "CRITICAL", "code_injection", "child_process.exec runs a shell command"),
        (r"require\(['\"]child_process", "js,ts", "CWE-78", "HIGH", "code_injection", "child_process imported"),
        (r"rejectUnauthorized\s*:\s*false", "js,ts", "CWE-295", "HIGH", "auth_bypass", "TLS verification disabled"),
        (r"Math\.random\s*\(\s*\)", "js,ts", "CWE-330", "MEDIUM", "crypto_weakness", "Math.random is not cryptographically secure"),
        (r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", "js,ts", "CWE-328", "MEDIUM", "crypto_weakness", "MD5/SHA-1 are broken hash algorithms"),
        (r"\bstrcpy\s*\(", "c,cpp", "CWE-120", "CRITICAL", "memory_safety", "strcpy has no bounds checking"),
        (r"\bstrcat\s*\(", "c,cpp", "CWE-120", "CRITICAL", "memory_safety", "strcat has no bounds checking"),
        (r"\bgets\s*\(", "c,cpp", "CWE-242", "CRITICAL", "memory_safety", "gets() cannot be used safely"),
        (r"\bsprintf\s*\(", "c,cpp", "CWE-120", "HIGH", "memory_safety", "sprintf can overflow the destination buffer"),
        (r"\bvsprintf\s*\(", "c,cpp", "CWE-120", "CRITICAL", "memory_safety", "vsprintf can overflow the destination buffer"),
        (r"\bmemcpy\s*\(", "c,cpp", "CWE-120", "HIGH", "memory_safety", "memcpy size must be validated"),
        (r"\balloca\s*\(", "c,cpp", "CWE-770", "MEDIUM", "memory_safety", "alloca can overflow the stack"),
        (r"\bsystem\s*\(", "c,cpp", "CWE-78", "CRITICAL", "code_injection", "system() invokes a shell"),
        (r"\batoi\s*\(", "c,cpp", "CWE-20", "MEDIUM", "input_validation", "atoi does not report conversion errors"),
        (r"\bstrcpy_s\s*\(", "c,cpp", "CWE-120", "LOW", "memory_safety", "bounded copy — verify size argument"),
        (r"\batoi\b", "c,cpp", "CWE-20", "LOW", "input_validation", "unchecked numeric conversion"),
        # Java
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "java", "CWE-78", "CRITICAL", "code_injection", "Runtime.exec runs an OS command"),
        (r"new\s+ObjectInputStream\s*\(", "java", "CWE-502", "CRITICAL", "code_injection", "Java deserialisation of untrusted data"),
        (r"Class\.forName\s*\(", "java", "CWE-470", "HIGH", "code_injection", "Reflective class loading from untrusted input"),
        (r"getInstance\s*\(\s*[\"']MD5[\"']", "java", "CWE-328", "MEDIUM", "crypto_weakness", "MD5 is a broken hash algorithm"),
        (r"getInstance\s*\(\s*[\"']SHA-?1[\"']", "java", "CWE-328", "MEDIUM", "crypto_weakness", "SHA-1 is a broken hash algorithm"),
        (r"TrustManager|HostnameVerifier|setDefaultHostnameVerifier", "java", "CWE-295", "HIGH", "auth_bypass", "Custom TLS trust manager may disable verification"),
        # --- exploit indicators -------------------------------------------
        # Harvested proof-of-concept code is attack code, not vulnerable
        # application code, so the classic sink rules rarely fire. These
        # recognise the exploit primitives themselves.
        (r"\$\{\s*jndi\s*:", "any", "CWE-917", "CRITICAL", "code_injection", "JNDI lookup payload (Log4Shell-style remote class loading)"),
        (r"(?:ldap|rmi|dns|ldaps)://", "any", "CWE-918", "HIGH", "code_injection", "External reference to a remote endpoint"),
        (r"/bin/(?:ba)?sh\s+-i", "any", "CWE-78", "CRITICAL", "code_injection", "Reverse shell payload"),
        (r"\bnc\s+(?:-[a-z]*e\b|-e\s)", "any", "CWE-78", "CRITICAL", "code_injection", "Netcat reverse shell payload"),
        (r"socket\.socket\s*\(", "python", "CWE-78", "MEDIUM", "code_injection", "Raw socket usage"),
        (r"b64decode\s*\(", "any", "CWE-506", "MEDIUM", "code_injection", "Encoded payload decoded at runtime"),
        (r"base64\.b64decode\s*\(", "python", "CWE-506", "MEDIUM", "code_injection", "Encoded payload decoded at runtime"),
        (r"__import__\s*\(", "python", "CWE-95", "HIGH", "code_injection", "Dynamic import of a runtime-chosen module"),
        (r"exec\s*\(\s*(?:compile|base64|bytes|request|payload|cmd)", "python", "CWE-95", "CRITICAL", "code_injection", "Dynamic execution of a constructed payload"),
        (r"(?:http|https)://[^\s\"']*\$\{", "any", "CWE-918", "MEDIUM", "code_injection", "Dynamic URL construction (possible SSRF)"),
    ]

    SECRET_PATTERN = re.compile(
        r"(?i)(api[_-]?key|secret|password|passwd|token|private[_-]?key|credential)\s*[:=]\s*"
        r"['\"][^'\"]{8,}['\"]"
    )

    def _analyse_patterns(self, code: str, language: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for pattern, langs, cwe, severity, dimension, title in self.PATTERN_RULES:
            # "any" applies to every language.
            if "any" not in langs and language not in langs.split(","):
                continue
            match = re.search(pattern, code)
            if not match:
                continue
            line_no = code[: match.start()].count("\n") + 1
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "dimension": dimension,
                    "description": f"Pattern matched `{match.group(0).strip()}` in a {language} snippet.",
                    "line": line_no,
                    "snippet": _line_at(code, line_no),
                    "occurrences": 1,
                }
            )

        secret = self.SECRET_PATTERN.search(code)
        if secret:
            line_no = code[: secret.start()].count("\n") + 1
            findings.append(
                {
                    "title": "Hardcoded credential in source",
                    "severity": "HIGH",
                    "cwe": "CWE-798",
                    "dimension": "data_exposure",
                    "description": "A secret appears to be hardcoded. Move it to environment configuration.",
                    "line": line_no,
                    "snippet": _line_at(code, line_no),
                    "occurrences": 1,
                }
            )
        return findings

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------
    @staticmethod
    def detect_language(code: str) -> str:
        """Best-effort language detection.

        Order matters: Java and C are checked before Python and JS because a
        Java snippet contains ``import`` and ``class``, which the naive
        Python test also matched.
        """
        if re.search(r"^\s*#include\s*[<\"]", code, re.MULTILINE):
            return "c"
        if re.search(
            r"(import\s+java\.|public\s+(static\s+)?(class|interface|enum)\b|"
            r"System\.out\.print|public\s+static\s+void\s+main)",
            code,
        ):
            return "java"
        if re.search(r"^\s*(def|class)\s+\w+\s*[(:]", code, re.MULTILINE) or re.search(
            r"^\s*(from\s+\S+\s+)?import\s+\w+", code, re.MULTILINE
        ):
            if re.search(r"\bself\.|\belif\b|\bNone\b|\bTrue\b", code):
                return "python"
        if re.search(
            r"(=>|\bfunction\s*[\w]*\s*\(|\b(?:var|let|const)\s+\w+\s*=|"
            r"\brequire\s*\(|console\.log|document\.|window\.|\.innerHTML|"
            r"\.textContent|\bexport\s+(?:default|\{|const|function)|"
            r"\bimport\s+.*\bfrom\s+['\"])",
            code,
        ):
            return "js"
        if re.search(r"\bfunc\s+\w+\s*\(", code):
            return "go"
        if re.search(r"\bfn\s+\w+\s*\(|let\s+mut\s+", code):
            return "rust"
        if re.search(r"^\s*(def|class|import)\s", code, re.MULTILINE):
            return "python"
        return "python" if code.strip() else "unknown"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze_code_snippet(self, code: str) -> dict[str, Any]:
        """Analyse a code snippet and return a normalised risk assessment.

        Returns a dict with ``risk_score`` (0-100), ``severity_label``,
        ``confidence``, ``findings``, per-dimension ``vector`` and the
        ``engine`` that produced it.
        """
        if not code or not code.strip():
            return {
                "risk_score": 0,
                "severity_label": "INFO",
                "confidence": 0.0,
                "engine": "ast",
                "findings": [],
                "factors": ["No code supplied for analysis."],
                "vector": {d: 0.0 for d in RADAR_DIMENSIONS},
                "signals": {"language": "unknown", "lines": 0, "characters": 0},
            }

        snippet = code[: self.settings.MAX_SNIPPET_CHARS]
        language = self.detect_language(snippet)

        findings: list[dict[str, Any]] = []
        if language == "python":
            findings.extend(self._analyse_python(snippet))
        findings.extend(self._analyse_patterns(snippet, language))

        # Collapse repeated occurrences of the same weakness class.
        unique = _merge_by_class(findings)

        # Weighting by occurrence count keeps the score identical to the
        # pre-merge behaviour, where each hit was its own row.
        total = sum(
            SEVERITY_WEIGHT.get(f["severity"], 5.0) * f.get("occurrences", 1)
            for f in unique
        )
        # Saturating curve: many findings raise the score but never past 100.
        ast_score = 100.0 * (1.0 - math.exp(-total / 55.0))

        semantic, note = self._semantic_risk(snippet)
        engine = "ast"
        if semantic is not None:
            engine = "codebert+ast"
            ast_score = 0.78 * ast_score + 0.22 * (semantic * 100.0)

        risk_score = int(round(max(0.0, min(100.0, ast_score))))

        # --- severity label --------------------------------------------
        max_sev = "INFO"
        for finding in unique:
            if SEVERITY_ORDER.index(finding["severity"]) > SEVERITY_ORDER.index(max_sev):
                max_sev = finding["severity"]
        severity_label = self._severity_from_score(risk_score, max_sev)

        # Keep the number and the label consistent. A single CRITICAL finding
        # floors the label, so the score has to clear the same bar - otherwise
        # the UI shows "44/100 CRITICAL", which reads like a bug.
        score_floor = {
            "CRITICAL": 78,
            "HIGH": 62,
            "MEDIUM": 45,
            "LOW": 25,
            "INFO": 0,
        }.get(severity_label, 0)
        risk_score = int(max(risk_score, score_floor))

        # --- radar vector ----------------------------------------------
        vector = {d: 0.0 for d in RADAR_DIMENSIONS}
        for finding in unique:
            dimension = finding.get("dimension") or "input_validation"
            if dimension in vector:
                vector[dimension] = min(
                    100.0,
                    vector[dimension]
                    + SEVERITY_WEIGHT.get(finding["severity"], 5.0)
                    * 2.2
                    * finding.get("occurrences", 1),
                )
        if semantic is not None:
            vector["code_injection"] = min(
                100.0, vector["code_injection"] + semantic * 18.0
            )

        # --- confidence + factors ---------------------------------------
        observed = sum(f.get("occurrences", 1) for f in unique)
        confidence = min(0.95, 0.35 + 0.12 * observed + (0.2 if engine == "codebert+ast" else 0.0))
        factors = [f["title"] for f in unique[:6]]
        if not factors:
            factors = ["No dangerous patterns detected in this snippet."]
        if semantic is not None:
            factors.append(note)

        return {
            "risk_score": risk_score,
            "severity_label": severity_label,
            "confidence": round(confidence, 3),
            "engine": engine,
            "findings": unique,
            "factors": factors,
            "vector": {k: round(v, 2) for k, v in vector.items()},
            "signals": {
                "language": language,
                "lines": snippet.count("\n") + 1,
                "characters": len(snippet),
                "ast_weight": round(total, 2),
                "semantic_note": note,
            },
        }

    @staticmethod
    def _severity_from_score(score: int, max_finding_severity: str) -> str:
        """Score drives the label, but a single CRITICAL finding floors it."""
        if max_finding_severity == "CRITICAL":
            return "CRITICAL"
        if score >= 72:
            return "CRITICAL" if max_finding_severity == "HIGH" and score >= 82 else "HIGH"
        if score >= 48:
            return "MEDIUM"
        if score >= 22:
            return "LOW"
        return "INFO"

    def analyze_many(self, code_blocks: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyse several code blocks and return the aggregate worst case."""
        analyses = [self.analyze_code_snippet(b.get("code", "")) for b in code_blocks if b.get("code")]
        if not analyses:
            return {
                "risk_score": 0,
                "severity_label": "INFO",
                "confidence": 0.0,
                "engine": "ast",
                "findings": [],
                "factors": ["No code blocks were harvested from the target."],
                "vector": {d: 0.0 for d in RADAR_DIMENSIONS},
                "signals": {"blocks": 0},
            }

        worst = max(analyses, key=lambda a: a["risk_score"])
        merged_vector = {d: 0.0 for d in RADAR_DIMENSIONS}
        for analysis in analyses:
            for key, value in analysis["vector"].items():
                merged_vector[key] = max(merged_vector[key], value)

        all_findings: list[dict[str, Any]] = []
        for analysis in analyses:
            all_findings.extend(analysis["findings"])

        # Collapse the same weakness class seen in several harvested artefacts.
        unique_findings = _merge_by_class(all_findings)

        return {
            "risk_score": worst["risk_score"],
            "severity_label": worst["severity_label"],
            "confidence": worst["confidence"],
            "engine": worst["engine"],
            "findings": unique_findings,
            "factors": worst["factors"],
            "vector": {k: round(v, 2) for k, v in merged_vector.items()},
            "signals": {
                "blocks": len(analyses),
                "worst_score": worst["risk_score"],
                "engines": sorted({a["engine"] for a in analyses}),
            },
        }


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------
def _merge_by_class(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse findings that describe the same weakness class.

    The key is the class (title + CWE), not the position in the file. The same
    JNDI payload turns up in every harvested proof-of-concept, so keying on
    the line number reported one bug once per artefact and the findings list
    read as a wall of duplicates. Occurrences are counted instead, so the
    information survives the collapse.
    """
    merged: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = f"{finding.get('title', '')}|{finding.get('cwe') or ''}"
        existing = merged.get(key)
        if existing is None:
            merged[key] = {**finding, "occurrences": finding.get("occurrences", 1)}
            continue
        existing["occurrences"] = existing.get("occurrences", 1) + finding.get("occurrences", 1)
    return list(merged.values())


def _called_name(node: ast.AST, dotted: bool = False) -> str:
    """Best-effort name of a called function, e.g. ``os.system``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _called_name(node.value, dotted=True) if dotted else ""
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _called_name(node.func, dotted=dotted)
    return ""


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def kw_is_true(call: ast.Call, arg: str, default: bool = False) -> bool:
    for keyword in call.keywords:
        if keyword.arg == arg:
            return _is_true(keyword.value)
    return default


def _yaml_safe_loader(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "Loader":
            name = _called_name(keyword.value, dotted=True)
            return "safe" in name.lower()
    return False


def _looks_like_sql(node: ast.Call) -> bool:
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        lowered = first.value.lower()
        return any(
            kw in lowered
            for kw in ("select", "insert", "update", "delete", "drop", "union", "where")
        )
    if isinstance(first, (ast.JoinedStr, ast.BinOp)):
        return True
    return False


def _has_concatenated_argument(node: ast.Call) -> bool:
    for argument in node.args:
        if isinstance(argument, ast.BinOp) and isinstance(argument.op, ast.Add):
            return True
        if isinstance(argument, ast.JoinedStr):
            return True
        if isinstance(argument, ast.BinOp):
            return True
    return False


def _secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in ("password", "passwd", "secret", "api_key", "apikey", "token", "private_key")
    )


def _snippet_for(code: str, node: ast.AST, context: int = 1) -> str:
    lines = code.splitlines()
    start = max(0, getattr(node, "lineno", 1) - 1 - context)
    end = min(len(lines), getattr(node, "lineno", 1) + context)
    return "\n".join(lines[start:end]).strip()


def _line_at(code: str, line_no: int) -> str:
    lines = code.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""
