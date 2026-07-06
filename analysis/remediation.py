# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Remediation Framework — Phase 3.

The one-line ``remediation`` string a scanner attaches to a finding is
enough to acknowledge a bug, not enough to fix it well.  A developer under
time pressure needs: the concrete steps, the mistakes people make while
"fixing" it (that reintroduce the bug), a snippet in *their* language, and
a way to prove the fix actually holds so it doesn't regress.

This framework turns each finding into that: a prioritised
:class:`RemediationGuidance` with ordered fix steps, best practices, common
mistakes to avoid, verification/regression checks, and a code example
selected for the technology stack WebShield fingerprinted (falling back to
language-agnostic guidance when the stack is unknown).

Static and deterministic — templates keyed on :class:`VulnType`, tailored
by the detected ``language`` only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models.vulnerability import Severity, Vulnerability, VulnType

_PRIORITY = {
    Severity.CRITICAL: "Immediate",
    Severity.HIGH: "Immediate",
    Severity.MEDIUM: "Planned",
    Severity.LOW: "Backlog",
    Severity.INFO: "Backlog",
}


@dataclass
class RemediationTemplate:
    summary: str
    steps: List[str]
    best_practices: List[str]
    common_mistakes: List[str]
    verification: List[str]


# Language-normalisation for fingerprint values → example keys.
def _norm_lang(language: Optional[str]) -> str:
    if not language:
        return "generic"
    l = language.strip().lower()
    aliases = {
        "js": "node", "javascript": "node", "nodejs": "node", "express": "node",
        "py": "python", "django": "python", "flask": "python",
        "dotnet": "dotnet", ".net": "dotnet", "asp.net": "dotnet", "c#": "dotnet",
        "rails": "ruby", "ror": "ruby",
        "spring": "java", "jsp": "java",
    }
    for key in ("python", "php", "java", "node", "ruby", "dotnet"):
        if key in l:
            return key
    return aliases.get(l, "generic")


# ─────────────────────────────────────────────────────────────────────────────
# Templates
# ─────────────────────────────────────────────────────────────────────────────

_GENERIC = RemediationTemplate(
    summary="Validate and constrain all untrusted input, apply least privilege, "
            "and add automated coverage so the issue cannot silently return.",
    steps=[
        "Identify every entry point that reaches the affected code path.",
        "Apply input validation / output encoding / access checks appropriate to the sink.",
        "Re-test with the payload from the finding to confirm the fix.",
    ],
    best_practices=[
        "Prefer allow-lists over deny-lists.",
        "Fail closed, not open.",
    ],
    common_mistakes=[
        "Fixing only the one endpoint in the report while leaving sibling endpoints vulnerable.",
        "Relying on client-side validation, which an attacker bypasses trivially.",
    ],
    verification=[
        "Add a regression test that replays the original payload and asserts it is now blocked.",
    ],
)

_TEMPLATES: Dict[VulnType, RemediationTemplate] = {
    VulnType.SQLI: RemediationTemplate(
        summary="Eliminate string-built SQL by using parameterised queries / prepared "
                "statements everywhere the database is touched.",
        steps=[
            "Replace every dynamically-concatenated query with a parameterised statement or ORM binding.",
            "Bind all user input as parameters — never interpolate it into the SQL text.",
            "For dynamic identifiers (table/column names) validate against a fixed allow-list.",
            "Apply least-privilege DB accounts so the app cannot read/write beyond its need.",
        ],
        best_practices=[
            "Use the ORM's parameter binding; avoid raw() escape hatches.",
            "Centralise data access so review can confirm no raw string SQL exists.",
        ],
        common_mistakes=[
            "Escaping quotes manually instead of parameterising — bypassable with encoding.",
            "Parameterising the WHERE clause but still concatenating ORDER BY / LIMIT.",
        ],
        verification=[
            "Replay the injection payload and confirm a normal, non-error response with no data leak.",
            "Add a test asserting `' OR '1'='1` returns zero extra rows.",
        ],
    ),
    VulnType.XSS: RemediationTemplate(
        summary="Context-aware output encoding plus a strong Content-Security-Policy.",
        steps=[
            "Encode all dynamic values at output time for their exact context (HTML, attribute, JS, URL, CSS).",
            "Prefer framework auto-escaping; avoid raw/unescaped HTML sinks (innerHTML, dangerouslySetInnerHTML).",
            "Deploy a restrictive CSP (no unsafe-inline) as defence-in-depth.",
            "Set HttpOnly on session cookies so injected script cannot read them.",
        ],
        best_practices=[
            "Sanitise rich HTML with a vetted library (DOMPurify) on the way in AND encode on the way out.",
            "Treat every DOM sink as dangerous by default.",
        ],
        common_mistakes=[
            "Blacklisting `<script>` while leaving event handlers and `javascript:` URLs.",
            "Encoding for HTML context but injecting into a JS or attribute context.",
        ],
        verification=[
            "Replay the XSS payload and confirm it renders inert (escaped) text.",
            "Confirm CSP blocks inline script via the browser console.",
        ],
    ),
    VulnType.CMDI: RemediationTemplate(
        summary="Avoid the shell entirely; pass arguments as an array to a specific executable.",
        steps=[
            "Replace shell-string execution with an argument-array API (no shell interpretation).",
            "Validate arguments against a strict allow-list; reject shell metacharacters.",
            "Drop to the lowest privilege the operation needs.",
        ],
        best_practices=[
            "Prefer a native library over shelling out at all.",
            "Never build the command line by string concatenation.",
        ],
        common_mistakes=[
            "Filtering `;` and `|` but missing `$()`, backticks, newlines and `&`.",
            "Using shell=True / os.system with 'cleaned' input.",
        ],
        verification=[
            "Replay the command-injection payload and confirm no secondary command runs.",
        ],
    ),
    VulnType.SSTI: RemediationTemplate(
        summary="Never render user input as a template; use logic-less, sandboxed rendering.",
        steps=[
            "Pass user data as template *variables*, never concatenate it into the template source.",
            "Use a logic-less engine or enable the engine's sandbox/auto-escape.",
            "Remove access to dangerous globals/builtins from the template context.",
        ],
        best_practices=["Keep templates static and version-controlled, data-driven only."],
        common_mistakes=["Blacklisting `{{` — trivially bypassed by alternate syntax."],
        verification=["Replay the `{{7*7}}`-style payload and confirm it is not evaluated."],
    ),
    VulnType.SSRF: RemediationTemplate(
        summary="Allow-list outbound destinations, block internal ranges, and disable redirects.",
        steps=[
            "Restrict outbound requests to an explicit allow-list of hosts/schemes.",
            "Resolve the hostname and reject private/link-local/loopback ranges (incl. 169.254.169.254).",
            "Disable automatic redirect-following, or re-validate each redirect target.",
            "Where possible, require the request go through an egress proxy with policy.",
        ],
        best_practices=[
            "Pin to the resolved IP and re-check after DNS to defeat DNS-rebinding.",
            "Deny the cloud metadata endpoint at the network layer as well.",
        ],
        common_mistakes=[
            "Validating the hostname string but letting a redirect reach an internal host.",
            "Blocking 127.0.0.1 but not `::1`, `0.0.0.0`, decimal/octal IPs or DNS rebinding.",
        ],
        verification=[
            "Replay with an internal/metadata URL and confirm the request is refused.",
        ],
    ),
    VulnType.XXE: RemediationTemplate(
        summary="Disable external entities and DTD processing in every XML parser.",
        steps=[
            "Set the parser to disallow DOCTYPE/DTD and external general+parameter entities.",
            "Disable XInclude and entity expansion.",
            "Prefer a data format without this footgun (JSON) where feasible.",
        ],
        best_practices=["Harden the parser at a shared factory so every call site inherits it."],
        common_mistakes=["Hardening one parser instance while other code paths use defaults."],
        verification=["Replay the external-entity payload and confirm no file/URL is fetched."],
    ),
    VulnType.PATH_TRAVERSAL: RemediationTemplate(
        summary="Resolve the canonical path and confirm it stays inside the intended base directory.",
        steps=[
            "Map user input to an internal identifier instead of using it as a path.",
            "Canonicalise the resolved path and verify it is within the allowed base directory.",
            "Reject `..`, absolute paths, null bytes and encoded variants.",
        ],
        best_practices=["Serve files by ID from a manifest, never by raw filename."],
        common_mistakes=["Stripping `../` once — `....//` reintroduces it after a single pass."],
        verification=["Replay the traversal payload and confirm access is denied."],
    ),
    VulnType.FILE_UPLOAD: RemediationTemplate(
        summary="Validate content, store outside the web root, and serve via a controlled handler.",
        steps=[
            "Validate the real content type (magic bytes), not just the extension or Content-Type header.",
            "Store uploads outside the web root with a random, non-executable name.",
            "Serve downloads through an authenticated handler with a fixed Content-Type.",
        ],
        best_practices=["Run uploads through AV/parsing sandboxes; strip metadata."],
        common_mistakes=["Trusting the client Content-Type or the file extension."],
        verification=["Attempt to upload and execute a webshell; confirm it cannot run."],
    ),
    VulnType.IDOR: RemediationTemplate(
        summary="Enforce per-object authorization on the server for every request.",
        steps=[
            "On every object access, verify the current principal owns/may access that object.",
            "Do the check server-side against the session identity — never trust a client-supplied owner id.",
            "Consider unguessable identifiers as defence-in-depth (not a substitute for the check).",
        ],
        best_practices=["Centralise authorization in a policy layer, not ad-hoc per controller."],
        common_mistakes=["Relying on unguessable IDs alone with no ownership check."],
        verification=["Replay the request as another user and confirm a 403/404."],
    ),
    VulnType.BROKEN_AUTH: RemediationTemplate(
        summary="Harden the full authentication lifecycle: credentials, sessions, and recovery.",
        steps=[
            "Enforce strong password policy + breached-password checks; add MFA.",
            "Rotate the session identifier on login; set Secure+HttpOnly+SameSite cookies.",
            "Rate-limit and lock out on repeated failures; make reset tokens single-use and short-lived.",
        ],
        best_practices=["Use a vetted auth framework; don't hand-roll session handling."],
        common_mistakes=["Not rotating the session id after privilege change (fixation)."],
        verification=["Confirm session id changes on login and old tokens are invalidated."],
    ),
    VulnType.SECURITY_HEADERS: RemediationTemplate(
        summary="Set the standard defensive response headers at the edge for every response.",
        steps=[
            "Add Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff.",
            "Add a Referrer-Policy and a restrictive Permissions-Policy.",
            "Set them centrally (reverse proxy / middleware) so no route is missed.",
        ],
        best_practices=["Start CSP in report-only, then enforce once clean."],
        common_mistakes=["Setting headers on some routes but not error pages / static assets."],
        verification=["Re-scan headers and confirm all required ones are present."],
    ),
    VulnType.SSL_TLS: RemediationTemplate(
        summary="Enforce TLS 1.2+ with modern ciphers and HSTS; drop legacy protocols.",
        steps=[
            "Disable SSLv3/TLS1.0/TLS1.1 and weak ciphers (RC4, 3DES, export).",
            "Enable HSTS with a long max-age and preferably preload.",
            "Keep certificates valid, complete-chained, and auto-renewed.",
        ],
        best_practices=["Track your config against the Mozilla 'Modern' profile."],
        common_mistakes=["Enabling HSTS without first ensuring all subresources are HTTPS."],
        verification=["Re-run the TLS scan and confirm no weak protocol/cipher is offered."],
    ),
    VulnType.CORS: RemediationTemplate(
        summary="Reflect only an explicit allow-list of origins; never combine wildcard with credentials.",
        steps=[
            "Validate Origin against a strict allow-list; echo it only on a match.",
            "Never return Access-Control-Allow-Origin: * together with Allow-Credentials: true.",
            "Limit allowed methods/headers to what the API actually needs.",
        ],
        best_practices=["Prefer same-site architecture; treat CORS as a deliberate exception."],
        common_mistakes=["Reflecting the Origin header unconditionally."],
        verification=["Replay with a foreign Origin and confirm it is not reflected."],
    ),
    VulnType.JWT: RemediationTemplate(
        summary="Pin the algorithm, verify the signature with a strong key, and validate all claims.",
        steps=[
            "Reject `alg: none` and confation of HMAC/RSA; pin the expected algorithm server-side.",
            "Verify the signature with a strong secret/key before trusting any claim.",
            "Validate exp/nbf/iss/aud; keep lifetimes short and support revocation.",
        ],
        best_practices=["Use a maintained JWT library with safe defaults; rotate keys."],
        common_mistakes=["Decoding without verifying, or trusting the token's own `alg` header."],
        verification=["Replay a tampered/`alg:none` token and confirm rejection."],
    ),
    VulnType.SECRET_EXPOSURE: RemediationTemplate(
        summary="Revoke the exposed secret, purge it from code/history, and move it to a secret store.",
        steps=[
            "Immediately revoke/rotate the exposed credential — assume it is compromised.",
            "Remove it from source and bundles; purge it from VCS history.",
            "Load secrets at runtime from a vault / environment, never from client-served files.",
        ],
        best_practices=["Add secret-scanning to CI to block re-introduction."],
        common_mistakes=["Rotating the key but leaving the old one in git history."],
        verification=["Confirm the secret no longer appears in any served asset or repo."],
    ),
    VulnType.OPEN_REDIRECT: RemediationTemplate(
        summary="Redirect only to validated internal targets; never to a raw user-supplied URL.",
        steps=[
            "Map redirect targets to an internal allow-list of paths.",
            "Reject absolute URLs and protocol-relative (`//`) targets.",
        ],
        best_practices=["Prefer relative-path redirects resolved server-side."],
        common_mistakes=["Allow-listing by `startswith(host)` — bypassed by `host.attacker.com`."],
        verification=["Replay with an external target and confirm the redirect is refused."],
    ),
    VulnType.CSRF: RemediationTemplate(
        summary="Require an anti-CSRF token on state-changing requests and use SameSite cookies.",
        steps=[
            "Add per-session (or per-request) CSRF tokens to all state-changing endpoints.",
            "Set session cookies to SameSite=Lax/Strict.",
            "Verify the token server-side on every mutating request.",
        ],
        best_practices=["Use the framework's built-in CSRF protection."],
        common_mistakes=["Protecting POST but leaving state-changing GET endpoints."],
        verification=["Replay a cross-site form submission and confirm it is rejected."],
    ),
}

# Tech-specific code examples: VulnType -> language -> snippet.
_CODE_EXAMPLES: Dict[VulnType, Dict[str, str]] = {
    VulnType.SQLI: {
        "python": "cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))  # bound param",
        "php":    "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$userId]);",
        "java":   "PreparedStatement ps = con.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setInt(1, userId);",
        "node":   "await db.query('SELECT * FROM users WHERE id = $1', [userId]);  // parameterised",
        "ruby":   "User.where(id: params[:id])  # ActiveRecord binds the value",
        "dotnet": "cmd.CommandText = \"SELECT * FROM users WHERE id = @id\";\ncmd.Parameters.AddWithValue(\"@id\", userId);",
        "generic": "Use prepared statements / bound parameters — never concatenate input into SQL.",
    },
    VulnType.XSS: {
        "python": "from markupsafe import escape\nreturn f\"<div>{escape(user_input)}</div>\"",
        "php":    "echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');",
        "java":   "out.print(org.owasp.encoder.Encode.forHtml(userInput));",
        "node":   "res.send(`<div>${escapeHtml(userInput)}</div>`);  // e.g. 'escape-html'",
        "ruby":   "<%= h(user_input) %>  <%# ERB auto-escapes with h/sanitize %>",
        "dotnet": "@Html.Encode(userInput)  @* Razor encodes by default with @model *@",
        "generic": "Encode output for its exact context; add a CSP without unsafe-inline.",
    },
    VulnType.CMDI: {
        "python": "subprocess.run(['convert', src, dst], shell=False, check=True)  # arg array, no shell",
        "php":    "$out = [];\nexec('convert ' . escapeshellarg($src) . ' ' . escapeshellarg($dst), $out);",
        "java":   "new ProcessBuilder(\"convert\", src, dst).start();  // no shell string",
        "node":   "execFile('convert', [src, dst]);  // NOT exec() with a string",
        "generic": "Invoke the binary with an argument array; never pass a shell string.",
    },
    VulnType.SSRF: {
        "python": "host = socket.gethostbyname(urlparse(url).hostname)\nif ipaddress.ip_address(host).is_private: raise Forbidden()",
        "node":   "const ip = (await dns.promises.lookup(new URL(url).hostname)).address;\nif (isPrivate(ip)) throw new Error('blocked');",
        "generic": "Resolve the host, reject private/link-local ranges, disable redirects, allow-list destinations.",
    },
    VulnType.SECURITY_HEADERS: {
        "generic": "add_header Content-Security-Policy \"default-src 'self'\";\n"
                   "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";\n"
                   "add_header X-Content-Type-Options nosniff;",
    },
    VulnType.JWT: {
        "python": "jwt.decode(token, key, algorithms=['RS256'])  # pin alg, verify signature",
        "node":   "jwt.verify(token, key, { algorithms: ['RS256'] });  // never {alg} from token",
        "generic": "Verify the signature with a pinned algorithm; reject alg:none; validate exp/iss/aud.",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RemediationGuidance:
    finding_id: str
    title: str
    vuln_type: str
    priority: str
    summary: str
    steps: List[str]
    best_practices: List[str]
    common_mistakes: List[str]
    verification: List[str]
    code_example: Optional[str]
    code_language: Optional[str]
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "priority": self.priority,
            "summary": self.summary,
            "steps": list(self.steps),
            "best_practices": list(self.best_practices),
            "common_mistakes": list(self.common_mistakes),
            "verification": list(self.verification),
            "code_example": self.code_example,
            "code_language": self.code_language,
            "references": list(self.references),
        }


@dataclass
class RemediationReport:
    guidance: List[RemediationGuidance]
    detected_language: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        # Group by vuln type so a report can show "fix all SQLi" once.
        by_type: Dict[str, int] = {}
        for g in self.guidance:
            by_type[g.vuln_type] = by_type.get(g.vuln_type, 0) + 1
        return {
            "detected_language": self.detected_language,
            "by_type": by_type,
            "guidance": [g.to_dict() for g in self.guidance],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Framework
# ─────────────────────────────────────────────────────────────────────────────

class RemediationFramework:
    """Generates prioritised, tech-aware remediation guidance per finding."""

    def generate(
        self,
        vulnerabilities: Sequence[Vulnerability],
        tech_profile: Optional[Dict[str, Any]] = None,
    ) -> RemediationReport:
        language = self._extract_language(tech_profile)
        lang_key = _norm_lang(language)
        guidance = [self._guide(v, lang_key) for v in vulnerabilities]
        return RemediationReport(guidance=guidance, detected_language=language)

    @staticmethod
    def _extract_language(tech_profile: Optional[Dict[str, Any]]) -> Optional[str]:
        if not isinstance(tech_profile, dict):
            return None
        return tech_profile.get("language") or tech_profile.get("cms") or tech_profile.get("framework")

    def _guide(self, v: Vulnerability, lang_key: str) -> RemediationGuidance:
        tpl = _TEMPLATES.get(v.vuln_type, _GENERIC)
        example, example_lang = self._code_for(v.vuln_type, lang_key)
        # Prefer the finding's own remediation string as the summary when the
        # scanner wrote a specific one; otherwise use the template summary.
        summary = v.remediation.strip() if v.remediation and v.remediation.strip() else tpl.summary
        return RemediationGuidance(
            finding_id=v.vuln_id,
            title=v.title,
            vuln_type=v.vuln_type.value,
            priority=_PRIORITY.get(v.severity, "Planned"),
            summary=summary,
            steps=list(tpl.steps),
            best_practices=list(tpl.best_practices),
            common_mistakes=list(tpl.common_mistakes),
            verification=list(tpl.verification),
            code_example=example,
            code_language=example_lang,
            references=list(v.references),
        )

    @staticmethod
    def _code_for(vuln_type: VulnType, lang_key: str):
        examples = _CODE_EXAMPLES.get(vuln_type)
        if not examples:
            return None, None
        if lang_key in examples:
            return examples[lang_key], lang_key
        if "generic" in examples:
            return examples["generic"], "generic"
        # Fall back to any available example rather than nothing.
        first_lang = next(iter(examples))
        return examples[first_lang], first_lang


__all__ = [
    "RemediationTemplate",
    "RemediationGuidance",
    "RemediationReport",
    "RemediationFramework",
]
