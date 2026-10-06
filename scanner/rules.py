"""Detection rules for the Safe Coding-Project Scanner.

Every rule is pure static analysis: files are read as text/bytes and matched
against patterns. Nothing in the scanned project is ever imported, executed,
installed or opened in a tool that could run it.

Implementation note: some keyword patterns below use single-character classes
(e.g. ``id_rs[a]``) so that this source file does not match its own rules when
the scanner is pointed at its own repository.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_POINTS = {"INFORMATIONAL": 1, "LOW": 5, "MEDIUM": 10, "HIGH": 25, "CRITICAL": 50}

# Extensions treated as source/config text for keyword-based rules.
TEXT_CODE_RE = (
    r"(\.(py|pyw|js|mjs|cjs|ts|jsx|tsx|sh|bash|zsh|ps1|bat|cmd|json|jsonc|ya?ml|cfg|ini|"
    r"toml|rb|go|php|pl|lua)|(^|/)(Makefile|makefile|GNUmakefile|Dockerfile))$"
)
CI_PATH_RE = re.compile(
    r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.travis\.ya?ml|\.circleci/[^/]+|\.gitlab-ci\.ya?ml|"
    r"azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|Jenkinsfile)$"
)
TEST_DIR_NAMES = {"test", "tests", "testing", "__tests__", "spec"}
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


@dataclass
class FileContext:
    """Everything a rule may inspect about one file (read-only)."""

    rel_path: str  # POSIX-style path relative to the scan root
    abs_path: str
    head: bytes  # first bytes of the file (for magic-byte checks)
    text: Optional[str]  # decoded text, None for binary/oversized files
    mode: int

    @property
    def lines(self) -> List[str]:
        if not hasattr(self, "_lines"):
            self._lines = (self.text or "").splitlines()
        return self._lines

    @property
    def basename(self) -> str:
        return self.rel_path.rsplit("/", 1)[-1]


@dataclass
class Match:
    line: Optional[int]
    text: str
    detail: str = ""


@dataclass
class Rule:
    rule_id: str
    description: str
    severity: str
    file_pattern: str  # regex matched against the relative POSIX path
    content_pattern: Optional[str]  # regex applied line-by-line (if no custom matcher)
    evidence_location: str
    possible_false_positives: str
    recommended_review_action: str
    path_filter: Optional[Callable[[str], bool]] = None
    matcher: Optional[Callable[["FileContext"], Optional[Match]]] = None
    needs_text: bool = True
    skip_comments: bool = False

    def __post_init__(self) -> None:
        self._file_re = re.compile(self.file_pattern, re.IGNORECASE if self.rule_id == "POLYGLOT_FILE" else 0)
        self._content_re = re.compile(self.content_pattern) if self.content_pattern else None

    def applies_to(self, rel_path: str) -> bool:
        if not self._file_re.search(rel_path):
            return False
        return self.path_filter(rel_path) if self.path_filter else True

    def check(self, ctx: FileContext) -> Optional[Match]:
        if self.needs_text and ctx.text is None:
            return None
        if self.matcher:
            return self.matcher(ctx)
        if self._content_re is None:
            return Match(None, ctx.rel_path)
        return first_line_match(ctx.lines, self._content_re, self.skip_comments)

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "file_pattern": self.file_pattern,
            "content_pattern": self.content_pattern or "",
            "evidence_location": self.evidence_location,
            "possible_false_positives": self.possible_false_positives,
            "recommended_review_action": self.recommended_review_action,
        }


# --------------------------------------------------------------------------- helpers
def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith("#") or s.startswith("//")


def first_line_match(lines: List[str], pattern: "re.Pattern[str]", skip_comments: bool = False) -> Optional[Match]:
    for idx, line in enumerate(lines, start=1):
        if skip_comments and _is_comment(line):
            continue
        if pattern.search(line):
            return Match(idx, line.strip())
    return None


def find_line(lines: List[str], needle: str) -> Optional[int]:
    for idx, line in enumerate(lines, start=1):
        if needle in line:
            return idx
    return None


def is_test_path(rel_path: str) -> bool:
    parts = rel_path.split("/")
    if any(p.lower() in TEST_DIR_NAMES for p in parts[:-1]):
        return True
    name = parts[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def _load_json(ctx: FileContext) -> Optional[dict]:
    try:
        data = json.loads(ctx.text or "")
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------- PKG_INSTALL_SCRIPT
def _match_pkg_install(ctx: FileContext) -> Optional[Match]:
    data = _load_json(ctx)
    if data is not None:
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            for hook in INSTALL_HOOKS:
                if hook in scripts:
                    line = find_line(ctx.lines, f'"{hook}"')
                    text = ctx.lines[line - 1].strip() if line else f'"{hook}": "{scripts[hook]}"'
                    return Match(line, text, f"lifecycle hook '{hook}' runs automatically during npm install")
        return None
    # Malformed JSON: fall back to a regex so broken files cannot hide hooks.
    m = first_line_match(ctx.lines, re.compile(r'"(%s)"\s*:' % "|".join(INSTALL_HOOKS)))
    if m:
        m.detail = "install lifecycle hook found (package.json did not parse as valid JSON)"
    return m


# --------------------------------------------------------------------------- ENCODED_CONTENT
_ENCODED_GENERIC = re.compile(
    r"\bb64decode\s*\(|\bb32decode\s*\(|\bb85decode\s*\(|\batob\s*\(|"
    r"Buffer\.from\([^)]*['\"]base64['\"]|\bbytes\.fromhex\s*\(|codecs\.decode\([^)]*['\"](?:hex|rot13)|"
    r"(?:\\x[0-9a-fA-F]{2}){16,}|(?<![0-9a-fA-F])[0-9a-fA-F]{100,}(?![0-9a-fA-F])"
)
_ENCODED_SHELL = re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b|\bxxd\s+-r\b")
_LONG_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])")


def _looks_like_b64(token: str) -> bool:
    return any(c.isdigit() for c in token) and any(c.isupper() for c in token) and any(c.islower() for c in token)


def _match_encoded(ctx: FileContext) -> Optional[Match]:
    is_shell = ctx.rel_path.endswith((".sh", ".bash"))
    for idx, line in enumerate(ctx.lines, start=1):
        if _ENCODED_GENERIC.search(line) or (is_shell and _ENCODED_SHELL.search(line)):
            return Match(idx, line.strip(), "runtime decoding of encoded data")
        for tok in _LONG_B64.findall(line):
            if _looks_like_b64(tok):
                return Match(idx, line.strip(), f"long base64-like string ({len(tok)} chars)")
    return None


# --------------------------------------------------------------------------- NETWORK_IN_SETUP
_NETWORK_RE = re.compile(
    r"\burllib3?\b|\brequests\s*\.\s*(?:get|post|put|patch|delete|head|request|Session)\b|"
    r"^\s*(?:import|from)\s+requests\b|\bhttpx\b|\bhttp\.client\b|\baiohttp\b|\bsocket\s*\.|"
    r"\bfetch\s*\(|\bcurl\b|\bwget\b|\baxios\b|\bhttps?\.(?:get|request)\s*\(|"
    r"Invoke-WebRequest|Invoke-RestMethod|\bnc\s+-"
)


def _match_network(ctx: FileContext) -> Optional[Match]:
    if ctx.basename == "package.json":
        data = _load_json(ctx)
        scripts = (data or {}).get("scripts") or {}
        if not isinstance(scripts, dict):
            return None
        for hook in INSTALL_HOOKS:
            value = scripts.get(hook)
            if isinstance(value, str) and _NETWORK_RE.search(value):
                line = find_line(ctx.lines, f'"{hook}"')
                return Match(line, ctx.lines[line - 1].strip() if line else value,
                             f"install hook '{hook}' performs network access")
        return None
    m = first_line_match(ctx.lines, _NETWORK_RE, skip_comments=True)
    if m:
        m.detail = "network client used in a file that runs during installation"
    return m


# --------------------------------------------------------------------------- HIDDEN_EXECUTABLE
def _match_hidden_exec(ctx: FileContext) -> Optional[Match]:
    executable = bool(ctx.mode & 0o111)
    is_sh = ctx.basename.endswith(".sh")
    first = ctx.lines[0].strip() if ctx.text and ctx.lines else ""
    if ctx.basename.startswith("."):
        if executable or is_sh or first.startswith("#!"):
            why = "executable bit set" if executable else ("shell script" if is_sh else "shebang line")
            return Match(1, first or ctx.basename, f"hidden file ({why})")
        return None
    if is_sh:  # shell script inside a hidden directory
        return Match(1, first or ctx.basename, "shell script inside a hidden directory")
    return None


# --------------------------------------------------------------------------- UNUSUAL_DEPENDENCY_URL
ALLOWED_HOSTS = {
    "registry.npmjs.org", "npmjs.com", "www.npmjs.com", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org", "pypi.python.org", "github.com", "codeload.github.com",
}
_URL_RE = re.compile(r"(?:git\+)?(?:https?|git|ssh)://[^\s'\"<>,;)\]]+")
_PINNED_RE = re.compile(r"[#@][0-9a-f]{40}\b")
_PY_DEP_CONTEXT = re.compile(r"index[-_]url|dependency_links|git\+|\s@\s|^\s*url\s*=|find-links|registry")


def url_issue(url: str) -> Optional[str]:
    """Return a human-readable reason if a dependency URL is unusual, else None."""
    bare = url[4:] if url.startswith("git+") else url
    parsed = urlparse(bare)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http":
        return f"insecure plain-HTTP dependency source ({host})"
    if host not in ALLOWED_HOSTS:
        return f"dependency fetched from non-standard host '{host}'"
    is_git = url.startswith(("git+", "git://", "ssh://")) or parsed.path.endswith(".git")
    if is_git and not _PINNED_RE.search(url):
        return "git dependency not pinned to a full commit hash"
    return None


def _match_dep_url(ctx: FileContext) -> Optional[Match]:
    name = ctx.basename
    if name == "package.json":
        data = _load_json(ctx) or {}
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for pkg, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                reason = None
                if "://" in spec:
                    reason = url_issue(spec)
                elif spec.startswith(("github:", "gitlab:", "bitbucket:")) and not _PINNED_RE.search(spec):
                    reason = "git shorthand dependency not pinned to a full commit hash"
                if reason:
                    line = find_line(ctx.lines, spec)
                    return Match(line, f'"{pkg}": "{spec}"', reason)
        return None
    any_line = name.startswith(("requirements", ".npmrc", ".yarnrc", ".pypirc", "pip.conf"))
    for idx, line in enumerate(ctx.lines, start=1):
        if _is_comment(line) or (not any_line and not _PY_DEP_CONTEXT.search(line)):
            continue
        for url in _URL_RE.findall(line):
            reason = url_issue(url)
            if reason:
                return Match(idx, line.strip(), reason)
    return None


# --------------------------------------------------------------------------- MAKEFILE_PHONY
_MAKE_TARGET = re.compile(r"^(install|all)\s*:(?!=)(.*)$")


def _match_makefile(ctx: FileContext) -> Optional[Match]:
    lines = ctx.lines
    for idx, line in enumerate(lines, start=1):
        m = _MAKE_TARGET.match(line)
        if not m:
            continue
        if ";" in m.group(2) and m.group(2).split(";", 1)[1].strip():
            return Match(idx, line.strip(), f"'{m.group(1)}' target has an inline recipe")
        for recipe in lines[idx:]:
            if recipe.startswith("\t") and recipe.strip():
                return Match(idx, f"{line.strip()} -> {recipe.strip()}",
                             f"'{m.group(1)}' target runs shell commands")
            if recipe.strip() and not recipe.startswith("\t"):
                break
    return None


# --------------------------------------------------------------------------- CI_SECRETS_EXPOSURE
_SECRET_REF = re.compile(
    r"\$\{\{\s*secrets\.|\bsecrets\.[A-Za-z_]\w*|\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\}?"
)
_SECRET_WRITE = re.compile(r"\becho\b|\bprintf\b|\btee\b|\bcat\b|>{1,2}|toJSON\s*\(\s*secrets")
_ENV_DUMP = re.compile(
    r"\bprintenv\b|(?:run:|^|[;&|]\s*)\s*env\s*(?:$|[>|])|\bexport\s+-p\b|\bset\s*(?:$|[>|])|toJSON\s*\(\s*secrets\s*\)"
)


def _match_ci_secrets(ctx: FileContext) -> Optional[Match]:
    has_secret = False
    for idx, line in enumerate(ctx.lines, start=1):
        if _is_comment(line):
            continue
        if _SECRET_REF.search(line):
            has_secret = True
            if _SECRET_WRITE.search(line):
                return Match(idx, line.strip(), "secret value echoed or written to a file/stream")
    if has_secret:
        for idx, line in enumerate(ctx.lines, start=1):
            if not _is_comment(line) and _ENV_DUMP.search(line.strip()):
                return Match(idx, line.strip(), "environment dump in a workflow that has secrets in scope")
    return None


# --------------------------------------------------------------------------- POLYGLOT_FILE
_MAGIC = {
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".bmp": [b"BM"],
    ".ico": [b"\x00\x00\x01\x00"],
    ".webp": [b"RIFF"],
}
_SCRIPT_MARKERS = re.compile(
    rb"<script|<\?php|#!/|\beval\s*\(|\bexec\s*\(|import\s+os|require\s*\(|powershell|/bin/(?:ba)?sh",
    re.IGNORECASE,
)


def _match_polyglot(ctx: FileContext) -> Optional[Match]:
    ext = os.path.splitext(ctx.basename)[1].lower()
    magics = _MAGIC.get(ext, [])
    if magics and not any(ctx.head.startswith(m) for m in magics):
        snippet = ctx.head[:60].decode("latin-1").replace("\n", " ")
        return Match(1, snippet, f"content does not start with the {ext} magic bytes")
    try:
        with open(ctx.abs_path, "rb") as fh:
            data = fh.read(1024 * 1024)
    except OSError:
        return None
    m = _SCRIPT_MARKERS.search(data)
    if m:
        start = max(0, m.start() - 20)
        snippet = data[start:m.end() + 40].decode("latin-1", "replace").replace("\n", " ")
        return Match(data[:m.start()].count(b"\n") + 1, snippet, "script marker embedded in image file")
    return None


# --------------------------------------------------------------------------- rule catalogue
RULES: List[Rule] = [
    Rule(
        rule_id="PKG_INSTALL_SCRIPT",
        description="package.json defines an npm lifecycle hook (preinstall/install/postinstall/prepare) "
                    "that runs automatically on `npm install`.",
        severity="HIGH",
        file_pattern=r"(^|/)package\.json$",
        content_pattern=r'"(preinstall|install|postinstall|prepare|prepublish)"\s*:',
        evidence_location="package.json -> scripts.<hook>",
        possible_false_positives="Build tooling (husky `prepare`, native module compilation with node-gyp, "
                                 "esbuild/puppeteer binary downloads).",
        recommended_review_action="Read the hook command and any script it calls; install with "
                                  "`npm install --ignore-scripts` inside a disposable VM.",
        matcher=_match_pkg_install,
    ),
    Rule(
        rule_id="SETUP_PY_CMDCLASS",
        description="setup.py overrides setuptools commands (cmdclass / install subclass), so arbitrary code "
                    "runs during `pip install`.",
        severity="HIGH",
        file_pattern=r"(^|/)setup\.py$",
        content_pattern=r"\bcmdclass\s*=|class\s+\w+\(\s*(?:_?install|develop|egg_info|build_py|build_ext|sdist|bdist_\w+)\s*\)",
        evidence_location="setup.py -> setup(cmdclass=...) or command subclass",
        possible_false_positives="Packages with C extensions or generated files that customise build_ext/build_py.",
        recommended_review_action="Read every overridden command's run() method before installing.",
        skip_comments=True,
    ),
    Rule(
        rule_id="VSCODE_AUTO_TASK",
        description="VS Code task configured with runOn: folderOpen executes as soon as the folder is opened "
                    "in a trusted workspace.",
        severity="HIGH",
        file_pattern=r"(^|/)\.vscode/tasks\.json$",
        content_pattern=r'"runOn"\s*:\s*"folderOpen"',
        evidence_location=".vscode/tasks.json -> tasks[].runOptions.runOn",
        possible_false_positives="Teams that auto-start a dev server or file watcher on open.",
        recommended_review_action="Open the folder in Restricted Mode and review every task command first.",
    ),
    Rule(
        rule_id="VSCODE_SETTINGS_EXEC",
        description="Workspace settings override terminal profiles/shell or the Python interpreter path, which "
                    "can redirect execution to a project-controlled binary.",
        severity="MEDIUM",
        file_pattern=r"((^|/)\.vscode/settings\.json|\.code-workspace)$",
        content_pattern=r"terminal\.integrated\.(?:profiles|defaultProfile|shell|shellArgs|automationProfile|env)|"
                        r"python\.(?:pythonPath|defaultInterpreterPath|condaPath|venvPath)",
        evidence_location=".vscode/settings.json -> terminal.integrated.* / python.* keys",
        possible_false_positives="Shared team settings pointing at a standard local virtualenv (./.venv/bin/python).",
        recommended_review_action="Verify the referenced shell/interpreter is a standard system binary.",
    ),
    Rule(
        rule_id="SHELL_IN_SETUP",
        description="setup.py / setup.cfg invokes shell or process-execution APIs that run during packaging "
                    "or installation.",
        severity="HIGH",
        file_pattern=r"(^|/)setup\.(py|cfg)$",
        content_pattern=r"\bos\.system\s*\(|\bsubprocess\b|\bpopen\s*\(|\bos\.exec\w*\s*\(|"
                        r"(?<![\w.])exec\s*\(|\bos\.spawn\w*\s*\(",
        evidence_location="setup.py / setup.cfg -> process execution call",
        possible_false_positives="Build scripts that call a compiler, git describe, or pkg-config.",
        recommended_review_action="Identify the exact command executed and whether user input reaches it.",
        skip_comments=True,
    ),
    Rule(
        rule_id="ENCODED_CONTENT",
        description="Source file decodes base64/hex data at runtime or embeds a long encoded blob, a common "
                    "way to hide a payload from reviewers.",
        severity="MEDIUM",
        file_pattern=r"\.(py|pyw|js|mjs|cjs|ts|sh|bash)$",
        content_pattern=r"b64decode\(|atob\(|Buffer\.from\(\.\.\.base64|bytes\.fromhex\(|[A-Za-z0-9+/]{60,}",
        evidence_location="Line containing the decode call or encoded literal",
        possible_false_positives="Embedded icons/fonts, test vectors, JWT samples, cryptographic constants.",
        recommended_review_action="Decode the blob offline (never execute it) and review the plaintext.",
        matcher=_match_encoded,
    ),
    Rule(
        rule_id="OBFUSCATED_JS",
        description="JavaScript passes decoded or encoded data straight into eval or the Function "
                    "constructor (string-to-code execution).",
        severity="HIGH",
        file_pattern=r"\.(js|mjs|cjs|ts|jsx|tsx)$",
        content_pattern=r"\b(?:eval|(?:new\s+)?Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|escape|"
                        r"Buffer\.from|String\.fromCharCode|['\"`](?:[A-Za-z0-9+/=]{40,}|(?:\\x[0-9a-fA-F]{2}){8,}|"
                        r"(?:\\u[0-9a-fA-F]{4}){8,}))",
        evidence_location="JS line with eval/Function wrapping an encoded argument",
        possible_false_positives="Legacy bundlers or minified vendor code using eval-based source maps.",
        recommended_review_action="Deobfuscate statically (e.g., replace eval with console.log in a copy, "
                                  "inside a sandbox) and review the result.",
    ),
    Rule(
        rule_id="DYNAMIC_EVAL",
        description="Python eval/exec call outside test directories executes dynamically constructed code.",
        severity="MEDIUM",
        file_pattern=r"\.pyw?$",
        content_pattern=r"(?<![\w.])(?:eval|exec)\s*\(",
        evidence_location="Python line containing the eval/exec call",
        possible_false_positives="Config loaders, REPL tools, template engines, plugin systems.",
        recommended_review_action="Trace where the argument comes from; treat any decoded/remote input as hostile.",
        path_filter=lambda p: not is_test_path(p),
        skip_comments=True,
    ),
    Rule(
        rule_id="CREDENTIAL_ACCESS",
        description="Code or config references developer credential stores (SSH keys, cloud/GPG config, "
                    "tokens, dotenv files, OS key stores).",
        severity="CRITICAL",
        file_pattern=TEXT_CODE_RE,
        content_pattern=(
            r"\.ss[h]/|~/\.ss[h]\b|\bid_rs[a]\b|\bid_ed2551[9]\b|\bid_ecds[a]\b|\.aw[s]/|~/\.aw[s]\b|"
            r"\.gnup[g]\b|\bGITHUB_TOKE[N]\b|\bNPM_TOKE[N]\b|\bAWS_SECRET_ACCESS_KE[Y]\b|\bkeychai[n]\b|"
            r"\bfind-generic-passwor[d]\b|\.kube/confi[g]\b|\.docker/config\.jso[n]\b|\.config/gclou[d]\b|"
            r"Login Dat[a]|(?:^|[\s'\"`/=(])\.en[v](?:\.[\w-]+)?(?=$|[\s'\"`)/,;])"
        ),
        evidence_location="Line referencing the credential path or token name",
        possible_false_positives="Documentation-like config, deployment scripts that legitimately load "
                                 "a local dotenv file, SSH helper tooling.",
        recommended_review_action="Determine whether the file reads or transmits the credential; assume "
                                  "compromise if it ran while you were logged in.",
        path_filter=lambda p: not CI_PATH_RE.search(p),
    ),
    Rule(
        rule_id="NETWORK_IN_SETUP",
        description="Setup file or install script performs network access (urllib, requests, fetch, curl, wget) "
                    "during installation.",
        severity="HIGH",
        file_pattern=r"(^|/)(setup\.(py|cfg)|package\.json|(?:pre|post)?install[\w.-]*\.(?:sh|js|mjs|cjs|py|ps1)|"
                     r"setup[\w.-]*\.(?:sh|js|mjs|cjs|ps1))$",
        content_pattern=r"urllib|requests\.get|fetch\(|curl|wget",
        evidence_location="Setup/install file line containing the network call",
        possible_false_positives="Installers that download prebuilt binaries from the vendor's release page.",
        recommended_review_action="Identify the destination; block egress and reinstall in an isolated sandbox.",
        matcher=_match_network,
    ),
    Rule(
        rule_id="HIDDEN_EXECUTABLE",
        description="Hidden file that is executable, has a shebang, or is a shell script (or a shell script "
                    "inside a hidden directory).",
        severity="MEDIUM",
        file_pattern=r"(^|/)\.[^/]+$|(^|/)\.(?!github/)[^/]+/(?:.*/)?[^/]+\.sh$",
        content_pattern=None,
        evidence_location="File mode / first line of the hidden file",
        possible_false_positives="Git hooks managers (.husky/), direnv .envrc, dotfile installers.",
        recommended_review_action="Read the script and check what references it (hooks, tasks, package scripts).",
        matcher=_match_hidden_exec,
        needs_text=False,
    ),
    Rule(
        rule_id="UNUSUAL_DEPENDENCY_URL",
        description="Dependency fetched from a non-standard registry/host, over plain HTTP, or from git "
                    "without a pinned commit hash.",
        severity="LOW",
        file_pattern=r"(^|/)(package\.json|requirements[\w.-]*\.(txt|in)|setup\.(py|cfg)|pyproject\.toml|Pipfile|"
                     r"\.npmrc|\.yarnrc(\.yml)?|\.pypirc|pip\.conf)$",
        content_pattern=r"(git\+)?(https?|git|ssh)://",
        evidence_location="Dependency declaration line",
        possible_false_positives="Private corporate registries (Artifactory, Nexus, GitLab package registry).",
        recommended_review_action="Confirm the host is trusted and pin the dependency to an exact version/commit.",
        matcher=_match_dep_url,
    ),
    Rule(
        rule_id="MAKEFILE_PHONY",
        description="Makefile `install` or `all` target runs shell commands - `make` with no arguments executes "
                    "the first target.",
        severity="MEDIUM",
        file_pattern=r"(^|/)(GNUmakefile|[Mm]akefile)$",
        content_pattern=r"^(install|all)\s*:",
        evidence_location="Makefile target and first recipe line",
        possible_false_positives="Almost every C/C++ project; severity reflects review need, not malice.",
        recommended_review_action="Run `make -n` (dry run) to print commands without executing them.",
        matcher=_match_makefile,
    ),
    Rule(
        rule_id="CI_SECRETS_EXPOSURE",
        description="CI configuration reads secrets and echoes them, writes them to files, or dumps the "
                    "environment.",
        severity="HIGH",
        file_pattern=CI_PATH_RE.pattern,
        content_pattern=r"secrets\.\w+ combined with echo/printf/tee/> or printenv/env dumps",
        evidence_location="Workflow step line that writes or dumps secret values",
        possible_false_positives="`echo $TOKEN | docker login --password-stdin` style piping.",
        recommended_review_action="Never approve workflows from forks that touch secrets; review the step.",
        matcher=_match_ci_secrets,
    ),
    Rule(
        rule_id="POLYGLOT_FILE",
        description="Image file whose magic bytes do not match its extension or that embeds script markers.",
        severity="INFORMATIONAL",
        file_pattern=r"\.(png|jpe?g|gif|bmp|ico|webp)$",
        content_pattern=None,
        evidence_location="File header bytes / embedded script marker",
        possible_false_positives="Mislabelled assets, SVG saved as .png, image metadata containing text.",
        recommended_review_action="Inspect with `file` and a hex viewer; check whether any code loads it.",
        matcher=_match_polyglot,
        needs_text=False,
    ),
]

RULES_BY_ID: Dict[str, Rule] = {r.rule_id: r for r in RULES}
