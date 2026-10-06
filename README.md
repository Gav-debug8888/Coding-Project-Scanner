# Safe Coding-Project Scanner

**A static, non-executing scanner that warns developers about dangerous behaviour hidden in untrusted coding assignments, before they run `npm install`, `pip install` or open the folder in VS Code.**

![python](https://img.shields.io/badge/python-3.9%2B-blue) ![tests](https://img.shields.io/badge/tests-49%20passing-brightgreen) ![analysis](https://img.shields.io/badge/analysis-static%20only-informational)

---

### Why this project exists

Some attack campaigns use fake recruiters who send developers a "take-home coding test". The repository looks normal, but it contains an npm `postinstall` hook, a VS Code task that runs when the folder opens, or a base64 loader in `setup.py`. Any of these can run code on the developer's machine and steal SSH keys, cloud credentials or browser data. This scanner reads the project **without executing anything** and reports which automatic execution paths and suspicious behaviours are present, with evidence for each one.

#### For recruiters and interviewers

> "I built a static scanner for untrusted coding assignments. It checks for risky installation hooks, automated editor tasks, obfuscation and suspicious setup behaviour without executing the project. I designed severity levels, evidence-rich reports, false-positive testing and CI integration. The tool supports analyst decisions rather than pretending that one indicator proves malicious intent."

#### Skills demonstrated

- Secure software supply chains
- Static analysis
- Detection engineering
- CI security
- Developer security
- False-positive management

---

### Installation

```bash
git clone <your-fork-url> coding-project-scanner
cd coding-project-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.9+. Runtime dependencies are `rich` and `colorama`. Tests need `pytest`. The CI gate also uses `jq` (a system package, not installed with pip).

### Usage

```bash
python -m scanner scan <path-to-repo> [--output json|terminal|both] [--output-file report.json]
                                      [--exclude GLOB ...] [--fail-on LEVEL]
python -m scanner rules               # print the rule catalogue
```

| Option | Meaning |
|---|---|
| `--output terminal` (default) | Coloured report using `rich` |
| `--output json` | JSON report on stdout, or written to `--output-file` |
| `--output both` | Terminal report, plus JSON (to `--output-file` or stdout) |
| `--exclude GLOB` | Skip a relative path or glob. Can be repeated. |
| `--fail-on LEVEL` | Exit with code `1` if the risk level is at or above `LEVEL` (useful in CI) |

#### Terminal output example

```text
$ python -m scanner scan tests/fixtures/install-hook-project
╭─────────────────────────────────── STATIC SCAN ────────────────────────────────────╮
│ Safe Coding-Project Scanner                                                        │
│ Project:   install-hook-project                                                    │
│ Scanned:   2026-10-06T13:35:08+00:00                                               │
│ Files:     3 scanned                                                               │
╰────────────────────────────────────────────────────────────────────────────────────╯
╭─ [1] HIGH  PKG_INSTALL_SCRIPT ───────────────────────────────────────────────────────╮
│ File:        package.json:7                                                          │
│ Evidence:    "postinstall": "echo \"SIMULATION: This is a harmless postinstall hook\"│
│              > /tmp/scanner_test.txt"                                                │
│ Why:         package.json defines an npm lifecycle hook ... that runs automatically  │
│              on `npm install`.                                                       │
│ Remediation: Open the project in a disposable VM before running npm install. Inspect │
│              the postinstall script manually. Consider `npm install --ignore-scripts`│
╰──────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────── RESULT ─────────────────────────────╮
│ Risk score: 25                                                  │
│ Risk level: MEDIUM                                              │
│ Findings:   1                                                   │
╰─────────────────────────────────────────────────────────────────╯
Static analysis cannot prove a project is safe. A clean result is not a guarantee of safety.
```

Severity colours: **CRITICAL** = bold red, **HIGH** = red, **MEDIUM** = yellow, **LOW** = cyan, **INFORMATIONAL** = white. The disclaimer is shown in dim italics.

#### JSON output example

```json
{
  "schema_version": "1.0",
  "scanner_version": "1.0.0",
  "project": "vscode-task-project",
  "scanned_path": "/home/you/coding-project-scanner/tests/fixtures/vscode-task-project",
  "scan_timestamp": "2026-10-06T13:35:08+00:00",
  "files_scanned": 3,
  "risk_score": 25,
  "risk_level": "MEDIUM",
  "composite_rule_triggered": false,
  "total_findings": 1,
  "findings": [
    {
      "rule_id": "VSCODE_AUTO_TASK",
      "severity": "HIGH",
      "file": ".vscode/tasks.json",
      "line": 11,
      "matched_text": "\"runOn\": \"folderOpen\"",
      "explanation": "VS Code task configured with runOn: folderOpen executes as soon as the folder is opened in a trusted workspace.",
      "remediation": "Open the project in VS Code Restricted Mode (File -> Open Folder as Restricted). Review tasks.json before trusting the workspace. ..."
    }
  ],
  "summary": "1 finding(s) in 1 file(s) (1 HIGH). Overall risk level: MEDIUM.",
  "disclaimer": "Static analysis cannot prove a project is safe. A clean result is not a guarantee of safety."
}
```

Each finding also includes `remediation_steps` (a list), `possible_false_positives` and `recommended_review_action`, so an analyst can triage it without opening the rule source.

---

### Rule catalogue

| Rule ID | What it detects | Severity |
|---|---|---|
| `PKG_INSTALL_SCRIPT` | `package.json` `preinstall` / `install` / `postinstall` / `prepare` lifecycle hooks | HIGH |
| `SETUP_PY_CMDCLASS` | `setup.py` custom `cmdclass` or overridden install/develop/build commands | HIGH |
| `VSCODE_AUTO_TASK` | `.vscode/tasks.json` task with `"runOn": "folderOpen"` | HIGH |
| `VSCODE_SETTINGS_EXEC` | `.vscode/settings.json` terminal profile/shell or `python.pythonPath`/interpreter overrides | MEDIUM |
| `SHELL_IN_SETUP` | `os.system`, `subprocess`, `popen`, `exec` in `setup.py` / `setup.cfg` | HIGH |
| `ENCODED_CONTENT` | `base64.b64decode`, `atob(`, `Buffer.from(..,'base64')`, hex blobs, base64 strings of 60+ characters in `.py/.js/.sh` | MEDIUM |
| `OBFUSCATED_JS` | `eval()` / `Function()` wrapping `atob`, `fromCharCode`, escaped or encoded literals | HIGH |
| `DYNAMIC_EVAL` | Python `eval(` / `exec(` outside test directories | MEDIUM |
| `CREDENTIAL_ACCESS` | `~/.ssh`, `id_rsa`, `~/.aws`, `~/.gnupg`, `GITHUB_TOKEN`, `.env`, keychain, kube/docker configs | CRITICAL |
| `NETWORK_IN_SETUP` | `urllib`, `requests`, `fetch`, `curl`, `wget` in setup files or install hooks/scripts | HIGH |
| `HIDDEN_EXECUTABLE` | Dot-files that are executable, have a shebang, or are `.sh` (or `.sh` inside hidden dirs) | MEDIUM |
| `UNUSUAL_DEPENDENCY_URL` | Dependencies from non-standard hosts, plain HTTP, or git dependencies not pinned to a commit | LOW |
| `MAKEFILE_PHONY` | Makefile `install:` / `all:` targets that run shell commands | MEDIUM |
| `CI_SECRETS_EXPOSURE` | CI configs that echo or write secrets to files, or dump the environment while secrets are in scope | HIGH |
| `POLYGLOT_FILE` | Image file whose magic bytes don't match its extension, or that contains script markers | INFORMATIONAL |

Every rule object in [`scanner/rules.py`](scanner/rules.py) has these fields: `rule_id`, `description`, `severity`, `file_pattern`, `content_pattern`, `evidence_location`, `possible_false_positives`, `recommended_review_action`. Each finding records the **first** matching line per rule per file, with the snippet truncated to 120 characters.

#### Scoring

| Severity | Points |
|---|---|
| INFORMATIONAL | +1 |
| LOW | +5 |
| MEDIUM | +10 |
| HIGH | +25 |
| CRITICAL | +50 |

Risk levels: `0` = CLEAN, `1–9` = INFORMATIONAL, `10–24` = LOW, `25–49` = MEDIUM, `50–99` = HIGH, `100+` = CRITICAL.

**Composite CRITICAL rule:** if a `CREDENTIAL_ACCESS` or `NETWORK_IN_SETUP` finding appears together with at least one *other* HIGH or CRITICAL finding (for example an automatic execution path), the overall level becomes **CRITICAL** and the score is raised to at least 100. This matches the pattern of the real attacks: an automatic trigger combined with credential theft or exfiltration.

> Finding severity and overall risk level are separate. A single HIGH finding (25 points) gives an overall level of MEDIUM. The finding is still listed as HIGH so a reviewer sees it.

---

### Synthetic fixtures and the safety boundary

`tests/fixtures/` contains five small repositories that **simulate** the patterns seen in malicious coding assignments. Every file is labelled `SIMULATION`.

| Fixture | What it simulates | Expected result |
|---|---|---|
| `clean-project` | Normal FizzBuzz project with harmless npm scripts | CLEAN, 0 findings |
| `vscode-task-project` | `folderOpen` task that only runs `echo` | `VSCODE_AUTO_TASK` |
| `encoded-script-project` | base64 + `exec` of `print('hello from encoded script')` | `ENCODED_CONTENT`, `DYNAMIC_EVAL` |
| `install-hook-project` | `postinstall` that echoes text into `/tmp/scanner_test.txt` | `PKG_INSTALL_SCRIPT` |
| `multi-warning-project` | All of the above + `~/.ssh/id_rsa` string + `requests.get` in `setup.py` | **CRITICAL** (composite) |

**Safety boundary**
- The fixtures contain **no live malware**, no real credentials and no reachable endpoints. The only URL is `https://example.invalid/...`, which uses a reserved TLD (RFC 2606) that can never resolve.
- The "credential access" is a plain string. Nothing opens or reads that path.
- The encoded payloads decode to `print()` statements.
- The scanner **never executes, imports or installs** scanned code. It only reads bytes from disk, does not follow symlinks, and skips `.git/`.

### Running the tests

```bash
python -m pytest tests/ -v
```

There are 49 tests. They cover the five fixtures, the JSON schema, the disclaimer, the scoring thresholds, the composite rule, a simulated positive case for every rule, and several false-positive guards (for example `process.env`, `re.compile`, valid PNG files and eval inside test folders).

---

### CI integration

[`.github/workflows/scanner-ci.yml`](.github/workflows/scanner-ci.yml) runs on every pull request to `main`. It:

1. Sets up Python 3.11 and installs the dependencies plus `jq`.
2. Runs the pytest suite.
3. Runs `python -m scanner scan . --exclude tests/fixtures --output both --output-file scan_report.json`. The deliberately suspicious fixtures are excluded so the gate measures real code.
4. Uploads `scan_report.json` as a build artifact, even when the job fails.
5. Uses `jq` to read `risk_level` and **fails the job if it is HIGH or CRITICAL**. *High-severity findings require human review — do not auto-merge.*

To use the scanner on an untrusted repository in your own pipeline:

```bash
python -m scanner scan ./candidate-assignment --output json --output-file report.json --fail-on HIGH
```

---

### Limitations

- Static scanning cannot detect every threat.
- Obfuscated behaviour may evade rules (for example, strings split across concatenations, or code loaded at runtime from a remote host).
- Legitimate developer tools sometimes resemble malicious behaviour (husky `prepare` hooks, native-module `postinstall`, `dotenv` loaders).
- A clean result is not a guarantee of safety.
- Dynamic analysis should occur only in a controlled sandbox.

See [`accuracy_report.md`](accuracy_report.md) for measured true positives, false positives and false negatives.

---

**This tool supports analyst decisions rather than pretending that one indicator proves malicious intent.**

