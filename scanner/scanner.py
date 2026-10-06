"""Scanner core and CLI.

Usage:
    python -m scanner scan <path-to-repo> [--output json|terminal|both] [--output-file report.json]

The scanner only reads files. It never imports, executes or installs anything
from the scanned project.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import __version__
from .remediation import get_remediation, get_remediation_steps
from .report import render_terminal, to_json
from .rules import RULES, SEVERITY_ORDER, SEVERITY_POINTS, FileContext, Rule

SCHEMA_VERSION = "1.0"
DISCLAIMER = "Static analysis cannot prove a project is safe. A clean result is not a guarantee of safety."
SKIP_DIRS = {".git"}
# A directory holding pyvenv.cfg is a local Python virtual environment (third-party
# packages, not project code). Skipped by default and always listed in the report.
VENV_MARKER = "pyvenv.cfg"
MAX_TEXT_BYTES = 2 * 1024 * 1024  # larger files are only checked by binary-safe rules
COMPOSITE_TRIGGERS = {"CREDENTIAL_ACCESS", "NETWORK_IN_SETUP"}
MAX_SNIPPET = 120


def truncate(text: str, limit: int = MAX_SNIPPET) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def risk_level_for(score: int) -> str:
    if score <= 0:
        return "CLEAN"
    if score < 10:
        return "INFORMATIONAL"
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 100:
        return "HIGH"
    return "CRITICAL"


def composite_triggered(findings: Sequence[Dict[str, Any]]) -> bool:
    """CRITICAL composite rule.

    True when a CREDENTIAL_ACCESS or NETWORK_IN_SETUP finding co-occurs with at
    least one *other* HIGH or CRITICAL finding (e.g. an auto-execution path).
    """
    for i, trigger in enumerate(findings):
        if trigger["rule_id"] not in COMPOSITE_TRIGGERS:
            continue
        for j, other in enumerate(findings):
            if i != j and other["severity"] in ("HIGH", "CRITICAL"):
                return True
    return False


def _read_file(abs_path: str) -> FileContext:
    st = os.stat(abs_path)
    with open(abs_path, "rb") as fh:
        raw = fh.read(MAX_TEXT_BYTES + 1)
    head = raw[:64]
    text: Optional[str] = None
    if len(raw) <= MAX_TEXT_BYTES and b"\x00" not in raw[:8192]:
        text = raw.decode("utf-8", errors="replace")
    return FileContext(rel_path="", abs_path=abs_path, head=head, text=text, mode=st.st_mode)


def _excluded(rel_path: str, excludes: Iterable[str]) -> bool:
    for pat in excludes:
        pat = pat.strip("/")
        if fnmatch.fnmatch(rel_path, pat) or rel_path == pat or rel_path.startswith(pat + "/"):
            return True
    return False


def iter_files(root: str, excludes: Sequence[str] = (), include_venv: bool = False,
               skipped: Optional[List[str]] = None) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}".lstrip("/")
            if d in SKIP_DIRS or _excluded(rel, excludes):
                continue
            if not include_venv and os.path.isfile(os.path.join(dirpath, d, VENV_MARKER)):
                if skipped is not None:
                    skipped.append(f"{rel}/ (local Python virtualenv)")
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}".lstrip("/")
            abs_path = os.path.join(dirpath, name)
            if os.path.islink(abs_path) or not os.path.isfile(abs_path) or _excluded(rel, excludes):
                continue
            yield rel


def scan_file(root: str, rel_path: str, rules: Sequence[Rule] = RULES) -> List[Dict[str, Any]]:
    applicable = [r for r in rules if r.applies_to(rel_path)]
    if not applicable:
        return []
    try:
        ctx = _read_file(os.path.join(root, rel_path))
    except OSError:
        return []
    ctx.rel_path = rel_path
    findings = []
    for rule in applicable:
        match = rule.check(ctx)
        if match is None:
            continue
        explanation = rule.description + (f" Evidence: {match.detail}." if match.detail else "")
        findings.append({
            "rule_id": rule.rule_id,
            "severity": rule.severity,
            "file": rel_path,
            "line": match.line,
            "matched_text": truncate(match.text),
            "explanation": explanation,
            "remediation": get_remediation(rule.rule_id),
            "remediation_steps": get_remediation_steps(rule.rule_id),
            "possible_false_positives": rule.possible_false_positives,
            "recommended_review_action": rule.recommended_review_action,
        })
    return findings


def build_summary(findings: List[Dict[str, Any]], level: str, composite: bool) -> str:
    if not findings:
        return "No rule matched. Review the project manually before running any of its code."
    counts = {s: 0 for s in reversed(SEVERITY_ORDER)}
    for f in findings:
        counts[f["severity"]] += 1
    parts = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    files = len({f["file"] for f in findings})
    text = f"{len(findings)} finding(s) in {files} file(s) ({parts}). Overall risk level: {level}."
    if composite:
        text += (" Composite rule triggered: credential access or install-time network activity co-occurs"
                 " with another high-severity behaviour - treat as CRITICAL and do not run this project"
                 " outside a disposable sandbox.")
    elif level in ("HIGH", "CRITICAL"):
        text += " Human review is required before running any code from this project."
    return text


def scan_path(path: str, excludes: Sequence[str] = (), include_venv: bool = False) -> Dict[str, Any]:
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"Not a directory: {path}")

    findings: List[Dict[str, Any]] = []
    files_scanned = 0
    skipped: List[str] = []
    for rel in iter_files(root, excludes, include_venv, skipped):
        files_scanned += 1
        findings.extend(scan_file(root, rel))

    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f["file"], f["line"] or 0, f["rule_id"]))
    score = sum(SEVERITY_POINTS[f["severity"]] for f in findings)
    composite = composite_triggered(findings)
    if composite:
        score = max(score, 100)
    level = "CRITICAL" if composite else risk_level_for(score)

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": __version__,
        "project": os.path.basename(root.rstrip(os.sep)) or root,
        "scanned_path": root,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_scanned": files_scanned,
        "skipped_paths": skipped,
        "risk_score": score,
        "risk_level": level,
        "composite_rule_triggered": composite,
        "total_findings": len(findings),
        "findings": findings,
        "summary": build_summary(findings, level, composite),
        "disclaimer": DISCLAIMER,
    }


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scanner",
        description="Static, non-executing scanner for risky behaviour in untrusted coding projects.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a project directory")
    scan.add_argument("path", help="Path to the project/repository to scan")
    scan.add_argument("--output", choices=["json", "terminal", "both"], default="terminal")
    scan.add_argument("--output-file", help="Write the JSON report to this file")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="Relative path or glob to skip (repeatable), e.g. --exclude tests/fixtures")
    scan.add_argument("--include-venv", action="store_true",
                      help="Also scan local Python virtualenvs (directories containing pyvenv.cfg)")
    scan.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None,
                      help="Exit with code 1 if risk_level is at or above this level")
    sub.add_parser("rules", help="List all detection rules")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        from rich.console import Console
        from rich.table import Table
        table = Table(title="Detection rules")
        for col in ("Rule ID", "Severity", "Description"):
            table.add_column(col)
        for r in RULES:
            table.add_row(r.rule_id, r.severity, r.description)
        Console().print(table)
        return 0

    try:
        excludes = list(args.exclude)
        if args.output_file:
            # Never scan the scanner's own previous report (it quotes matched evidence).
            out_rel = os.path.relpath(os.path.abspath(args.output_file), os.path.abspath(args.path))
            if not out_rel.startswith(".."):
                excludes.append(out_rel.replace(os.sep, "/"))
        report = scan_path(args.path, excludes=excludes, include_venv=args.include_venv)
    except (NotADirectoryError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output in ("terminal", "both"):
        render_terminal(report)
    payload = to_json(report)
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        if args.output in ("terminal", "both"):
            print(f"JSON report written to {args.output_file}")
    elif args.output in ("json", "both"):
        print(payload)

    if args.fail_on:
        levels = ["CLEAN"] + SEVERITY_ORDER
        if levels.index(report["risk_level"]) >= levels.index(args.fail_on):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
