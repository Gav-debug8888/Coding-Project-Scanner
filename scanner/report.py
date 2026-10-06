"""Terminal (rich) and JSON rendering of scan reports."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFORMATIONAL": "white",
}
LEVEL_STYLES = {**SEVERITY_STYLES, "CLEAN": "bold green"}


def to_json(report: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(report, indent=indent, ensure_ascii=False)


def render_terminal(report: Dict[str, Any], console: Optional[Console] = None) -> None:
    console = console or Console(highlight=False)

    header = Text()
    header.append("Safe Coding-Project Scanner\n", style="bold")
    header.append(f"Project:   {report['project']}\n")
    header.append(f"Path:      {report['scanned_path']}\n")
    header.append(f"Scanned:   {report['scan_timestamp']}\n")
    header.append(f"Files:     {report.get('files_scanned', 0)} scanned")
    console.print(Panel(header, title="STATIC SCAN", border_style="blue", expand=False))

    findings = report["findings"]
    if not findings:
        console.print("[green]No findings.[/green]")
    for i, f in enumerate(findings, start=1):
        style = SEVERITY_STYLES.get(f["severity"], "white")
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        body = Text()
        body.append("File:        ", style="bold")
        body.append(f"{loc}\n")
        body.append("Evidence:    ", style="bold")
        body.append(f"{f['matched_text']}\n")
        body.append("Why:         ", style="bold")
        body.append(f"{f['explanation']}\n")
        body.append("Remediation: ", style="bold")
        body.append(f["remediation"])
        console.print(Panel(body, title=Text(f"[{i}] {f['severity']}  {f['rule_id']}", style=style),
                            border_style=style, title_align="left"))

    level = report["risk_level"]
    lstyle = LEVEL_STYLES.get(level, "white")
    footer = Text()
    footer.append("Risk score: ", style="bold")
    footer.append(f"{report['risk_score']}\n", style=lstyle)
    footer.append("Risk level: ", style="bold")
    footer.append(f"{level}\n", style=lstyle)
    footer.append("Findings:   ", style="bold")
    footer.append(f"{report['total_findings']}\n")
    footer.append(report["summary"])
    console.print(Panel(footer, title="RESULT", border_style=lstyle, expand=False))
    for skipped in report.get("skipped_paths", []):
        console.print(Text(f"Skipped: {skipped} - use --include-venv to scan it", style="dim"))
    console.print(Text(report["disclaimer"], style="italic dim"))
