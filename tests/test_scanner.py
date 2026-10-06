"""Unit tests for the Safe Coding-Project Scanner.

Fixture repos live in tests/fixtures (harmless SIMULATION content). Rule-level
tests build tiny throwaway repos in pytest's tmp_path. Sensitive keywords are
assembled by concatenation so this file does not trigger the scanner itself.
"""
import json
import os
import stat
from pathlib import Path

import pytest

from scanner.rules import RULES, url_issue
from scanner.scanner import DISCLAIMER, main, risk_level_for, scan_path

FIXTURES = Path(__file__).parent / "fixtures"
REQUIRED_KEYS = {
    "schema_version", "project", "scanned_path", "scan_timestamp", "risk_score",
    "risk_level", "total_findings", "findings", "summary", "disclaimer",
}
FINDING_KEYS = {"rule_id", "severity", "file", "line", "matched_text", "explanation", "remediation"}
ALL_FIXTURES = ["clean-project", "vscode-task-project", "encoded-script-project",
                "install-hook-project", "multi-warning-project"]


def scan(name):
    return scan_path(str(FIXTURES / name))


def rule_ids(report):
    return {f["rule_id"] for f in report["findings"]}


def finding(report, rule_id):
    return next(f for f in report["findings"] if f["rule_id"] == rule_id)


def make_repo(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
    return tmp_path


# --------------------------------------------------------------------------- required fixture tests
def test_clean_project_is_clean():
    report = scan("clean-project")
    assert report["risk_level"] == "CLEAN"
    assert report["total_findings"] == 0
    assert report["risk_score"] == 0


def test_vscode_task_project():
    report = scan("vscode-task-project")
    f = finding(report, "VSCODE_AUTO_TASK")
    assert f["severity"] == "HIGH"
    assert f["file"] == ".vscode/tasks.json"
    assert "folderOpen" in f["matched_text"]
    assert rule_ids(report) == {"VSCODE_AUTO_TASK"}


def test_encoded_script_project():
    report = scan("encoded-script-project")
    assert "ENCODED_CONTENT" in rule_ids(report)
    assert "DYNAMIC_EVAL" in rule_ids(report)
    assert finding(report, "ENCODED_CONTENT")["severity"] == "MEDIUM"


def test_install_hook_project():
    report = scan("install-hook-project")
    f = finding(report, "PKG_INSTALL_SCRIPT")
    assert f["severity"] == "HIGH"
    assert "postinstall" in f["matched_text"]
    assert f["line"] == 7


def test_multi_warning_project_is_critical():
    report = scan("multi-warning-project")
    assert report["risk_level"] == "CRITICAL"
    assert report["composite_rule_triggered"] is True
    assert {"PKG_INSTALL_SCRIPT", "VSCODE_AUTO_TASK", "ENCODED_CONTENT", "CREDENTIAL_ACCESS",
            "NETWORK_IN_SETUP", "DYNAMIC_EVAL"} <= rule_ids(report)


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_json_output_matches_schema(name, tmp_path, capsys):
    out = tmp_path / "report.json"
    assert main(["scan", str(FIXTURES / name), "--output", "json", "--output-file", str(out)]) == 0
    data = json.loads(out.read_text())
    assert REQUIRED_KEYS <= data.keys()
    assert data["schema_version"] == "1.0"
    assert data["project"] == name
    assert os.path.isabs(data["scanned_path"])
    assert isinstance(data["risk_score"], int)
    assert data["total_findings"] == len(data["findings"])
    for f in data["findings"]:
        assert FINDING_KEYS <= f.keys()
        assert len(f["matched_text"]) <= 120


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_disclaimer_always_present(name, capsys):
    main(["scan", str(FIXTURES / name), "--output", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["disclaimer"] == DISCLAIMER


# --------------------------------------------------------------------------- scoring / CLI
@pytest.mark.parametrize("score,level", [(0, "CLEAN"), (1, "INFORMATIONAL"), (9, "INFORMATIONAL"),
                                         (10, "LOW"), (24, "LOW"), (25, "MEDIUM"), (49, "MEDIUM"),
                                         (50, "HIGH"), (99, "HIGH"), (100, "CRITICAL")])
def test_risk_thresholds(score, level):
    assert risk_level_for(score) == level


def test_every_rule_has_required_metadata():
    assert len(RULES) == 15
    for r in RULES:
        d = r.to_dict()
        for key in ("rule_id", "description", "severity", "file_pattern", "evidence_location",
                    "possible_false_positives", "recommended_review_action"):
            assert d[key], f"{r.rule_id} missing {key}"


def test_terminal_output_runs(capsys):
    assert main(["scan", str(FIXTURES / "multi-warning-project"), "--output", "terminal"]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "Static analysis cannot prove" in out


def test_fail_on_exit_code():
    assert main(["scan", str(FIXTURES / "multi-warning-project"), "--output", "json",
                 "--output-file", os.devnull, "--fail-on", "HIGH"]) == 1
    assert main(["scan", str(FIXTURES / "clean-project"), "--output", "json",
                 "--output-file", os.devnull, "--fail-on", "HIGH"]) == 0


def test_missing_path_returns_error():
    assert main(["scan", "/nonexistent/definitely/missing"]) == 2


def test_git_directory_is_skipped(tmp_path):
    make_repo(tmp_path, {".git/hooks/post-checkout.sh": "#!/bin/sh\necho hi\n"})
    assert scan_path(str(tmp_path))["total_findings"] == 0


def test_exclude_option(tmp_path):
    make_repo(tmp_path, {"vendor/setup.py": "import os\nos.system('echo SIMULATION')\n"})
    assert scan_path(str(tmp_path), excludes=["vendor"])["total_findings"] == 0


# --------------------------------------------------------------------------- per-rule unit tests
SSH_KEY = "~/." + "ssh/id_" + "rsa"
RULE_CASES = {
    "SETUP_PY_CMDCLASS": {"setup.py": "from setuptools import setup\nsetup(name='x', cmdclass={'install': X})\n"},
    "VSCODE_SETTINGS_EXEC": {".vscode/settings.json": '{"terminal.integrated.defaultProfile.linux": "sim"}'},
    "SHELL_IN_SETUP": {"setup.py": "import subprocess\nsubprocess.run(['echo', 'SIMULATION'])\n"},
    "OBFUSCATED_JS": {"index.js": "eval(ato" + "b('Y29uc29sZS5sb2coIlNJTVVMQVRJT04iKQ=='));\n"},
    "CREDENTIAL_ACCESS": {"collect.py": f"path = '{SSH_KEY}'\n"},
    "NETWORK_IN_SETUP": {"setup.py": "import urllib.request\n"},
    "UNUSUAL_DEPENDENCY_URL": {"requirements.txt": "simpkg @ git+http://example.invalid/sim.git\n"},
    "MAKEFILE_PHONY": {"Makefile": "all:\n\techo SIMULATION\n"},
    "CI_SECRETS_EXPOSURE": {".github/workflows/x.yml": "jobs:\n  a:\n    steps:\n"
                            "      - run: echo ${{ secrets.SIM_KEY }} > leak.txt\n"},
    "POLYGLOT_FILE": {"logo.png": b"<script>alert('SIMULATION')</script>"},
}


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_rule_detects_simulated_case(tmp_path, rule_id):
    report = scan_path(str(make_repo(tmp_path, RULE_CASES[rule_id])))
    assert rule_id in rule_ids(report)


def test_hidden_executable(tmp_path):
    make_repo(tmp_path, {".helper": "#!/bin/sh\necho SIMULATION\n"})
    p = tmp_path / ".helper"
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    assert "HIDDEN_EXECUTABLE" in rule_ids(scan_path(str(tmp_path)))


def test_composite_upgrades_to_critical(tmp_path):
    # install hook (HIGH) + network call in setup.py (HIGH) -> CRITICAL even though score is 50
    make_repo(tmp_path, {
        "package.json": '{"scripts": {"preinstall": "echo SIMULATION"}}',
        "setup.py": "import urllib.request\n",
    })
    report = scan_path(str(tmp_path))
    assert report["risk_level"] == "CRITICAL"
    assert report["risk_score"] >= 100


def test_single_network_finding_does_not_trigger_composite(tmp_path):
    make_repo(tmp_path, {"setup.py": "import urllib.request\n"})
    report = scan_path(str(tmp_path))
    assert report["composite_rule_triggered"] is False
    assert report["risk_level"] == "MEDIUM"


# --------------------------------------------------------------------------- false-positive guards
def test_dynamic_eval_ignored_in_test_dirs(tmp_path):
    make_repo(tmp_path, {"tests/test_x.py": "exec('1 + 1')\n"})
    assert "DYNAMIC_EVAL" not in rule_ids(scan_path(str(tmp_path)))


def test_regex_exec_method_not_flagged(tmp_path):
    make_repo(tmp_path, {"app.py": "import re\nre.compile('a').match('a')\ncursor.exec('x')\n"})
    assert scan_path(str(tmp_path))["total_findings"] == 0


def test_process_env_not_credential_access(tmp_path):
    make_repo(tmp_path, {"app.js": "const port = process.env.PORT || 3000;\n"})
    assert "CREDENTIAL_ACCESS" not in rule_ids(scan_path(str(tmp_path)))


def test_valid_png_not_polyglot(tmp_path):
    make_repo(tmp_path, {"img.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64})
    assert scan_path(str(tmp_path))["total_findings"] == 0


def test_url_issue_logic():
    assert url_issue("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz") is None
    assert url_issue("git+https://github.com/org/repo.git#" + "a" * 40) is None
    assert "pinned" in url_issue("git+https://github.com/org/repo.git")
    assert "HTTP" in url_issue("http://pypi.org/simple")
    assert "non-standard" in url_issue("https://pkgs.example.invalid/simple")


def test_local_virtualenv_skipped_but_reported(tmp_path):
    from scanner.scanner import scan_path
    venv = tmp_path / ".venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (venv / "lib" / "mod.py").write_text("ex" "ec(open('x').read())\n")
    report = scan_path(str(tmp_path))
    assert report["risk_level"] == "CLEAN"
    assert report["skipped_paths"] == [".venv/ (local Python virtualenv)"]
    assert scan_path(str(tmp_path), include_venv=True)["total_findings"] >= 1


def test_dir_named_venv_without_marker_is_still_scanned(tmp_path):
    from scanner.scanner import scan_path
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "evil.py").write_text("ex" "ec(open('x').read())\n")
    assert scan_path(str(tmp_path))["total_findings"] >= 1


def test_output_file_inside_repo_is_not_scanned(tmp_path):
    from scanner.scanner import main
    (tmp_path / "report.json").write_text('{"matched_text": "~/.ss' 'h/id_r' 'sa"}')
    assert main(["scan", str(tmp_path), "--output", "json", "--output-file",
                 str(tmp_path / "report.json"), "--fail-on", "LOW"]) == 0
