"""Actionable remediation advice for each rule."""
from __future__ import annotations

from typing import Dict, List

REMEDIATION: Dict[str, List[str]] = {
    "PKG_INSTALL_SCRIPT": [
        "Open the project in a disposable VM before running npm install.",
        "Inspect the postinstall script manually (and any file it calls).",
        "Consider using `npm install --ignore-scripts`.",
    ],
    "SETUP_PY_CMDCLASS": [
        "Read every custom command class in setup.py before running pip install.",
        "Prefer installing from a reviewed wheel, or use `pip download --no-deps` and inspect the sdist offline.",
        "Install only inside a disposable, network-isolated virtual machine.",
    ],
    "VSCODE_AUTO_TASK": [
        "Open the project in VS Code Restricted Mode (File -> Open Folder as Restricted).",
        "Review tasks.json before trusting the workspace.",
        "Keep `task.allowAutomaticTasks` set to \"off\" in your user settings.",
    ],
    "VSCODE_SETTINGS_EXEC": [
        "Do not trust the workspace until the terminal/interpreter overrides in .vscode/settings.json are reviewed.",
        "Confirm any interpreter or shell path points to a standard system binary, not a file inside the repo.",
    ],
    "SHELL_IN_SETUP": [
        "Identify the exact command that setup.py/setup.cfg executes and why it is needed.",
        "Never run `pip install .` or `python setup.py` on an untrusted project outside a sandbox.",
    ],
    "ENCODED_CONTENT": [
        "Decode and review the content manually before allowing execution.",
        "Use `base64 -d` or Python's base64 module to inspect - print the result, never execute it.",
    ],
    "OBFUSCATED_JS": [
        "Deobfuscate the eval/Function argument statically and read the plaintext.",
        "Do not run `node` or `npm` commands in this project until the decoded code is understood.",
    ],
    "DYNAMIC_EVAL": [
        "Treat eval/exec as high-risk.",
        "Read the argument carefully; never run in a production environment.",
    ],
    "CREDENTIAL_ACCESS": [
        "Never open untrusted projects while authenticated with production credentials.",
        "Use a dedicated test account with no production access.",
        "Revoke any credentials that may have been exposed.",
    ],
    "NETWORK_IN_SETUP": [
        "Audit the network call destination before proceeding.",
        "Use a network-isolated sandbox environment.",
    ],
    "HIDDEN_EXECUTABLE": [
        "Read the hidden script and search the repo for anything that invokes it (hooks, tasks, package scripts).",
        "Remove the executable bit (`chmod -x`) until the file has been reviewed.",
    ],
    "UNUSUAL_DEPENDENCY_URL": [
        "Verify the registry/host is legitimate and owned by the expected organisation.",
        "Pin git dependencies to a full 40-character commit hash and prefer HTTPS sources.",
    ],
    "MAKEFILE_PHONY": [
        "Run `make -n` (dry run) to print the commands without executing them.",
        "Review the `all`/`install` recipes before invoking make.",
    ],
    "CI_SECRETS_EXPOSURE": [
        "Do not approve or run this workflow until the step writing secrets is removed.",
        "Rotate any secret that was in scope if the workflow already ran.",
        "Require maintainer approval for workflows triggered from forks.",
    ],
    "POLYGLOT_FILE": [
        "Inspect the file with `file` and a hex viewer.",
        "Search the codebase for code that reads or executes this asset.",
    ],
}

DEFAULT_REMEDIATION = ["Review the flagged file manually inside a disposable, network-isolated environment."]


def get_remediation_steps(rule_id: str) -> List[str]:
    return REMEDIATION.get(rule_id, DEFAULT_REMEDIATION)


def get_remediation(rule_id: str) -> str:
    return " ".join(get_remediation_steps(rule_id))
