"""CLI entry point for agent-config-scan.

Usage:
    python3 -m agent_config_scan [dir]

Recursively scans *.json, *.yaml, *.yml and *.md files, skipping
.git, __pycache__ and node_modules, and prints one finding per line::

    SEVERITY file:line pattern-name -- explanation

Exit codes: 0 = no HIGH findings, 1 = at least one HIGH finding,
2 = usage error / directory missing.
"""

import os
import re
import sys
from dataclasses import dataclass, field

SCAN_EXTENSIONS = (".json", ".yaml", ".yml", ".md")
SKIP_DIRS = {".git", "__pycache__", "node_modules"}

SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Secret-looking value patterns. Findings report the pattern name and
# line only -- the matched value is NEVER printed.
SECRET_PATTERNS = [
    ("secret-openai-key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("secret-aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("secret-github-token", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    (
        "secret-private-key",
        re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----"),
    ),
]

SHELL_KEYWORDS = ("shell", "exec", "run_command")
RAW_INPUT_WORDS = ("user input", "arbitrary")
FETCH_KEYWORDS = ("fetch", "curl", "wget", "http")
ALLOWLIST_WORDS = ("allowlist", "allowed_domains", "allowed_hosts",
                   "allowed domain", "domain restriction", "allow-list")
WRITE_KEYWORDS = ("write", "write_file", "save_file")
TOOL_NAME_RE = re.compile(
    r"""["']?name["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./]+)""")
EVAL_EXEC_NAME_RE = re.compile(r"(eval|exec)", re.IGNORECASE)


@dataclass(order=True)
class Finding:
    sort_key: tuple = field(init=False, repr=False)
    severity: str
    path: str
    line: int
    pattern: str
    explanation: str

    def __post_init__(self):
        self.sort_key = (
            self.path,
            self.line,
            SEVERITY_RANK.get(self.severity, 3),
            self.pattern,
        )

    def format(self):
        return (
            f"{self.severity} {self.path}:{self.line} {self.pattern} "
            f"-- {self.explanation}"
        )


def _window(lines, index, before=2, after=1):
    """Join the lines around ``index`` (inclusive) for context checks."""
    start = max(0, index - before)
    end = min(len(lines), index + after + 1)
    return "\n".join(lines[start:end])


def scan_file(path, rel_path):
    """Scan one file, returning a list of Finding objects."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return findings  # unreadable / binary: skip silently

    lowered = [line.lower() for line in lines]

    for index, line in enumerate(lines):
        low = lowered[index]
        lineno = index + 1
        context = _window(lowered, index)

        # --- HIGH: permission-skip flags -------------------------------
        if "dangerously-skip-permissions" in low:
            findings.append(Finding(
                "HIGH", rel_path, lineno, "skip-permissions-flag",
                "dangerously-skip-permissions disables the permission "
                "gate; a prompt-injected agent can run anything."))
        elif "skip-permissions" in low:
            findings.append(Finding(
                "HIGH", rel_path, lineno, "skip-permissions-flag",
                "skip-permissions disables the permission gate; a "
                "prompt-injected agent can run anything."))

        # --- HIGH: secret-looking values (value never printed) --------
        for pattern_name, regex in SECRET_PATTERNS:
            if regex.search(line):
                findings.append(Finding(
                    "HIGH", rel_path, lineno, pattern_name,
                    "secret-looking value in a config file; move it to "
                    "an environment variable or secret store."))
                break  # one secret finding per line is enough

        # --- HIGH: shell/exec tool executing raw user/agent input -----
        if any(k in low for k in SHELL_KEYWORDS):
            if any(w in context for w in RAW_INPUT_WORDS):
                findings.append(Finding(
                    "HIGH", rel_path, lineno, "shell-exec-raw-input",
                    "shell/exec tool wired to raw user input; prompt "
                    "injection can turn into arbitrary command execution."))

        # --- MEDIUM: unrestricted network fetch tool ------------------
        if any(k in low for k in FETCH_KEYWORDS):
            if not any(w in context for w in ALLOWLIST_WORDS):
                findings.append(Finding(
                    "MEDIUM", rel_path, lineno, "fetch-no-allowlist",
                    "network fetch tool with no allowlist or domain "
                    "restriction mentioned nearby; can exfiltrate data "
                    "or fetch attacker-controlled content."))

        # --- MEDIUM: file write tool with wildcard scope --------------
        if any(k in low for k in WRITE_KEYWORDS) and "**" in context:
            findings.append(Finding(
                "MEDIUM", rel_path, lineno, "write-wildcard-scope",
                "file write tool scoped with a '**' glob; an injected "
                "prompt could overwrite files anywhere."))

        # --- MEDIUM: tool named like *eval* / *exec* -----------------
        match = TOOL_NAME_RE.search(low)
        if match and EVAL_EXEC_NAME_RE.search(match.group(1)):
            findings.append(Finding(
                "MEDIUM", rel_path, lineno, "eval-exec-tool-name",
                f"tool named '{match.group(1)}' suggests code "
                "evaluation/execution; audit its input handling."))

    # --- LOW: tool declared with no description nearby ----------------
    for index, line in enumerate(lines):
        low = lowered[index]
        match = TOOL_NAME_RE.search(low)
        if not match:
            continue
        nearby = "\n".join(lowered[max(0, index - 2):index + 3])
        if "description" not in nearby:
            findings.append(Finding(
                "LOW", rel_path, index + 1, "undocumented-tool",
                f"tool '{match.group(1)}' has no description; "
                "undocumented tools hide their blast radius from "
                "reviewers and from the agent itself."))

    # De-duplicate: one tool block (name line + description line) can
    # trip the same pattern twice; keep the first hit within 3 lines.
    findings.sort(key=lambda f: (f.line, SEVERITY_RANK[f.severity]))
    deduped = []
    for finding in findings:
        if any(
            other.pattern == finding.pattern
            and abs(other.line - finding.line) <= 3
            for other in deduped
        ):
            continue
        deduped.append(finding)
    return deduped


def scan_directory(root):
    """Walk ``root`` and return all findings, sorted by file/line."""
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in sorted(filenames):
            if not filename.lower().endswith(SCAN_EXTENSIONS):
                continue
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root)
            findings.extend(scan_file(full, rel))
    findings.sort(key=lambda f: f.sort_key)
    return findings


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("usage: python3 -m agent_config_scan <directory>",
              file=sys.stderr)
        return 2
    root = argv[0]
    if not os.path.isdir(root):
        print(f"error: directory not found: {root}", file=sys.stderr)
        return 2

    findings = scan_directory(root)
    for finding in findings:
        print(finding.format())

    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    print(f"findings: {len(findings)} (high: {high}, medium: {medium}, "
          f"low: {low})")
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
