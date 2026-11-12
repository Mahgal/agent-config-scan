# agent-config-scan

Coding agents now ship with tool and config files that can execute shell commands, fetch arbitrary URLs, and hold API keys — one prompt-injection away from a breach. This is a small, stdlib-only, offline CLI that scans your agent configs for those unsafe wiring patterns before you run them.

## Quick start

```bash
python3 -m agent_config_scan <directory>
```

Recursively scans `*.json`, `*.yaml`, `*.yml`, and `*.md` files (skips `.git`, `__pycache__`, `node_modules`) and prints one finding per line:

```
SEVERITY file:line pattern-name -- explanation
```

Exit codes: `0` = no HIGH findings, `1` = at least one HIGH finding, `2` = usage error / directory missing. A summary line is always printed last:

```
findings: N (high: H, medium: M, low: L)
```

## What it flags

| Severity | Pattern | Why it matters |
|---|---|---|
| HIGH | `shell-exec-raw-input` | Shell/exec tool wired to raw user/agent input — prompt injection becomes arbitrary command execution |
| HIGH | `skip-permissions-flag` | `dangerously-skip-permissions` / `skip-permissions` disables the permission gate |
| HIGH | `secret-openai-key`, `secret-aws-access-key`, `secret-github-token`, `secret-private-key` | Secret-looking value in a config file (the value itself is never printed, only the pattern name and line) |
| MEDIUM | `fetch-no-allowlist` | Network fetch tool with no allowlist / domain restriction nearby |
| MEDIUM | `write-wildcard-scope` | File write tool scoped with a `**` glob |
| MEDIUM | `eval-exec-tool-name` | Tool named like `*eval*` / `*exec*` |
| LOW | `undocumented-tool` | Tool declared with no description nearby |

## Example output

Risky fixtures (exit code 1):

```
$ python3 -m agent_config_scan examples/risky
HIGH agent.md:3 shell-exec-raw-input -- shell/exec tool wired to raw user input; prompt injection can turn into arbitrary command execution.
MEDIUM agent.md:3 eval-exec-tool-name -- tool named 'shell_exec' suggests code evaluation/execution; audit its input handling.
MEDIUM agent.md:4 fetch-no-allowlist -- network fetch tool with no allowlist or domain restriction mentioned nearby; can exfiltrate data or fetch attacker-controlled content.
HIGH agent.md:5 secret-aws-access-key -- secret-looking value in a config file; move it to an environment variable or secret store.
HIGH keys.yaml:1 secret-github-token -- secret-looking value in a config file; move it to an environment variable or secret store.
HIGH keys.yaml:3 secret-private-key -- secret-looking value in a config file; move it to an environment variable or secret store.
HIGH tools.json:2 secret-openai-key -- secret-looking value in a config file; move it to an environment variable or secret store.
HIGH tools.json:3 skip-permissions-flag -- dangerously-skip-permissions disables the permission gate; a prompt-injected agent can run anything.
HIGH tools.json:6 shell-exec-raw-input -- shell/exec tool wired to raw user input; prompt injection can turn into arbitrary command execution.
MEDIUM tools.json:10 fetch-no-allowlist -- network fetch tool with no allowlist or domain restriction mentioned nearby; can exfiltrate data or fetch attacker-controlled content.
MEDIUM tools.json:14 write-wildcard-scope -- file write tool scoped with a '**' glob; an injected prompt could overwrite files anywhere.
MEDIUM tools.json:20 eval-exec-tool-name -- tool named 'eval_code' suggests code evaluation/execution; audit its input handling.
LOW tools.json:23 undocumented-tool -- tool 'mystery_tool' has no description; undocumented tools hide their blast radius from reviewers and from the agent itself.
findings: 13 (high: 7, medium: 5, low: 1)
```

Clean fixture (exit code 0):

```
$ python3 -m agent_config_scan examples/clean
findings: 0 (high: 0, medium: 0, low: 0)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

8 tests, stdlib `unittest` only. See [SMOKE.md](SMOKE.md) for the recorded runs and exit codes.

## Limitations

Line-oriented heuristics, not a full parser: a tool whose description is far from its name, or a fetch tool with an allowlist defined in another file, can be mis-flagged. Treat findings as a review checklist, not a verdict.
