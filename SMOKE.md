# SMOKE.md — recorded runs (2026-11-12)

All commands run from the project root
`~/workspace/github-factory/2026-11-12/agent-config-scan/`.

## Tests

```
$ python3 -m unittest discover -s tests -v
Ran 8 tests in 0.961s

OK
```

- Tests passed: **8 / 8**
- Exit code: **0**

Coverage: HIGH on skip-permissions flag; HIGH on secret pattern without
leaking the value; MEDIUM on unrestricted fetch tool; LOW on undocumented
tool; clean config exits 0; missing directory exits 2; usage error exits 2;
allowlisted fetch is not flagged.

## Demo: risky fixtures

```
$ python3 -m agent_config_scan examples/risky
```

- Exit code: **1**
- Findings: **13 (high: 7, medium: 5, low: 1)**

## Demo: clean fixture

```
$ python3 -m agent_config_scan examples/clean
findings: 0 (high: 0, medium: 0, low: 0)
```

- Exit code: **0**
- Findings: **0 (high: 0, medium: 0, low: 0)**

## Error path

```
$ python3 -m agent_config_scan /nope
error: directory not found: /nope
```

- Exit code: **2**

Note: the fixture "secrets" in `examples/risky/` are planted fakes
(`sk-TESTFIXTURE…`, the AWS documentation example key
`AKIAIOSFODNN7EXAMPLE`, a fake `ghp_` token, and a private-key header
with no key material). No real credentials were used or printed anywhere.
