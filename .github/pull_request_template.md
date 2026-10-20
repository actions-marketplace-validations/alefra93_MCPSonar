## What and why

<!-- One concern per PR. Link the issue it fixes, if any. -->

## How it was tested

- [ ] `pytest -q` and `ruff check src tests` pass locally
- [ ] New behavior / fixed bug has a test (a fix includes a test that fails without it)
- [ ] Tests use only local servers / mocks — no external network, no third-party MCP packages

## Security and compatibility

- [ ] Touches auth, `websec.py`, `netpolicy.py`, `redact.py`, stdio or probes → threat explained below and covered by a test
- [ ] No credentials (real or realistic-looking) in code, tests, fixtures or screenshots
- [ ] User-visible or API behavior change → `CHANGELOG.md` (Unreleased) and docs updated

<!-- Security notes / compatibility impact: -->
