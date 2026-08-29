# file-tunnel-test/contract-conformance-tests

Deterministic state-model, idempotency, serialization, and protocol contract conformance tests.

This repository is the `contract` deep-test suite for `file-tunnel`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

The initial model is executable rather than a placeholder. Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle.

## Paired desktop contract

The DEN-3384 desktop adapter treats the Rust and Flutter applications as one release unit. It assembles their feature manifests against the canonical JSON Schema, requires identical ordered feature/status pairs, and verifies that both dependency graphs pin the same immutable `ftnl-interfaces` commit. CI checks out the three source revisions recorded in `fixtures/desktop-contract-sources.json`; branch names and moving tags are deliberately rejected as evidence.

To verify existing local checkouts without requiring network access:

```bash
PYTHONPATH=src python -m deep_tests.desktop_contract \
  --interfaces /path/to/ftnl-interfaces \
  --rust /path/to/ftnl-desktop-app.rs \
  --flutter /path/to/ftnl-flutter \
  --source-lock fixtures/desktop-contract-sources.json
```

Pass `--verify-git-revisions` when each checkout is at the exact revision in the source lock, as CI does.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
