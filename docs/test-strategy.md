# Deep test strategy

## Scope

Suite: `contract`
Test organization: `file-tunnel-test`
Primary organization: `file-tunnel`

## Invariants

- every randomized test uses an explicit deterministic seed;
- retries, duplicates, migrations, and rejected inputs are observable assertions, not sleeps;
- test data is synthetic and contains no production credentials or customer payloads;
- the suite runs without network access by default;
- a product adapter must preserve the reference model and publish the seed and minimized trace on failure;
- scheduled CI is defense in depth; pull-request and main-branch checks remain authoritative.

## Expansion path

1. Add a versioned adapter for the primary repository contract.
2. Add sanitized golden fixtures owned by the canonical interface repository.
3. Run the same trace against the reference model and implementation.
4. Retain failing seeds as regression tests.
5. Link behavior changes to the matching Linear issue and repository PR.

## Paired desktop gate

The desktop adapter is a versioned cross-repository test, not a network-dependent unit test. Offline tests generate synthetic schemas, manifests, and dependency files to exercise negative vectors. CI checks out immutable commits for the public `ftnl-interfaces` and `ftnl-desktop-app.rs` repositories. The cross-organization token cannot read private `ftnl-flutter`, so its exact commit, interface pin, and feature manifest are carried as a sanitized reviewable evidence record. This keeps product credentials out of the test organization while preserving the release snapshot.

The gate fails closed when a source lock uses a mutable ref, Flutter evidence disagrees with that lock, either client pins a different interface commit, a manifest omits or reorders a schema feature, evidence violates the schema boundary, or Rust and Flutter report different statuses. Evidence prose may differ because each client owns its implementation details; the feature identifiers and statuses may not.

## Worker contract gate

The worker adapter tests only the public contract surface at an immutable `ftnl-interfaces` commit. The private worker repository is deliberately outside the public test organization's checkout graph. Shared Auth service identity, File Tunnel product authorization, storage capabilities, and provider credentials therefore cannot leak into this job.

The gate normalizes the independently authored server JSON Schema and TypeSpec models and requires exact field, optionality, reference, pattern, and numeric-bound agreement. It verifies the parity receipt against every generated file digest, asserts that Node exports server types while browser and edge bundles do not, checks stable Protobuf field numbers and validation options, and compiles a descriptor with a pinned Protobuf compiler. Synthetic positive and negative payloads exercise the same closed-object, identifier, digest, workload, and output-size limits without customer data or network calls.
