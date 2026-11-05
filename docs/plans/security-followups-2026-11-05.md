# Security queue review: rsa-handshake

## Scope and limits

Reviewed the four inherited queue rows against local `master` on 2026-11-05. Landed changes are source-reviewed only. No build, test, package, runtime, or remote CI was run; only `git diff --check` was used. The checked-in workflow trigger is `workflow_dispatch` only. The publish job condition still requires a `push` event, so dispatch does not currently execute publication. This repository-level observation does not establish GitHub settings or an approved release policy.

## Dispositions

| ID | Result | Evidence / rationale |
| --- | --- | --- |
| RH-1 | Applied, source-only | `cb015c0c` pins checkout, rust-cache, and rust-toolchain actions in the workflow and keeps checkout credentials disabled. Checkout and rust-cache release refs were verified against their upstream tag commits; the rust-toolchain pin is the verified upstream commit [e97e2d8](https://github.com/dtolnay/rust-toolchain/commit/e97e2d8cc328f1b50210efc529dca0028893a2d9). No workflow run was performed. |
| RH-2 | Policy required | The publish step supplies the registry token to `cargo publish`, which can run dependency build scripts; no isolated tokenless verification or dependency-lock policy was chosen. Keep publication disabled pending owner policy. |
| RH-3 | Follow-up retained | Add explicit PSS test vectors for non-byte-aligned modulus and maximum supported size. Tests were not added or run. |
| RH-4 | Policy required | The source implements RSA and the deprecation target contains a separate AES-128 implementation. Resolve whether this package remains publishable; no cryptographic policy was inferred. |

## Source commit

`cb015c0c` is on local `master`; the checkout remains ahead of its remote and was not pushed. No credentials, private paths, raw audit reports, or benchmark artifacts are included here.
