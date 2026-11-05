# Security findings to revalidate: rsa-handshake

This queue carries forward candidate findings from a static review dated 2026-10-14. That review did not run the software. None of these findings has been revalidated against the current source in this checkout in this cleanup, so treat every item as unknown, not as a confirmed current defect.

For each item, compare the reported location with current source and workflow configuration. If it remains open, record the concrete owner task and expected focused evidence in the project TODO. If fixed or refuted, record the source evidence and remove the item. Do not copy historical exploit examples or private machine paths into public docs.

## Candidate findings

- [ ] Revalidate RH-1: (low): Publish job runs mutable-ref third-party actions before the step that holds CARGO_REGISTRY_TOKEN (reported location: .github/workflows/rust.yml:72 (token at line 75)). Current status: unknown.
- [ ] Revalidate RH-2: (low): cargo publish resolves unlocked dependencies with the registry token in env (reported location: .github/workflows/rust.yml:83). Current status: unknown.
- [ ] Revalidate RH-3: (info): No test vector covers PSS with modBits % 8 == 1 or 8192-bit PSS (reported location: tests/wycheproof.rs:36). Current status: unknown.
- [ ] Revalidate RH-4: (info): Policy conflict: the crate implements RSA, and the deprecation target also carries AES-128 (reported location: README.md:3). Current status: unknown.

## Review limit

This note preserves issue titles and the source locations reported at review time. It is not a source audit, fix plan, security certification, or publication clearance.
