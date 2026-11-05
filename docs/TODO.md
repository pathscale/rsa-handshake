# TODO: rsa-handshake

This repository's inherited security queue was reviewed against current local `master`. Changes are source-reviewed only; no build, tests, runtime, or remote workflow was run. See [the disposition plan](plans/security-followups-2026-11-05.md).

- [ ] Decide whether and how the crate may publish: current workflow is manual-dispatch only, but the publish job itself is guarded by a push event and cannot publish from a manual run. Keep default automation off and establish tokenless verification plus a protected release path before enabling publication.
- [ ] Remove the registry token from any dependency build step during publishing; define whether a tracked lockfile is compatible with this library's release policy and how dependencies are verified.
- [ ] Add focused PSS coverage for the non-byte-aligned modulus edge and maximum supported modulus size, then verify independently. No such test was added or run in this cleanup.
- [ ] Resolve the cryptography policy for this deprecated RSA implementation, including the separate AES-128 implementation in the deprecation target; no policy decision was inferred.
