# rsa-handshake

Verify-only RSASSA-PSS for the TLS 1.3 server CertificateVerify, and nothing
else.

A TLS 1.3 client that keeps its own key exchange and record layer on ECC and
ChaCha20-Poly1305 still meets servers whose certificate key is RSA. For those,
one RSA operation per connection cannot be avoided: checking the server's
signature over the handshake transcript. This crate is that one operation.

## Scope

- RSASSA-PSS verification (RFC 8017, section 8.1.2) with SHA-256, SHA-384 or
  SHA-512, MGF1 with the same hash, salt length equal to the hash length, as
  RFC 8446 requires for `rsa_pss_rsae_sha256`, `_sha384` and `_sha512`.
- Public keys from DER `RSAPublicKey` (PKCS#1) or `SubjectPublicKeyInfo`
  with `rsaEncryption` and NULL parameters.

Not here, by design: signing, private keys, key generation, encryption,
decryption, PKCS#1 v1.5 outside certificate signatures, and the `rsa_pss_pss_*` schemes. With no private key
anywhere, timing attacks on RSA decryption (Marvin and its relatives) have
nothing to reach.

## Policy

- Modulus 2048 to 8192 bits, odd. Anything outside is rejected.
- Public exponent exactly 65537. Every certificate on the public web uses it,
  and fixing it keeps the exponentiation to 16 squarings and one multiply.
- Strict DER: minimal lengths, minimal positive integers, no trailing bytes at
  any level.
- The signature must be exactly the modulus length and less than the modulus.
- The salt length is checked exactly, not inferred.

## Properties

`#![no_std]`, no `alloc`, `#![forbid(unsafe_code)]`. The only dependency is
`sha2`. The arithmetic is a small fixed-limb Montgomery multiplication in
`src/bigint.rs`; all of its inputs are public, so it is not constant-time and
does not need to be.

## Usage

```rust,ignore
use rsa_handshake::{RsaPublicKey, tls13_scheme};

let key = RsaPublicKey::from_spki_der(spki)?;
let hash = tls13_scheme(scheme).ok_or(MyError::Scheme)?;
// `message` is the RFC 8446 section 4.4.3 CertificateVerify input:
// 64 spaces, the context string, a zero byte, the transcript hash.
key.verify_pss(hash, message, signature)?;
```

The caller still validates the certificate chain and the negotiated scheme.

## Chain certificates

Certificate authorities sign RSA certificates with RSASSA-PKCS1-v1_5
(`sha256WithRSAEncryption` and the SHA-384 and SHA-512 variants).
`verify_pkcs1v15` checks those, for certificate signatures only. It builds the
single valid encoding (`00 01 FF..FF 00 DigestInfo hash`, at least 8 bytes of
`FF`, DigestInfo with explicit NULL parameters) and compares it whole; nothing
in the decoded block is parsed, so lenient-parser forgeries have nothing to
work with. TLS 1.3 forbids PKCS#1 v1.5 for CertificateVerify; use
`verify_pss` there.

## Tests

`cargo test` runs every Wycheproof RSASSA-PKCS1-v1_5 vector for 2048 to 8192-bit
keys (keys with exponents other than 65537 are skipped; legacy "acceptable"
encodings are rejected) and every Wycheproof RSA-PSS vector vendored in `tests/data`
(2048, 3072 and 4096-bit keys; SHA-256, SHA-384 and SHA-512; salt equal to the
hash length) and negative tests for the key policy, DER strictness and
signature handling.

## License

MIT OR Apache-2.0. The PSS verification structure follows RustCrypto
[`rsa`](https://github.com/RustCrypto/RSA), MIT OR Apache-2.0, noted in
`src/pss.rs`. Test vectors are from
[Wycheproof](https://github.com/C2SP/wycheproof), Apache-2.0.
