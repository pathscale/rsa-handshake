//! Allocation-free RSA-PSS verification for TLS 1.3 RSA encryption keys.
//!
//! Callers must construct the RFC 8446 CertificateVerify message and validate
//! the certificate, negotiated signature scheme, and certificate chain.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bigint;
mod der;
mod pss;

use core::fmt;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Supported TLS 1.3 PSS hashes. MGF1 uses the same hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hash {
    /// SHA-256 with a 32-byte salt.
    Sha256,
    /// SHA-384 with a 48-byte salt.
    Sha384,
    /// SHA-512 with a 64-byte salt.
    Sha512,
}

/// A parsing or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The input is not canonical DER of the required type.
    Der,
    /// The key violates the modulus or exponent policy.
    Key,
    /// The supplied digest has the wrong length.
    DigestLength,
    /// The signature or PSS encoding is invalid.
    Verification,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Der => "invalid DER",
            Self::Key => "unsupported RSA key",
            Self::DigestLength => "incorrect digest length",
            Self::Verification => "invalid RSA-PSS signature",
        })
    }
}

impl core::error::Error for Error {}

/// A fixed-storage RSA public key with a 2048 through 8192-bit odd modulus.
///
/// Only exponent 65537 is accepted. This deliberately limits the arithmetic
/// and verification cost to a single audited public-exponent operation.
pub struct RsaPublicKey {
    modulus: bigint::Number,
    r2: bigint::Number,
    limbs: usize,
    bits: usize,
    inverse: u64,
}

impl RsaPublicKey {
    /// Parse a canonical PKCS#1 `RSAPublicKey`, without trailing bytes.
    pub fn from_der(input: &[u8]) -> Result<Self, Error> {
        let modulus = der::public_key(input)?;
        let first = *modulus.first().ok_or(Error::Key)?;
        let bits = modulus.len() * 8 - first.leading_zeros() as usize;
        if !(2048..=8192).contains(&bits) || modulus.last().is_none_or(|byte| byte & 1 == 0) {
            return Err(Error::Key);
        }
        let limbs = modulus.len().div_ceil(8);
        let modulus = bigint::decode(modulus)?;
        let inverse = bigint::inverse(bigint::word(&modulus, 0));
        let r2 = bigint::r2(&modulus, limbs)?;
        Ok(Self {
            modulus,
            r2,
            limbs,
            bits,
            inverse,
        })
    }

    /// Parse canonical SPKI with `rsaEncryption` and exactly NULL parameters.
    pub fn from_spki_der(input: &[u8]) -> Result<Self, Error> {
        Self::from_der(der::spki(input)?)
    }

    /// Verify PSS over a message, with MGF1 and salt matching `hash`.
    pub fn verify_pss(&self, hash: Hash, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        match hash {
            Hash::Sha256 => self.verify_pss_prehashed(hash, &Sha256::digest(msg), sig),
            Hash::Sha384 => self.verify_pss_prehashed(hash, &Sha384::digest(msg), sig),
            Hash::Sha512 => self.verify_pss_prehashed(hash, &Sha512::digest(msg), sig),
        }
    }

    /// Verify PSS over an already computed digest of exactly the hash length.
    ///
    /// The caller is responsible for hashing the complete intended message.
    pub fn verify_pss_prehashed(&self, hash: Hash, digest: &[u8], sig: &[u8]) -> Result<(), Error> {
        let expected = match hash {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        };
        if digest.len() != expected {
            return Err(Error::DigestLength);
        }
        let k = self.bits.div_ceil(8);
        if sig.len() != k {
            return Err(Error::Verification);
        }
        let signature = bigint::decode(sig)?;
        if !bigint::less(&signature, &self.modulus, self.limbs) {
            return Err(Error::Verification);
        }
        let result = bigint::exponentiate(self, &signature)?;
        let mut encoded = [0u8; 1024];
        let encoded = encoded.get_mut(..k).ok_or(Error::Verification)?;
        bigint::encode(&result, encoded);
        match hash {
            Hash::Sha256 => pss::verify::<Sha256>(digest, encoded, self.bits),
            Hash::Sha384 => pss::verify::<Sha384>(digest, encoded, self.bits),
            Hash::Sha512 => pss::verify::<Sha512>(digest, encoded, self.bits),
        }
    }
}

/// Map only TLS `rsa_pss_rsae_*` schemes to their hash.
///
/// Schemes 0x0809 through 0x080b require RSASSA-PSS OID keys and are rejected.
pub const fn tls13_scheme(scheme: u16) -> Option<Hash> {
    match scheme {
        0x0804 => Some(Hash::Sha256),
        0x0805 => Some(Hash::Sha384),
        0x0806 => Some(Hash::Sha512),
        _ => None,
    }
}
