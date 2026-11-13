//! Snapshot tests guarding the wire format of every supported [CoseKey] and [CoseKeyThumbprint].
//!
//! Keys are generated with [Rng], a deterministic RNG, so that the snapshots are stable.
//! Each key gets a fresh RNG so that snapshots do not depend on the order in which they are generated.
#![cfg(not(target_family = "wasm"))]

use cose_key::{CoseKey, reexports::ciborium, thumbprint::CoseKeyThumbprint};
use dernged::Rng;

/// Deterministic key material, built from bytes rather than with `random()` so that snapshots do not depend on how
/// each library turns RNG output into a scalar.
fn seed<const N: usize>() -> [u8; N] {
    use rand::Rng as _;
    let mut seed = [0; N];
    Rng::default().fill_bytes(&mut seed);
    seed
}

mod ed25519 {
    use super::*;

    fn keypair() -> (CoseKey, CoseKey) {
        let sk = ed25519_dalek::SigningKey::generate(&mut Rng::default());
        (
            CoseKey::try_from(&sk).unwrap(),
            CoseKey::try_from(&sk.verifying_key()).unwrap(),
        )
    }

    #[test]
    fn cose_key() {
        let (private, public) = keypair();
        snapshot_keypair("ed25519", private, public);
    }

    #[test]
    fn thumbprint() {
        let (private, public) = keypair();
        snapshot_thumbprints("ed25519", private, public);
    }
}

mod p256 {
    use super::*;

    fn keypair() -> (CoseKey, CoseKey) {
        let sk = ::p256::SecretKey::from_slice(&seed::<32>()).unwrap();
        (
            CoseKey::try_from(&sk).unwrap(),
            CoseKey::try_from(&sk.public_key()).unwrap(),
        )
    }

    #[test]
    fn cose_key() {
        let (private, public) = keypair();
        snapshot_keypair("p256", private, public);
    }

    #[test]
    fn ecdsa_cose_key() {
        let sk = ::p256::ecdsa::SigningKey::from_slice(&seed::<32>()).unwrap();
        let private = CoseKey::try_from(&sk).unwrap();
        let public = CoseKey::try_from(sk.verifying_key()).unwrap();
        snapshot_keypair("p256_ecdsa", private, public);
    }

    #[test]
    fn thumbprint() {
        let (private, public) = keypair();
        snapshot_thumbprints("p256", private, public);
    }
}

mod p384 {
    use super::*;

    fn keypair() -> (CoseKey, CoseKey) {
        let sk = ::p384::SecretKey::from_slice(&seed::<48>()).unwrap();
        (
            CoseKey::try_from(&sk).unwrap(),
            CoseKey::try_from(&sk.public_key()).unwrap(),
        )
    }

    #[test]
    fn cose_key() {
        let (private, public) = keypair();
        snapshot_keypair("p384", private, public);
    }

    #[test]
    fn ecdsa_cose_key() {
        let sk = ::p384::ecdsa::SigningKey::from_slice(&seed::<48>()).unwrap();
        let private = CoseKey::try_from(&sk).unwrap();
        let public = CoseKey::try_from(sk.verifying_key()).unwrap();
        snapshot_keypair("p384_ecdsa", private, public);
    }

    #[test]
    fn thumbprint() {
        let (private, public) = keypair();
        snapshot_thumbprints("p384", private, public);
    }
}

mod bls {
    use super::*;

    fn keypair() -> (CoseKey, CoseKey) {
        let sk = bls_signatures::PrivateKey::generate(&mut dernged01::Rng::default());
        (
            CoseKey::try_from(&sk).unwrap(),
            CoseKey::try_from(&sk.public_key()).unwrap(),
        )
    }

    #[test]
    fn cose_key() {
        let (private, public) = keypair();
        snapshot_keypair("bls12381g1", private, public);
    }

    #[test]
    fn thumbprint() {
        let (private, public) = keypair();
        snapshot_thumbprints("bls12381g1", private, public);
    }
}

fn cbor_hex(key: &CoseKey) -> String {
    let mut buf = vec![];
    ciborium::into_writer(key, &mut buf).unwrap();
    hex::encode(buf)
}

/// Snapshots the private [CoseKey], its public counterpart and verifies [CoseKey::as_public_cose_key]
/// yields the very same public key.
fn snapshot_keypair(name: &str, private: CoseKey, public: CoseKey) {
    assert!(private.is_private());
    assert!(public.is_public());

    let mut stripped = private.clone();
    stripped.as_public_cose_key();
    assert_eq!(stripped, public);

    insta::assert_snapshot!(format!("{name}_private"), cbor_hex(&private));
    insta::assert_snapshot!(format!("{name}_public"), cbor_hex(&public));
}

/// Snapshots the thumbprint of a key for every supported hasher and verifies a private key and its public
/// counterpart yield the same thumbprint.
fn snapshot_thumbprints(name: &str, private: CoseKey, public: CoseKey) {
    macro_rules! thumbprint {
        ($len:literal, $hasher:ty, $suffix:literal) => {{
            let tp = CoseKeyThumbprint::<$len>::compute::<$hasher>(public.clone()).unwrap();
            let tp_from_private = CoseKeyThumbprint::<$len>::compute::<$hasher>(private.clone()).unwrap();
            assert_eq!(tp.to_string(), tp_from_private.to_string());
            insta::assert_snapshot!(format!("{name}_thumbprint_{}", $suffix), tp);
        }};
    }

    thumbprint!(32, sha2::Sha256, "sha256");
    thumbprint!(32, sha2::Sha512_256, "sha512_256");
    thumbprint!(48, sha2::Sha384, "sha384");
    thumbprint!(64, sha2::Sha512, "sha512");
}
