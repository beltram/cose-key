//! Examples from [RFC 9964 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9964#appendix-A.2)

use cose_key::{CoseKey, thumbprint::CoseKeyThumbprint};
use coset::{CoseSign1, TaggedCborSerializable as _, iana};
use ml_dsa::{Keypair as _, MlDsa44, SigningKey, VerifyingKey};
use signature::{Signer as _, Verifier as _};

/// Figure 6: ML_DSA_44
const ML_DSA_44: &str = include_str!("vectors/rfc9964-ml-dsa-44.json");

struct Vector {
    private: Vec<u8>,
    key: Vec<u8>,
    sign1: Vec<u8>,
    raw_to_be_signed: Vec<u8>,
    raw_signature: Vec<u8>,
    raw_public_key: Vec<u8>,
}

fn vector() -> Vector {
    let json: serde_json::Value = serde_json::from_str(ML_DSA_44).unwrap();
    let field = |name: &str| hex::decode(json[name].as_str().unwrap()).unwrap();
    Vector {
        private: field("priv"),
        key: field("key"),
        sign1: field("sign1"),
        raw_to_be_signed: field("raw_to_be_signed"),
        raw_signature: field("raw_signature"),
        raw_public_key: field("raw_public_key"),
    }
}

fn rfc_cose_key(v: &Vector) -> CoseKey {
    ciborium::from_reader::<CoseKey, _>(&v.key[..]).unwrap()
}

#[test]
fn should_decode_key() {
    let v = vector();
    let cose_key = rfc_cose_key(&v);

    assert_eq!(cose_key.kty, coset::KeyType::Assigned(iana::KeyType::AKP));
    assert_eq!(cose_key.alg(), Some(iana::Algorithm::ML_DSA_44));
    assert!(cose_key.is_private());

    // the RFC 'priv' is the seed and 'pub' must match the one derived from it
    let sk = SigningKey::<MlDsa44>::try_from(&cose_key).unwrap();
    assert_eq!(sk.as_seed().as_slice(), &v.private[..]);
    assert_eq!(sk.verifying_key().encode().as_slice(), &v.raw_public_key[..]);

    let vk = VerifyingKey::<MlDsa44>::try_from(&cose_key).unwrap();
    assert_eq!(vk.encode().as_slice(), &v.raw_public_key[..]);
}

#[test]
fn should_encode_key() {
    let v = vector();
    let rfc_key = rfc_cose_key(&v);

    let seed: [u8; 32] = v.private[..].try_into().unwrap();
    let sk = SigningKey::<MlDsa44>::from_seed(&seed.into());
    let mut cose_key = CoseKey::try_from(&sk).unwrap();
    cose_key.key_id = rfc_key.key_id.clone();

    assert_eq!(cose_key, rfc_key);
}

#[test]
fn kid_should_be_the_thumbprint() {
    let v = vector();
    let cose_key = rfc_cose_key(&v);

    // from the private CoseKey
    let thumbprint = CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(cose_key.clone()).unwrap();
    assert_eq!(&thumbprint[..], &cose_key.key_id[..]);

    // from the verifying key
    let vk = VerifyingKey::<MlDsa44>::try_from(&cose_key).unwrap();
    let thumbprint = CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(&vk).unwrap();
    assert_eq!(&thumbprint[..], &cose_key.key_id[..]);
}

#[test]
fn should_verify_sign1() {
    let v = vector();
    let cose_key = rfc_cose_key(&v);

    let sign1 = CoseSign1::from_tagged_slice(&v.sign1).unwrap();
    assert_eq!(
        sign1.protected.header.alg,
        Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_44))
    );
    assert_eq!(sign1.protected.header.key_id, cose_key.key_id);
    assert_eq!(sign1.tbs_data(b""), v.raw_to_be_signed);
    assert_eq!(sign1.signature, v.raw_signature);

    // with the private key
    sign1
        .verify_signature(b"", |sig, tbs| cose_key.verify(tbs, &sig.to_vec()))
        .unwrap();

    // with the public key only
    let mut public_cose_key = cose_key.clone();
    public_cose_key.as_public_cose_key();
    assert!(public_cose_key.is_public());
    sign1
        .verify_signature(b"", |sig, tbs| public_cose_key.verify(tbs, &sig.to_vec()))
        .unwrap();

    // from the raw public key
    let vk = VerifyingKey::<MlDsa44>::decode(&v.raw_public_key[..].try_into().unwrap());
    let raw_cose_key = CoseKey::try_from(vk).unwrap();
    raw_cose_key.verify(&v.raw_to_be_signed, &v.raw_signature).unwrap();

    // tampered payload must fail
    let mut tampered = sign1.clone();
    tampered.payload = Some(b"hello classical signatures".to_vec());
    assert!(
        tampered
            .verify_signature(b"", |sig, tbs| cose_key.verify(tbs, &sig.to_vec()))
            .is_err()
    );
}

#[test]
fn should_resign_sign1() {
    let v = vector();
    let cose_key = rfc_cose_key(&v);

    // ML-DSA deterministic signing (empty context) reproduces the RFC signature
    let signature = cose_key.sign(&v.raw_to_be_signed);
    assert_eq!(signature, v.raw_signature);

    let sign1 = CoseSign1::from_tagged_slice(&v.sign1).unwrap();
    let resigned = coset::CoseSign1Builder::new()
        .protected(sign1.protected.header.clone())
        .payload(sign1.payload.clone().unwrap())
        .create_signature(b"", |tbs| cose_key.sign(tbs))
        .build();
    assert_eq!(resigned.to_tagged_vec().unwrap(), v.sign1);
}
