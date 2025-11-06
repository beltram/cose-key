//! Serialization.
//! Given ciborium does not implement deterministic encoding as defined in https://datatracker.ietf.org/doc/html/rfc8949#section-4.2
//!

use crate::CoseKey;
use coset::AsCborValue as _;
use serde::{Deserializer, Serializer};

impl serde::Serialize for CoseKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let value = self.0.clone().to_cbor_value().map_err(S::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CoseKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = <ciborium::Value as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self(
            coset::CoseKey::from_cbor_value(value).map_err(D::Error::custom)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_ser_de_should_roundtrip() {
        let ed25519_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let cose_key = CoseKey::from(ed25519_sk);
        let ser_value = ciborium::Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }

    #[test]
    fn p256_ser_de_should_roundtrip() {
        let p256_sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(p256_sk).unwrap();
        let ser_value = ciborium::Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }

    #[test]
    fn p384_ser_de_should_roundtrip() {
        let p384_sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(p384_sk).unwrap();
        let ser_value = ciborium::Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }

    #[test]
    fn bls12_381_ser_de_should_roundtrip() {
        let bls12_381_sk = bls_signatures::PrivateKey::generate(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(bls12_381_sk).unwrap();
        let ser_value = ciborium::Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }
}
