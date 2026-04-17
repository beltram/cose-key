//! Serialization.
//! Given ciborium does not implement deterministic encoding as defined in https://datatracker.ietf.org/doc/html/rfc8949#section-4.2
//!

use crate::CoseKey;
use coset::{AsCborValue as _, KeyType, Label, iana, iana::EnumI64 as _};

impl serde::Serialize for CoseKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let value = self.0.clone().to_cbor_value().map_err(S::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CoseKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use ciborium::Value;
        use serde::de::Error as _;

        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        #[allow(unused_mut)]
        let mut cose_key = Self(coset::CoseKey::from_cbor_value(value).map_err(D::Error::custom)?);

        // we try to deduce the verifying key(s) from the signing key
        match cose_key.kty {
            #[cfg(feature = "ed25519")]
            KeyType::Assigned(iana::KeyType::OKP) => {
                let (mut d, mut x, mut crv) = (None, None, None);

                cose_key.params.iter().for_each(|(label, value)| match (label, value) {
                    (Label::Int(i), Value::Bytes(b)) if *i == iana::OkpKeyParameter::D.to_i64() => {
                        d.replace(b);
                    }
                    (Label::Int(i), Value::Bytes(b)) if *i == iana::OkpKeyParameter::X.to_i64() => {
                        x.replace(b);
                    }
                    (Label::Int(i), Value::Integer(c))
                        if *i == iana::OkpKeyParameter::Crv.to_i64()
                            && let Some(c) = iana::EllipticCurve::from_i64(i128::from(*c) as i64) =>
                    {
                        crv.replace(c);
                    }
                    _ => {}
                });

                // unless X is already set, we try deducing it
                if x.is_none()
                    && crv == Some(iana::EllipticCurve::Ed25519)
                    && let Some(d) = d
                {
                    let d = d[..]
                        .try_into()
                        .map_err(|_| D::Error::custom("invalid OKP private key size"))?;
                    let sk = ed25519_dalek::SigningKey::from_bytes(d);
                    cose_key.params.push((
                        Label::Int(iana::OkpKeyParameter::X.to_i64()),
                        Value::Bytes(sk.verifying_key().as_bytes().into()),
                    ));
                }
            }
            #[cfg(any(feature = "p256", feature = "p384"))]
            KeyType::Assigned(iana::KeyType::EC2) => {
                let (mut d, mut x, mut y, mut crv) = (None, None, None, None);

                cose_key.params.iter().for_each(|(label, value)| match (label, value) {
                    (Label::Int(i), Value::Bytes(b)) if *i == iana::Ec2KeyParameter::D.to_i64() => {
                        d.replace(b);
                    }
                    (Label::Int(i), Value::Bytes(b)) if *i == iana::Ec2KeyParameter::X.to_i64() => {
                        x.replace(b);
                    }
                    (Label::Int(i), Value::Bytes(b)) if *i == iana::Ec2KeyParameter::Y.to_i64() => {
                        y.replace(b);
                    }
                    (Label::Int(i), Value::Integer(c))
                        if *i == iana::Ec2KeyParameter::Crv.to_i64()
                            && let Some(c) = iana::EllipticCurve::from_i64(i128::from(*c) as i64) =>
                    {
                        crv.replace(c);
                    }
                    _ => {}
                });

                // unless X and Y are already set, we try deducing them
                if x.is_none()
                    && y.is_none()
                    && let Some(d) = d
                {
                    match crv {
                        #[cfg(feature = "p256")]
                        Some(iana::EllipticCurve::P_256) => {
                            let sk = p256::ecdsa::SigningKey::from_bytes(d[..].into()).map_err(D::Error::custom)?;

                            let point = sk.verifying_key().to_encoded_point(false);
                            let (x, y) = (point.x(), point.y());
                            let x = x.ok_or(D::Error::custom("Invalid x point while deserializing a P256 CoseKey"))?;
                            let y = y.ok_or(D::Error::custom("Invalid y point while deserializing a P256 CoseKey"))?;

                            cose_key
                                .params
                                .push((Label::Int(iana::Ec2KeyParameter::X as i64), Value::Bytes(x.to_vec())));
                            cose_key
                                .params
                                .push((Label::Int(iana::Ec2KeyParameter::Y as i64), Value::Bytes(y.to_vec())));
                        }
                        #[cfg(feature = "p384")]
                        Some(iana::EllipticCurve::P_384) => {
                            let sk = p384::ecdsa::SigningKey::from_bytes(d[..].into()).map_err(D::Error::custom)?;

                            let point = sk.verifying_key().to_encoded_point(false);
                            let (x, y) = (point.x(), point.y());
                            let x = x.ok_or(D::Error::custom("Invalid x point while deserializing a P384 CoseKey"))?;
                            let y = y.ok_or(D::Error::custom("Invalid y point while deserializing a P384 CoseKey"))?;

                            cose_key
                                .params
                                .push((Label::Int(iana::Ec2KeyParameter::X as i64), Value::Bytes(x.to_vec())));
                            cose_key
                                .params
                                .push((Label::Int(iana::Ec2KeyParameter::Y as i64), Value::Bytes(y.to_vec())));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        Ok(cose_key)
    }
}

impl CoseKey {
    pub fn as_slim(&self) -> CoseKeySlim<'_> {
        CoseKeySlim(self)
    }
}

/// Used solely for serialization. It trims the public encoded points for curves where they can be
/// inferred from the private key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CoseKeySlim<'a>(&'a CoseKey);

impl serde::Serialize for CoseKeySlim<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let mut key: CoseKey = self.0.clone();
        match &key.kty {
            KeyType::Assigned(iana::KeyType::OKP) => key
                .0
                .params
                .retain(|(label, _)| *label != Label::Int(iana::OkpKeyParameter::X.to_i64())),
            KeyType::Assigned(iana::KeyType::EC2) => key.0.params.retain(|(label, _)| {
                *label != Label::Int(iana::Ec2KeyParameter::X.to_i64())
                    || *label != Label::Int(iana::Ec2KeyParameter::Y.to_i64())
            }),
            _ => {}
        }
        key.0.to_cbor_value().map_err(S::Error::custom)?.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    #[test]
    fn ed25519_ser_de_should_roundtrip() {
        let ed25519_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(ed25519_sk).unwrap();
        let ser_value = Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let cose_key_slim = cose_key.as_slim();
        let ser_value = Value::serialized(&cose_key_slim).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key_slim, de.as_slim());

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key.as_slim(), &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }

    #[test]
    fn p256_ser_de_should_roundtrip() {
        let p256_sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(p256_sk).unwrap();
        let ser_value = Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let cose_key_slim = cose_key.as_slim();
        let ser_value = Value::serialized(&cose_key_slim).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key_slim, de.as_slim());

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key.as_slim(), &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }

    #[test]
    fn p384_ser_de_should_roundtrip() {
        let p384_sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(p384_sk).unwrap();
        let ser_value = Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let cose_key_slim = cose_key.as_slim();
        let ser_value = Value::serialized(&cose_key_slim).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key_slim, de.as_slim());

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key.as_slim(), &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }

    #[test]
    fn bls12_381_ser_de_should_roundtrip() {
        let bls12_381_sk = bls_signatures::PrivateKey::generate(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(bls12_381_sk).unwrap();
        let ser_value = Value::serialized(&cose_key).unwrap();
        let de = ser_value.deserialized::<CoseKey>().unwrap();
        assert_eq!(cose_key, de);

        let mut ser_bytes = vec![];
        ciborium::into_writer(&cose_key, &mut ser_bytes).unwrap();
        let de = ciborium::from_reader::<CoseKey, _>(&ser_bytes[..]).unwrap();
        assert_eq!(cose_key, de);
    }
}
