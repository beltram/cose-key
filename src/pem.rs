use crate::{CoseKey, CoseKeyError};
use ciborium::Value;
use coset::iana::EnumI64;
use coset::{Algorithm, KeyType, Label, iana};

impl CoseKey {
    pub fn from_public_key_pem<
        K: pkcs8::DecodePublicKey + TryInto<Self, Error = E>,
        E: Into<CoseKeyError>,
    >(
        s: &str,
    ) -> Result<Self, CoseKeyError> {
        K::from_public_key_pem(s)?.try_into().map_err(Into::into)
    }
}

impl pkcs8::EncodePublicKey for CoseKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        let coset::CoseKey {
            alg: Some(alg),
            params,
            kty,
            ..
        } = &self.0
        else {
            return Err(pkcs8::spki::Error::AlgorithmParametersMissing);
        };

        let crv = |params: &[(Label, Value)], label: i64, expected: iana::EllipticCurve| {
            params
                .iter()
                .find_map(|(k, v)| (k == &Label::Int(label)).then_some(v))
                .map(|v| matches!(v, Value::Integer(crv) if crv == &expected.to_i64().into()))
                .unwrap_or_default()
        };

        match (kty, alg, params) {
            #[cfg(feature = "ed25519")]
            (
                KeyType::Assigned(iana::KeyType::OKP),
                Algorithm::Assigned(iana::Algorithm::EdDSA),
                p,
            ) if crv(
                p,
                iana::OkpKeyParameter::Crv.to_i64(),
                iana::EllipticCurve::Ed25519,
            ) =>
            {
                ed25519_dalek::VerifyingKey::try_from(self)
                    .map_err(|_| pkcs8::spki::Error::KeyMalformed)?
                    .to_public_key_der()
            }
            #[cfg(feature = "p256")]
            (
                KeyType::Assigned(iana::KeyType::EC2),
                Algorithm::Assigned(iana::Algorithm::ES256),
                p,
            ) if crv(
                p,
                iana::OkpKeyParameter::Crv.to_i64(),
                iana::EllipticCurve::P_256,
            ) =>
            {
                p256::ecdsa::VerifyingKey::try_from(self)
                    .map_err(|_| pkcs8::spki::Error::KeyMalformed)?
                    .to_public_key_der()
            }
            #[cfg(feature = "p384")]
            (
                KeyType::Assigned(iana::KeyType::EC2),
                Algorithm::Assigned(iana::Algorithm::ES384),
                p,
            ) if crv(
                p,
                iana::OkpKeyParameter::Crv.to_i64(),
                iana::EllipticCurve::P_384,
            ) =>
            {
                p384::ecdsa::VerifyingKey::try_from(self)
                    .map_err(|_| pkcs8::spki::Error::KeyMalformed)?
                    .to_public_key_der()
            }
            _ => Err(pkcs8::spki::Error::KeyMalformed),
        }
    }
}
