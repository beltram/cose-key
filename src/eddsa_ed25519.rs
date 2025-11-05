use super::*;
use ciborium::Value;
use coset::iana::{self, EnumI64};

impl CoseKeyExt for ed25519_dalek::VerifyingKey {
    fn alg() -> iana::Algorithm {
        iana::Algorithm::EdDSA
    }
}

impl EcdsaCoseKeyExt for ed25519_dalek::VerifyingKey {
    fn crv() -> iana::EllipticCurve {
        iana::EllipticCurve::Ed25519
    }
}

/// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
impl From<&ed25519_dalek::VerifyingKey> for CoseKey {
    fn from(pk: &ed25519_dalek::VerifyingKey) -> Self {
        Self(
            coset::CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::Bytes(pk.as_bytes().into()),
                )
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::Integer(iana::EllipticCurve::Ed25519.to_i64().into()),
                )
                .build(),
        )
    }
}

impl From<ed25519_dalek::VerifyingKey> for CoseKey {
    fn from(pk: ed25519_dalek::VerifyingKey) -> Self {
        (&pk).into()
    }
}

impl From<&ed25519_dalek::SigningKey> for CoseKey {
    fn from(sk: &ed25519_dalek::SigningKey) -> Self {
        sk.verifying_key().into()
    }
}

/// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
impl TryFrom<&CoseKey> for ed25519_dalek::VerifyingKey {
    type Error = CoseKeyError;

    fn try_from(key: &crate::CoseKey) -> Result<Self, Self::Error> {
        let coset::CoseKey {
            alg: Some(alg),
            params,
            kty,
            ..
        } = &key.0
        else {
            return Err(CoseKeyError::MissingAlg);
        };

        // verify kty
        if kty != &coset::KeyType::Assigned(iana::KeyType::OKP) {
            return Err(CoseKeyError::InvalidKty);
        }

        // verify alg
        let coset::Algorithm::Assigned(alg) = alg else {
            return Err(CoseKeyError::UnknownAlg(alg.clone()));
        };
        if *alg != iana::Algorithm::EdDSA {
            return Err(CoseKeyError::InvalidAlg(
                iana::Algorithm::EdDSA.to_i64(),
                alg.to_i64(),
            ));
        }

        // verify curve
        let Some((_, Value::Integer(crv))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::OkpKeyParameter::Crv.to_i64()))
        else {
            return Err(CoseKeyError::MissingCrv);
        };
        let crv: i64 = (*crv)
            .try_into()
            .map_err(CoseKeyError::InvalidCborIntegerClaimKey)?;

        if crv != iana::EllipticCurve::Ed25519.to_i64() {
            return Err(CoseKeyError::UnknownCurve(crv));
        }

        // read x
        let Some((_, Value::Bytes(x))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::OkpKeyParameter::X.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
        };
        let x = x[..].try_into().map_err(|_| {
            CoseKeyError::InvalidKeyLength(ed25519_dalek::PUBLIC_KEY_LENGTH, x.len())
        })?;
        Ok(Self::from_bytes(x)?)
    }
}

impl TryFrom<crate::CoseKey> for ed25519_dalek::VerifyingKey {
    type Error = CoseKeyError;

    fn try_from(key: crate::CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}
