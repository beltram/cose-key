use super::*;
use coset::iana::{self};

impl CoseKeyExt for p256::ecdsa::VerifyingKey {
    fn alg() -> iana::Algorithm {
        iana::Algorithm::ES256
    }
}

impl EcdsaCoseKeyExt for p256::ecdsa::VerifyingKey {
    fn crv() -> iana::EllipticCurve {
        iana::EllipticCurve::P_256
    }
}

/// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
impl TryFrom<&p256::PublicKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: &p256::PublicKey) -> Result<Self, Self::Error> {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let point = pk.to_encoded_point(false);
        let (x, y) = (
            point.x().ok_or(Self::Error::InvalidP256Key)?,
            point.y().ok_or(Self::Error::InvalidP256Key)?,
        );
        Ok(Self(
            coset::CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                x.to_vec(),
                y.to_vec(),
            )
            .build(),
        ))
    }
}

impl TryFrom<p256::PublicKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: p256::PublicKey) -> Result<Self, Self::Error> {
        (&pk).try_into()
    }
}

impl TryFrom<&p256::ecdsa::VerifyingKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(vk: &p256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        let point = vk.to_encoded_point(false);
        let (x, y) = (
            point.x().ok_or(Self::Error::InvalidP256Key)?,
            point.y().ok_or(Self::Error::InvalidP256Key)?,
        );
        Ok(Self(
            coset::CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                x.to_vec(),
                y.to_vec(),
            )
            .algorithm(iana::Algorithm::ES256)
            .build(),
        ))
    }
}

impl TryFrom<p256::ecdsa::VerifyingKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(vk: p256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        (&vk).try_into()
    }
}

impl TryFrom<&p256::ecdsa::SigningKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: &p256::ecdsa::SigningKey) -> Result<Self, Self::Error> {
        sk.as_ref().try_into()
    }
}

/// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
impl TryFrom<&CoseKey> for p256::PublicKey {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        let coset::CoseKey { params, kty, .. } = &key.0;

        // verify kty
        if kty != &coset::KeyType::Assigned(iana::KeyType::EC2) {
            return Err(CoseKeyError::InvalidKty);
        }

        // verify curve
        let Some((_, Value::Integer(crv))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))
        else {
            return Err(CoseKeyError::MissingCrv);
        };
        let crv: i64 = (*crv)
            .try_into()
            .map_err(CoseKeyError::InvalidCborIntegerClaimKey)?;

        if crv != iana::EllipticCurve::P_256.to_i64() {
            return Err(CoseKeyError::UnknownCurve(crv));
        }

        // read x & y
        let Some((_, Value::Bytes(x))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::Ec2KeyParameter::X.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
        };

        let Some((_, Value::Bytes(y))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::Ec2KeyParameter::Y.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'y' claim"));
        };

        use p256::elliptic_curve::Curve as _;
        const VERIFYING_KEY_LENGTH: usize = p256::NistP256::ORDER.bits() / 8;

        #[allow(clippy::unnecessary_fallible_conversions)]
        let x = x[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, x.len()))?;
        #[allow(clippy::unnecessary_fallible_conversions)]
        let y = y[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, y.len()))?;

        use p256::elliptic_curve::sec1::FromEncodedPoint as _;

        let point = p256::EncodedPoint::from_affine_coordinates(x, y, false);
        // we use this weird construct instead of `.into_option()` because a crate might enforce an
        // older version of subtle where the method is absent
        Option::from(Self::from_encoded_point(&point)).ok_or(CoseKeyError::InvalidP256Key)
    }
}

impl TryFrom<CoseKey> for p256::PublicKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

impl TryFrom<&CoseKey> for p256::ecdsa::VerifyingKey {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        let coset::CoseKey { alg: Some(alg), .. } = &key.0 else {
            return Err(CoseKeyError::MissingAlg);
        };

        // verify alg
        let coset::Algorithm::Assigned(alg) = alg else {
            return Err(CoseKeyError::UnknownAlg(alg.clone()));
        };
        if *alg != iana::Algorithm::ES256 {
            return Err(CoseKeyError::InvalidAlg(
                iana::Algorithm::ES256.to_i64(),
                alg.to_i64(),
            ));
        }

        Ok(Self::from(p256::PublicKey::try_from(key)?))
    }
}

impl TryFrom<CoseKey> for p256::ecdsa::VerifyingKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}
