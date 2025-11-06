use super::*;
use coset::iana::{self};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use std::ops::Deref;

impl CoseKeyExt for p384::ecdsa::VerifyingKey {
    fn alg() -> iana::Algorithm {
        iana::Algorithm::ES384
    }
}

impl EcdsaCoseKeyExt for p384::ecdsa::VerifyingKey {
    fn crv() -> iana::EllipticCurve {
        iana::EllipticCurve::P_384
    }
}

/// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
impl TryFrom<&p384::PublicKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: &p384::PublicKey) -> Result<Self, Self::Error> {
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
        let point = pk.to_encoded_point(false);
        let (x, y) = (
            point.x().ok_or(Self::Error::InvalidP384Key)?,
            point.y().ok_or(Self::Error::InvalidP384Key)?,
        );
        Ok(Self(
            coset::CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_384,
                x.to_vec(),
                y.to_vec(),
            )
            .build(),
        ))
    }
}

impl TryFrom<p384::PublicKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: p384::PublicKey) -> Result<Self, Self::Error> {
        (&pk).try_into()
    }
}

impl TryFrom<&p384::SecretKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: &p384::SecretKey) -> Result<Self, Self::Error> {
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
        let point = sk.public_key().to_encoded_point(false);
        let (x, y) = (
            point.x().ok_or(Self::Error::InvalidP384Key)?,
            point.y().ok_or(Self::Error::InvalidP384Key)?,
        );
        let d = sk.to_bytes();
        Ok(Self(
            coset::CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_384,
                x.to_vec(),
                y.to_vec(),
                d.to_vec(),
            )
            .build(),
        ))
    }
}

impl TryFrom<p384::SecretKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: p384::SecretKey) -> Result<Self, Self::Error> {
        (&sk).try_into()
    }
}

impl TryFrom<&p384::ecdsa::VerifyingKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(vk: &p384::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        let point = vk.to_encoded_point(false);
        let (x, y) = (
            point.x().ok_or(Self::Error::InvalidP384Key)?,
            point.y().ok_or(Self::Error::InvalidP384Key)?,
        );
        Ok(Self(
            coset::CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_384,
                x.to_vec(),
                y.to_vec(),
            )
            .algorithm(iana::Algorithm::ES384)
            .build(),
        ))
    }
}

impl TryFrom<p384::ecdsa::VerifyingKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(vk: p384::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        (&vk).try_into()
    }
}

impl TryFrom<&p384::ecdsa::SigningKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: &p384::ecdsa::SigningKey) -> Result<Self, Self::Error> {
        let point = sk.verifying_key().to_encoded_point(false);
        let (x, y) = (
            point.x().ok_or(Self::Error::InvalidP384Key)?,
            point.y().ok_or(Self::Error::InvalidP384Key)?,
        );
        let d = sk.to_bytes();
        Ok(Self(
            coset::CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_384,
                x.to_vec(),
                y.to_vec(),
                d.to_vec(),
            )
            .build(),
        ))
    }
}

impl TryFrom<p384::ecdsa::SigningKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: p384::ecdsa::SigningKey) -> Result<Self, Self::Error> {
        (&sk).try_into()
    }
}

/// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
impl TryFrom<&CoseKey> for p384::PublicKey {
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

        if crv != iana::EllipticCurve::P_384.to_i64() {
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

        use p384::elliptic_curve::Curve as _;
        const VERIFYING_KEY_LENGTH: usize = p384::NistP384::ORDER.bits() / 8;

        #[allow(clippy::unnecessary_fallible_conversions)]
        let x = x[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, x.len()))?;
        #[allow(clippy::unnecessary_fallible_conversions)]
        let y = y[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, y.len()))?;

        use p384::elliptic_curve::sec1::FromEncodedPoint as _;

        let point = p384::EncodedPoint::from_affine_coordinates(x, y, false);
        // we use this weird construct instead of `.into_option()` because a crate might enforce an
        // older version of subtle where the method is absent
        Option::from(Self::from_encoded_point(&point)).ok_or(CoseKeyError::InvalidP384Key)
    }
}

impl TryFrom<CoseKey> for p384::PublicKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

impl TryFrom<&CoseKey> for p384::SecretKey {
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

        if crv != iana::EllipticCurve::P_384.to_i64() {
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

        // read d
        let Some((_, Value::Bytes(d))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::Ec2KeyParameter::D.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'd' claim"));
        };

        use p384::elliptic_curve::Curve as _;
        const VERIFYING_KEY_LENGTH: usize = p384::NistP384::ORDER.bits() / 8;
        const SIGNING_KEY_LENGTH: usize = p384::NistP384::ORDER.bits() / 8;

        #[allow(clippy::unnecessary_fallible_conversions)]
        let x: [u8; VERIFYING_KEY_LENGTH] = x[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, x.len()))?;
        #[allow(clippy::unnecessary_fallible_conversions)]
        let y: [u8; VERIFYING_KEY_LENGTH] = y[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, y.len()))?;
        #[allow(clippy::unnecessary_fallible_conversions)]
        let d = d[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(SIGNING_KEY_LENGTH, d.len()))?;

        let sk = Self::from_bytes(d).map_err(|_| CoseKeyError::InvalidP384Key)?;

        let point = sk.public_key().to_encoded_point(false);
        let (point_x, point_y) = (
            point.x().ok_or(Self::Error::InvalidP384Key)?,
            point.y().ok_or(Self::Error::InvalidP384Key)?,
        );
        if point_x.deref() != x || point_y.deref() != y {
            return Err(CoseKeyError::MismatchPrivateKey);
        }

        Ok(sk)

        /*let point = p384::EncodedPoint::from_affine_coordinates(x, y, false);
        // we use this weird construct instead of `.into_option()` because a crate might enforce an
        // older version of subtle where the method is absent
        Option::from(Self::from_encoded_point(&point)).ok_or(CoseKeyError::InvalidP384Key)*/
    }
}

impl TryFrom<CoseKey> for p384::SecretKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

impl TryFrom<&CoseKey> for p384::ecdsa::VerifyingKey {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        // verify alg if present
        if let coset::CoseKey {
            alg: Some(Algorithm::Assigned(alg)),
            ..
        } = &key.0
            && *alg != iana::Algorithm::ES384
        {
            return Err(CoseKeyError::InvalidAlg(iana::Algorithm::ES384, *alg));
        };

        Ok(Self::from(p384::PublicKey::try_from(key)?))
    }
}

impl TryFrom<CoseKey> for p384::ecdsa::VerifyingKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

impl TryFrom<&CoseKey> for p384::ecdsa::SigningKey {
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

        if crv != iana::EllipticCurve::P_384.to_i64() {
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

        // read d
        let Some((_, Value::Bytes(d))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::Ec2KeyParameter::D.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'd' claim"));
        };

        use p384::elliptic_curve::Curve as _;
        const VERIFYING_KEY_LENGTH: usize = p384::NistP384::ORDER.bits() / 8;
        const SIGNING_KEY_LENGTH: usize = p384::NistP384::ORDER.bits() / 8;

        #[allow(clippy::unnecessary_fallible_conversions)]
        let x: [u8; VERIFYING_KEY_LENGTH] = x[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, x.len()))?;
        #[allow(clippy::unnecessary_fallible_conversions)]
        let y: [u8; VERIFYING_KEY_LENGTH] = y[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, y.len()))?;
        #[allow(clippy::unnecessary_fallible_conversions)]
        let d = d[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(SIGNING_KEY_LENGTH, d.len()))?;

        let sk = Self::from_bytes(d).map_err(|_| CoseKeyError::InvalidP384Key)?;

        let point = sk.verifying_key().to_encoded_point(false);
        let (point_x, point_y) = (
            point.x().ok_or(Self::Error::InvalidP384Key)?,
            point.y().ok_or(Self::Error::InvalidP384Key)?,
        );
        if point_x.deref() != x || point_y.deref() != y {
            return Err(CoseKeyError::MismatchPrivateKey);
        }

        Ok(sk)
    }
}

impl TryFrom<CoseKey> for p384::ecdsa::SigningKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_should_roundtrip() {
        let pk = p384::SecretKey::random(&mut rand::thread_rng()).public_key();
        let cose_key = CoseKey::try_from(pk).unwrap();
        let pk_from_cose = p384::PublicKey::try_from(&cose_key).unwrap();
        assert_eq!(pk, pk_from_cose);
    }

    #[test]
    fn secret_key_should_roundtrip() {
        let sk = p384::SecretKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(&sk).unwrap();
        let sk_from_cose = p384::SecretKey::try_from(&cose_key).unwrap();
        assert_eq!(sk, sk_from_cose);
    }

    #[test]
    fn verifying_key_should_roundtrip() {
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pk = sk.verifying_key();
        let cose_key = CoseKey::try_from(pk).unwrap();
        let pk_from_cose = p384::ecdsa::VerifyingKey::try_from(&cose_key).unwrap();
        assert_eq!(pk, &pk_from_cose);
    }

    #[test]
    fn signing_key_should_roundtrip() {
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(&sk).unwrap();
        let sk_from_cose = p384::ecdsa::SigningKey::try_from(&cose_key).unwrap();
        assert_eq!(sk, sk_from_cose);
    }

    #[test]
    fn can_build_public_key_from_private_cose_key() {
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(&sk).unwrap();
        p384::ecdsa::VerifyingKey::try_from(&cose_key).unwrap();

        let sk = p384::SecretKey::random(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(&sk).unwrap();
        p384::PublicKey::try_from(&cose_key).unwrap();
    }
}
