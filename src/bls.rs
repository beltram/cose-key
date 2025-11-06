use super::*;
use bls_signatures::{PrivateKey as BbsPrivateKey, PublicKey as BbsPublicKey};
use coset::iana::{self};

// requested assignments as per https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-08#section-4.2
const TBD_BLS12381G1: i64 = 13;
#[allow(dead_code)]
const TBD_BLS12381G2: i64 = 14;
#[allow(dead_code)]
const TBD_BLS48581G1: i64 = 15;
#[allow(dead_code)]
const TBD_BLS48581G2: i64 = 16;

impl CoseKeyExt for BbsPublicKey {
    fn alg() -> iana::Algorithm {
        iana::Algorithm::EdDSA
    }
}

/*impl EcdsaCoseKeyExt for BbsPublicKey {
    fn crv() -> iana::EllipticCurve {
        // TODO: we cannot publish this crate by depending on a git fork of coset so let's wait a bit
        // it should be: BLS12381G2 (13 requested)
        iana::EllipticCurve::Ed25519
    }
}*/

impl TryFrom<&BbsPublicKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: &BbsPublicKey) -> Result<Self, Self::Error> {
        let x = pk.as_affine().to_compressed();
        Ok(Self(
            coset::CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::Integer(TBD_BLS12381G1.into()),
                )
                .param(iana::OkpKeyParameter::X.to_i64(), Value::Bytes(x.into()))
                .build(),
        ))
    }
}

impl TryFrom<BbsPublicKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: BbsPublicKey) -> Result<Self, Self::Error> {
        (&pk).try_into()
    }
}

impl TryFrom<&BbsPrivateKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: &BbsPrivateKey) -> Result<Self, Self::Error> {
        let x = sk.public_key().as_affine().to_compressed();
        let d = bls_signatures::Serialize::as_bytes(sk);
        Ok(Self(
            coset::CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::Integer(TBD_BLS12381G1.into()),
                )
                .param(iana::OkpKeyParameter::X.to_i64(), Value::Bytes(x.into()))
                .param(iana::OkpKeyParameter::D.to_i64(), Value::Bytes(d))
                .build(),
        ))
    }
}

impl TryFrom<BbsPrivateKey> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: BbsPrivateKey) -> Result<Self, Self::Error> {
        (&pk).try_into()
    }
}

impl TryFrom<&CoseKey> for BbsPublicKey {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        let coset::CoseKey { params, kty, .. } = &key.0;

        // verify kty
        if kty != &KeyType::Assigned(iana::KeyType::OKP) {
            return Err(CoseKeyError::InvalidKty);
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

        if crv != TBD_BLS12381G1 {
            return Err(CoseKeyError::UnknownCurve(crv));
        }

        // read x
        let Some((_, Value::Bytes(x))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::OkpKeyParameter::X.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
        };
        let x = x[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(48, x.len()))?;

        use bls_signatures::Serialize as _;
        Ok(Self::from_bytes(x)?)
    }
}

impl TryFrom<CoseKey> for BbsPublicKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

impl TryFrom<&CoseKey> for BbsPrivateKey {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        let coset::CoseKey { params, kty, .. } = &key.0;

        // verify kty
        if kty != &KeyType::Assigned(iana::KeyType::OKP) {
            return Err(CoseKeyError::InvalidKty);
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

        if crv != TBD_BLS12381G1 {
            return Err(CoseKeyError::UnknownCurve(crv));
        }

        // read x
        let Some((_, Value::Bytes(x))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::OkpKeyParameter::X.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
        };
        let x: [u8; 48] = x[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(48, x.len()))?;

        // read d
        let Some((_, Value::Bytes(d))) = params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::OkpKeyParameter::D.to_i64()))
        else {
            return Err(CoseKeyError::MissingPoint("Missing 'd' claim"));
        };
        let d = d[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(32, d.len()))?;

        use bls_signatures::Serialize as _;
        let sk = Self::from_bytes(d)?;
        let expected_x = sk.public_key().as_affine().to_compressed();
        if x != expected_x {
            return Err(CoseKeyError::MismatchPrivateKey);
        }

        Ok(sk)
    }
}

impl TryFrom<CoseKey> for BbsPrivateKey {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

#[cfg(test)]
mod tests {
    use crate::CoseKey;

    #[test]
    fn public_key_should_roundtrip() {
        let pk = bls_signatures::PrivateKey::generate(&mut rand::thread_rng()).public_key();
        let cose_key = CoseKey::try_from(&pk).unwrap();
        let pk_from_cose = bls_signatures::PublicKey::try_from(cose_key).unwrap();
        assert_eq!(pk, pk_from_cose);
    }

    #[test]
    fn private_key_should_roundtrip() {
        let sk = bls_signatures::PrivateKey::generate(&mut rand::thread_rng());
        let cose_key = CoseKey::try_from(&sk).unwrap();
        let sk_from_cose = bls_signatures::PrivateKey::try_from(cose_key).unwrap();
        assert_eq!(sk, sk_from_cose);
    }
}
