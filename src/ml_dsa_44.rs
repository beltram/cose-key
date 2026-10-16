use super::*;
use ciborium::Value;
use coset::iana::{self, EnumI64};
use ml_dsa::{MlDsa44, SigningKey, VerifyingKey};

/// Size of an encoded ML-DSA-44 public key
/// see https://www.rfc-editor.org/rfc/rfc9964#section-5 (Table 1)
pub const ML_DSA_44_PUBLIC_KEY_LENGTH: usize = 1312;
/// Size of an ML-DSA private key, which is always the seed
/// see https://www.rfc-editor.org/rfc/rfc9964#section-4
pub const ML_DSA_SEED_LENGTH: usize = 32;

impl CoseKeyExt for VerifyingKey<MlDsa44> {
    fn alg() -> iana::Algorithm {
        iana::Algorithm::ML_DSA_44
    }
}

/// See https://www.rfc-editor.org/rfc/rfc9964#section-3
#[allow(clippy::infallible_try_from)] // required for specifying generic bounds because NIST P-curves conversion is fallible
impl TryFrom<&VerifyingKey<MlDsa44>> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: &VerifyingKey<MlDsa44>) -> Result<Self, Self::Error> {
        Ok(Self(
            coset::CoseKeyBuilder::new_mldsa_pub_key(coset::MlDsaVariant::MlDsa44, pk.encode().to_vec()).build(),
        ))
    }
}

#[allow(clippy::infallible_try_from)] // required for specifying generic bounds because NIST P-curves conversion is fallible
impl TryFrom<VerifyingKey<MlDsa44>> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(pk: VerifyingKey<MlDsa44>) -> Result<Self, Self::Error> {
        (&pk).try_into()
    }
}

#[allow(clippy::infallible_try_from)] // required for specifying generic bounds because NIST P-curves conversion is fallible
impl TryFrom<&SigningKey<MlDsa44>> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: &SigningKey<MlDsa44>) -> Result<Self, Self::Error> {
        use ml_dsa::Keypair as _;
        Ok(Self(
            coset::CoseKeyBuilder::new_mldsa_pub_key(
                coset::MlDsaVariant::MlDsa44,
                sk.verifying_key().encode().to_vec(),
            )
            .param(iana::AkpKeyParameter::Priv.to_i64(), Value::Bytes(sk.as_seed().to_vec()))
            .build(),
        ))
    }
}

#[allow(clippy::infallible_try_from)] // required for specifying generic bounds because NIST P-curves conversion is fallible
impl TryFrom<SigningKey<MlDsa44>> for CoseKey {
    type Error = CoseKeyError;

    fn try_from(sk: SigningKey<MlDsa44>) -> Result<Self, Self::Error> {
        (&sk).try_into()
    }
}

/// Verifies the 'kty' & 'alg' claims then reads the 'pub' claim
fn read_pub(key: &CoseKey) -> Result<&[u8; ML_DSA_44_PUBLIC_KEY_LENGTH], CoseKeyError> {
    let coset::CoseKey { alg, params, kty, .. } = &key.0;

    // verify kty
    if kty != &KeyType::Assigned(iana::KeyType::AKP) {
        return Err(CoseKeyError::InvalidKty);
    }

    // verify alg, which is REQUIRED for AKP keys
    match alg {
        Some(Algorithm::Assigned(iana::Algorithm::ML_DSA_44)) => {}
        Some(Algorithm::Assigned(alg)) => return Err(CoseKeyError::InvalidAlg(iana::Algorithm::ML_DSA_44, *alg)),
        Some(alg) => return Err(CoseKeyError::UnknownAlg(alg.clone())),
        None => return Err(CoseKeyError::MissingAlg),
    }

    // read pub
    let Some((_, Value::Bytes(public))) = params
        .iter()
        .find(|(k, _)| k == &Label::Int(iana::AkpKeyParameter::Pub.to_i64()))
    else {
        return Err(CoseKeyError::MissingKeyParam("Missing 'pub' claim"));
    };
    public[..]
        .try_into()
        .map_err(|_| CoseKeyError::InvalidKeyLength(ML_DSA_44_PUBLIC_KEY_LENGTH, public.len()))
}

impl TryFrom<&CoseKey> for VerifyingKey<MlDsa44> {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        let public = read_pub(key)?;
        Ok(Self::decode(&(*public).into()))
    }
}

impl TryFrom<CoseKey> for VerifyingKey<MlDsa44> {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

impl TryFrom<&CoseKey> for SigningKey<MlDsa44> {
    type Error = CoseKeyError;

    fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
        use ml_dsa::Keypair as _;

        let public = read_pub(key)?;

        // read priv
        let Some((_, Value::Bytes(seed))) = key
            .params
            .iter()
            .find(|(k, _)| k == &Label::Int(iana::AkpKeyParameter::Priv.to_i64()))
        else {
            return Err(CoseKeyError::MissingKeyParam("Missing 'priv' claim"));
        };
        // see https://www.rfc-editor.org/rfc/rfc9964#section-7.3
        let seed: [u8; ML_DSA_SEED_LENGTH] = seed[..]
            .try_into()
            .map_err(|_| CoseKeyError::InvalidKeyLength(ML_DSA_SEED_LENGTH, seed.len()))?;

        let sk = Self::from_seed(&seed.into());

        // see https://www.rfc-editor.org/rfc/rfc9964#section-7.4
        if sk.verifying_key().encode().as_slice() != public {
            return Err(CoseKeyError::MismatchPrivateKey);
        }

        Ok(sk)
    }
}

impl TryFrom<CoseKey> for SigningKey<MlDsa44> {
    type Error = CoseKeyError;

    fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
        (&key).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::Keypair as _;

    fn random_sk() -> SigningKey<MlDsa44> {
        SigningKey::from_seed(&rand::random::<[u8; ML_DSA_SEED_LENGTH]>().into())
    }

    #[test]
    fn public_key_should_roundtrip() {
        let pk = random_sk().verifying_key();
        let cose_key = CoseKey::try_from(&pk).unwrap();
        assert!(!cose_key.is_private());
        assert_eq!(cose_key.alg(), Some(iana::Algorithm::ML_DSA_44));
        let pk_from_cose = VerifyingKey::<MlDsa44>::try_from(&cose_key).unwrap();
        assert_eq!(pk, pk_from_cose);
    }

    #[test]
    fn private_key_should_roundtrip() {
        let sk = random_sk();
        let cose_key = CoseKey::try_from(&sk).unwrap();
        assert!(cose_key.is_private());
        let sk_from_cose = SigningKey::<MlDsa44>::try_from(&cose_key).unwrap();
        assert_eq!(sk.as_seed(), sk_from_cose.as_seed());
    }

    #[test]
    fn can_build_public_key_from_private_cose_key() {
        let sk = random_sk();
        let cose_key = CoseKey::try_from(&sk).unwrap();
        let pk = VerifyingKey::<MlDsa44>::try_from(&cose_key).unwrap();
        assert_eq!(pk, sk.verifying_key());
    }

    #[test]
    fn as_public_cose_key_should_strip_priv() {
        let sk = random_sk();
        let mut cose_key = CoseKey::try_from(&sk).unwrap();
        cose_key.as_public_cose_key();
        assert!(cose_key.is_public());
        assert_eq!(cose_key, CoseKey::try_from(sk.verifying_key()).unwrap());
    }

    #[test]
    fn should_fail_when_priv_does_not_match_pub() {
        let mut cose_key = CoseKey::try_from(random_sk()).unwrap();
        let other = CoseKey::try_from(random_sk()).unwrap();
        let priv_label = Label::Int(iana::AkpKeyParameter::Priv.to_i64());
        let other_priv = other.params.iter().find(|(k, _)| k == &priv_label).unwrap().1.clone();
        cose_key.params.retain(|(k, _)| k != &priv_label);
        cose_key.params.push((priv_label, other_priv));

        assert!(matches!(
            SigningKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::MismatchPrivateKey)
        ));
    }

    #[test]
    fn should_fail_when_priv_has_invalid_length() {
        let mut cose_key = CoseKey::try_from(random_sk()).unwrap();
        let priv_label = Label::Int(iana::AkpKeyParameter::Priv.to_i64());
        cose_key.params.retain(|(k, _)| k != &priv_label);
        cose_key.params.push((priv_label, Value::Bytes(vec![0; 64])));

        assert!(matches!(
            SigningKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::InvalidKeyLength(ML_DSA_SEED_LENGTH, 64))
        ));
    }

    #[test]
    fn should_fail_when_pub_has_invalid_length() {
        let mut cose_key = CoseKey::try_from(random_sk().verifying_key()).unwrap();
        let pub_label = Label::Int(iana::AkpKeyParameter::Pub.to_i64());
        cose_key.params.retain(|(k, _)| k != &pub_label);
        cose_key.params.push((pub_label, Value::Bytes(vec![0; 32])));

        assert!(matches!(
            VerifyingKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::InvalidKeyLength(ML_DSA_44_PUBLIC_KEY_LENGTH, 32))
        ));
    }

    #[test]
    fn should_fail_when_alg_missing() {
        let mut cose_key = CoseKey::try_from(random_sk()).unwrap();
        cose_key.alg = None;

        assert!(matches!(
            VerifyingKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::MissingAlg)
        ));
        assert!(matches!(
            SigningKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::MissingAlg)
        ));
    }

    #[test]
    fn should_fail_when_alg_mismatch() {
        let mut cose_key = CoseKey::try_from(random_sk()).unwrap();
        cose_key.alg = Some(Algorithm::Assigned(iana::Algorithm::ML_DSA_65));

        assert!(matches!(
            VerifyingKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::InvalidAlg(
                iana::Algorithm::ML_DSA_44,
                iana::Algorithm::ML_DSA_65
            ))
        ));
    }

    #[test]
    fn should_fail_when_kty_mismatch() {
        let mut cose_key = CoseKey::try_from(random_sk()).unwrap();
        cose_key.kty = KeyType::Assigned(iana::KeyType::OKP);

        assert!(matches!(
            VerifyingKey::<MlDsa44>::try_from(&cose_key),
            Err(CoseKeyError::InvalidKty)
        ));
    }
}
