use crate::CoseKey;
use ciborium::Value;
use coset::iana;
use coset::{KeyType, Label};
use iana::EnumI64 as _;
#[allow(unused_imports)]
use signature::SignatureEncoding as _;
use signature::{Signer, Verifier};

#[cfg(all(
    feature = "signature",
    not(any(feature = "ed25519", feature = "p256", feature = "p384"))
))]
compile_error!(
    "At least one feature ['ed25519', 'p256', 'p384'] has to be enabled alongside 'signature' feature"
);

impl Signer<Vec<u8>> for CoseKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        match &self.kty {
            KeyType::Assigned(iana::KeyType::OKP) => {
                let Some((_, Value::Integer(crv))) = self
                    .params
                    .iter()
                    .find(|(label, _)| label == &Label::Int(iana::OkpKeyParameter::Crv.to_i64()))
                else {
                    return Err(signature::Error::from_source("Missing 'crv' claim"));
                };
                let crv: i64 = (*crv)
                    .try_into()
                    .map_err(|_| signature::Error::from_source("Invalid crv"))?;
                match iana::EllipticCurve::from_i64(crv) {
                    Some(iana::EllipticCurve::Ed25519) => {
                        if cfg!(feature = "ed25519") {
                            let sk = ed25519_dalek::SigningKey::try_from(self).map_err(|_| {
                                signature::Error::from_source("Invalid Ed25519 CoseKey")
                            })?;
                            Ok(sk.try_sign(msg)?.to_vec())
                        } else {
                            Err(signature::Error::from_source(
                                "You must turn on the 'ed25519' feature to use this",
                            ))
                        }
                    }
                    _ => Err(signature::Error::from_source("Unsupported curve")),
                }
            }
            KeyType::Assigned(iana::KeyType::EC2) => {
                let Some((_, Value::Integer(crv))) = self
                    .params
                    .iter()
                    .find(|(label, _)| label == &Label::Int(iana::OkpKeyParameter::Crv.to_i64()))
                else {
                    return Err(signature::Error::from_source("Missing 'crv' claim"));
                };
                let crv: i64 = (*crv)
                    .try_into()
                    .map_err(|_| signature::Error::from_source("Invalid crv"))?;
                match iana::EllipticCurve::from_i64(crv) {
                    Some(iana::EllipticCurve::P_256) => {
                        if cfg!(feature = "p256") {
                            let sk = p256::ecdsa::SigningKey::try_from(self).map_err(|_| {
                                signature::Error::from_source("Invalid P256 CoseKey")
                            })?;
                            Ok(Signer::<p256::ecdsa::Signature>::try_sign(&sk, msg)?.to_vec())
                        } else {
                            Err(signature::Error::from_source(
                                "You must turn on the 'p256' feature to use this",
                            ))
                        }
                    }
                    Some(iana::EllipticCurve::P_384) => {
                        if cfg!(feature = "p384") {
                            let sk = p384::ecdsa::SigningKey::try_from(self).map_err(|_| {
                                signature::Error::from_source("Invalid P384 CoseKey")
                            })?;
                            Ok(Signer::<p384::ecdsa::Signature>::try_sign(&sk, msg)?.to_vec())
                        } else {
                            Err(signature::Error::from_source(
                                "You must turn on the 'p384' feature to use this",
                            ))
                        }
                    }
                    _ => Err(signature::Error::from_source("Unsupported curve")),
                }
            }
            _ => Err(signature::Error::from_source("Unsupported key type")),
        }
    }
}

impl Verifier<Vec<u8>> for CoseKey {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
        match &self.kty {
            KeyType::Assigned(iana::KeyType::OKP) => {
                let Some((_, Value::Integer(crv))) = self
                    .params
                    .iter()
                    .find(|(label, _)| label == &Label::Int(iana::OkpKeyParameter::Crv.to_i64()))
                else {
                    return Err(signature::Error::from_source("Missing 'crv' claim"));
                };
                let crv: i64 = (*crv)
                    .try_into()
                    .map_err(|_| signature::Error::from_source("Invalid crv"))?;
                match iana::EllipticCurve::from_i64(crv) {
                    Some(iana::EllipticCurve::Ed25519) => {
                        if cfg!(feature = "ed25519") {
                            let vk = ed25519_dalek::VerifyingKey::try_from(self).map_err(|_| {
                                signature::Error::from_source("Invalid Ed25519 CoseKey")
                            })?;
                            let signature =
                                ed25519_dalek::Signature::from_slice(signature.as_slice())?;
                            vk.verify(msg, &signature)
                        } else {
                            Err(signature::Error::from_source(
                                "You must turn on the 'ed25519' feature to use this",
                            ))
                        }
                    }
                    _ => Err(signature::Error::from_source("Unsupported curve")),
                }
            }
            KeyType::Assigned(iana::KeyType::EC2) => {
                let Some((_, Value::Integer(crv))) = self
                    .params
                    .iter()
                    .find(|(label, _)| label == &Label::Int(iana::OkpKeyParameter::Crv.to_i64()))
                else {
                    return Err(signature::Error::from_source("Missing 'crv' claim"));
                };
                let crv: i64 = (*crv)
                    .try_into()
                    .map_err(|_| signature::Error::from_source("Invalid crv"))?;
                match iana::EllipticCurve::from_i64(crv) {
                    Some(iana::EllipticCurve::P_256) => {
                        if cfg!(feature = "p256") {
                            let vk = p256::ecdsa::VerifyingKey::try_from(self).map_err(|_| {
                                signature::Error::from_source("Invalid P256 CoseKey")
                            })?;
                            let signature =
                                p256::ecdsa::Signature::from_slice(signature.as_slice())?;
                            vk.verify(msg, &signature)
                        } else {
                            Err(signature::Error::from_source(
                                "You must turn on the 'p256' feature to use this",
                            ))
                        }
                    }
                    Some(iana::EllipticCurve::P_384) => {
                        if cfg!(feature = "p384") {
                            let vk = p384::ecdsa::VerifyingKey::try_from(self).map_err(|_| {
                                signature::Error::from_source("Invalid P384 CoseKey")
                            })?;
                            let signature =
                                p384::ecdsa::Signature::from_slice(signature.as_slice())?;
                            vk.verify(msg, &signature)
                        } else {
                            Err(signature::Error::from_source(
                                "You must turn on the 'p384' feature to use this",
                            ))
                        }
                    }
                    _ => Err(signature::Error::from_source("Unsupported curve")),
                }
            }
            _ => Err(signature::Error::from_source("Unsupported key type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_sign_ed25519() {
        let msg = b"Hello world !";
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let signature = sk.sign(msg).to_vec();
        let cose_key = CoseKey::from(&sk);
        let cose_key_signature = cose_key.sign(msg).to_vec();
        assert_eq!(signature, cose_key_signature);
    }

    #[test]
    fn should_verify_ed25519() {
        let msg = b"Hello world !";
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let signature = sk.sign(msg).to_vec();
        let cose_key = CoseKey::from(&sk);
        cose_key.verify(msg, &signature).unwrap();
    }

    #[test]
    fn should_sign_p256() {
        let msg = b"Hello world !";
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let signature = Signer::<p256::ecdsa::Signature>::sign(&sk, msg).to_vec();
        let cose_key = CoseKey::try_from(&sk).unwrap();
        let cose_key_signature = cose_key.sign(msg).to_vec();
        assert_eq!(signature, cose_key_signature);
    }

    #[test]
    fn should_verify_p256() {
        let msg = b"Hello world !";
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let signature = Signer::<p256::ecdsa::Signature>::sign(&sk, msg).to_vec();
        let cose_key = CoseKey::try_from(&sk).unwrap();
        cose_key.verify(msg, &signature).unwrap();
    }

    #[test]
    fn should_sign_p384() {
        let msg = b"Hello world !";
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let signature = Signer::<p384::ecdsa::Signature>::sign(&sk, msg).to_vec();
        let cose_key = CoseKey::try_from(&sk).unwrap();
        let cose_key_signature = cose_key.sign(msg).to_vec();
        assert_eq!(signature, cose_key_signature);
    }

    #[test]
    fn should_verify_p384() {
        let msg = b"Hello world !";
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let signature = Signer::<p384::ecdsa::Signature>::sign(&sk, msg).to_vec();
        let cose_key = CoseKey::try_from(&sk).unwrap();
        cose_key.verify(msg, &signature).unwrap();
    }
}
