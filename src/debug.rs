use crate::CoseKey;
use ciborium::Value;
use coset::{
    KeyType, Label,
    iana::{self, EnumI64 as _},
};

impl std::fmt::Debug for CoseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("CoseKey");
        f.field("kty", &self.0.kty);
        if !self.0.key_id.is_empty() {
            f.field("key_id", &hex::encode(&self.0.key_id));
        }
        f.field("alg", &self.0.alg);
        if !self.0.base_iv.is_empty() {
            f.field("base_iv", &"***");
        }
        if !self.0.params.is_empty() {
            f.field(
                "params",
                &self
                    .0
                    .params
                    .iter()
                    .map(|(label, value)| match (&self.0.kty, label, value) {
                        // === private keys ===
                        (KeyType::Assigned(iana::KeyType::OKP), Label::Int(i), _)
                            if *i == iana::OkpKeyParameter::D.to_i64() =>
                        {
                            (label, "***".into())
                        }
                        (KeyType::Assigned(iana::KeyType::EC2), Label::Int(i), _)
                            if *i == iana::Ec2KeyParameter::D.to_i64() =>
                        {
                            (label, "***".into())
                        }
                        (KeyType::Assigned(iana::KeyType::RSA), Label::Int(i), _)
                            if *i == iana::RsaKeyParameter::D.to_i64() =>
                        {
                            (label, "***".into())
                        }
                        (KeyType::Assigned(iana::KeyType::AKP), Label::Int(i), _)
                            if *i == iana::AkpKeyParameter::Priv.to_i64() =>
                        {
                            (label, "***".into())
                        }
                        // === public keys ===
                        (KeyType::Assigned(iana::KeyType::OKP), Label::Int(i), Value::Bytes(b))
                            if *i == iana::OkpKeyParameter::X.to_i64() =>
                        {
                            (label, hex::encode(b))
                        }
                        (KeyType::Assigned(iana::KeyType::EC2), Label::Int(i), Value::Bytes(b))
                            if *i == iana::Ec2KeyParameter::X.to_i64() | iana::Ec2KeyParameter::Y.to_i64() =>
                        {
                            (label, hex::encode(b))
                        }
                        // === Curve ===
                        (KeyType::Assigned(iana::KeyType::OKP), Label::Int(i), Value::Integer(crv))
                            if *i == iana::OkpKeyParameter::Crv.to_i64()
                                && let Some(crv) = iana::EllipticCurve::from_i64(i128::from(*crv) as i64) =>
                        {
                            (label, format!("{crv:?}"))
                        }
                        (KeyType::Assigned(iana::KeyType::EC2), Label::Int(i), Value::Integer(crv))
                            if *i == iana::Ec2KeyParameter::Crv.to_i64()
                                && let Some(crv) = iana::EllipticCurve::from_i64(i128::from(*crv) as i64) =>
                        {
                            (label, format!("{crv:?}"))
                        }
                        // === Rest ===
                        _ => (label, format!("{value:?}")),
                    })
                    .collect::<Vec<_>>(),
            );
        }
        f.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use coset::{Algorithm, KeyOperation, KeyType};
    use std::collections::BTreeSet;

    #[test]
    fn should_strip_private_key() {
        let k = CoseKey::from(coset::CoseKey {
            kty: KeyType::Assigned(iana::KeyType::OKP),
            key_id: b"key_id".to_vec(),
            alg: Some(Algorithm::Assigned(iana::Algorithm::EdDSA)),
            key_ops: BTreeSet::from_iter([KeyOperation::Assigned(iana::KeyOperation::Sign)]),
            base_iv: b"base_iv".to_vec(),
            params: vec![
                (
                    Label::Int(iana::OkpKeyParameter::Crv.to_i64()),
                    Value::Integer(iana::EllipticCurve::Ed25519.to_i64().into()),
                ),
                (
                    Label::Int(iana::OkpKeyParameter::D.to_i64()),
                    Value::Bytes([0u8; ed25519_dalek::SECRET_KEY_LENGTH].to_vec()),
                ),
                (
                    Label::Int(iana::OkpKeyParameter::X.to_i64()),
                    Value::Bytes([0u8; ed25519_dalek::PUBLIC_KEY_LENGTH].to_vec()),
                ),
            ],
        });
        assert_eq!(
            &format!("{k:?}"),
            "CoseKey { kty: Assigned(OKP), key_id: \"6b65795f6964\", alg: Some(Assigned(EdDSA)), base_iv: \"***\", params: [(Int(-1), \"Ed25519\"), (Int(-4), \"***\"), (Int(-2), \"0000000000000000000000000000000000000000000000000000000000000000\")] }"
        );
    }
}
