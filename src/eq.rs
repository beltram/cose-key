use crate::CoseKey;
use ciborium::Value;
use subtle::{Choice, ConstantTimeEq as _};

impl subtle::ConstantTimeEq for CoseKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        let kty_eq = self.0.kty == other.kty;
        let key_id_eq = &self.0.key_id.ct_eq(&other.0.key_id);
        let alg_eq = self.0.alg == other.0.alg;
        let key_ops_eq = self.0.key_ops == other.0.key_ops;
        let base_iv_eq = &self.0.base_iv.ct_eq(&other.0.base_iv);

        let params_len_eq = self.0.params.len() == other.0.params.len();

        let mut params_choice = Choice::from(true as u8);
        for (self_label, self_value) in &self.0.params {
            let found = other
                .params
                .iter()
                .find(|(label, value)| label == self_label && value_ct_eq(value, self_value).into());
            params_choice &= (found.is_some() as u8).into();
        }
        Choice::from((kty_eq & alg_eq & key_ops_eq & params_len_eq) as u8) & *key_id_eq & *base_iv_eq & params_choice
    }
}

fn value_ct_eq(value: &Value, other: &Value) -> Choice {
    match (value, other) {
        (Value::Integer(a), Value::Integer(b)) => i128::from(*a).ct_eq(&i128::from(*b)),
        (Value::Bytes(a), Value::Bytes(b)) => a.ct_eq(b),
        (Value::Float(_), Value::Float(_)) => (false as u8).into(), // we should not have to compare floats, never
        (Value::Text(a), Value::Text(b)) => a.as_bytes().ct_eq(b.as_bytes()),
        (Value::Bool(a), Value::Bool(b)) => ((a == b) as u8).into(),
        (Value::Null, Value::Null) => (true as u8).into(),
        (Value::Tag(ta, a), Value::Tag(tb, b)) if ta == tb => value_ct_eq(a, b),
        (Value::Array(a), Value::Array(b)) => {
            let len_eq = a.len().ct_eq(&b.len());
            let mut choice = Choice::from(true as u8);
            for va in a {
                let found = b.iter().find(|vb| value_ct_eq(va, vb).into());
                choice &= (found.is_some() as u8).into();
            }
            len_eq & choice
        }
        (Value::Map(a), Value::Map(b)) => {
            let len_eq = a.len().ct_eq(&b.len());
            let mut choice = Choice::from(true as u8);
            for (ka, va) in a {
                let found = b
                    .iter()
                    .find(|(kb, vb)| (value_ct_eq(ka, kb) & value_ct_eq(va, vb)).into());
                choice &= (found.is_some() as u8).into();
            }
            dbg!(len_eq);
            dbg!(choice);
            len_eq & choice
        }
        (Value::Simple(a), Value::Simple(b)) => a.ct_eq(b),
        (_, _) => (false as u8).into(),
    }
}

impl PartialEq for CoseKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.ct_eq(other).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{Algorithm, KeyOperation, KeyType, Label};
    use ed25519_dalek::SigningKey as Ed25519Signer;
    use p256::ecdsa::SigningKey as P256Signer;
    use p384::ecdsa::SigningKey as P384Signer;
    use std::collections::BTreeSet;

    #[test]
    fn fields_should_be_eq() {
        assert_eq!(
            CoseKey::from(coset::CoseKey { ..Default::default() }),
            CoseKey::from(coset::CoseKey { ..Default::default() }),
        );
        // kty
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                kty: KeyType::Text("a".into()),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                kty: KeyType::Text("a".into()),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                kty: KeyType::Text("a".into()),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                kty: KeyType::Text("b".into()),
                ..Default::default()
            }),
        );
        // key_id
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                key_id: b"a".to_vec(),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_id: b"a".to_vec(),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                key_id: b"a".to_vec(),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_id: b"b".to_vec(),
                ..Default::default()
            }),
        );
        // alg
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                alg: Some(Algorithm::Text("a".into())),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                alg: Some(Algorithm::Text("a".into())),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                alg: Some(Algorithm::Text("a".into())),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                alg: Some(Algorithm::Text("b".into())),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                alg: Some(Algorithm::Text("a".into())),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                alg: None,
                ..Default::default()
            }),
        );
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                alg: None,
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                alg: None,
                ..Default::default()
            }),
        );
        // key_ops
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into())]),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into())]),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into())]),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("b".into())]),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into())]),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([]),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into()), KeyOperation::Text("b".into())]),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into())]),
                ..Default::default()
            }),
        );
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("a".into()), KeyOperation::Text("b".into())]),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                key_ops: BTreeSet::from_iter([KeyOperation::Text("b".into()), KeyOperation::Text("a".into())]),
                ..Default::default()
            }),
        );
        // base_iv
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                base_iv: b"a".to_vec(),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                base_iv: b"a".to_vec(),
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                base_iv: b"a".to_vec(),
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                base_iv: b"b".to_vec(),
                ..Default::default()
            }),
        );
        // params
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                params: vec![
                    (Label::Text("a".into()), "a".into()),
                    (Label::Text("b".into()), "b".into())
                ],
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                params: vec![
                    (Label::Text("a".into()), "a".into()),
                    (Label::Text("b".into()), "b".into())
                ],
                ..Default::default()
            }),
        );
        assert_eq!(
            CoseKey::from(coset::CoseKey {
                params: vec![
                    (Label::Text("a".into()), "a".into()),
                    (Label::Text("b".into()), "b".into())
                ],
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                params: vec![
                    (Label::Text("b".into()), "b".into()),
                    (Label::Text("a".into()), "a".into())
                ],
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                params: vec![(Label::Text("a".into()), "a".into())],
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                params: vec![(Label::Text("b".into()), "a".into())],
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                params: vec![(Label::Text("a".into()), "a".into())],
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                params: vec![(Label::Text("a".into()), "b".into())],
                ..Default::default()
            }),
        );
        assert_ne!(
            CoseKey::from(coset::CoseKey {
                params: vec![(Label::Text("a".into()), "a".into())],
                ..Default::default()
            }),
            CoseKey::from(coset::CoseKey {
                params: vec![],
                ..Default::default()
            }),
        );
    }

    #[test]
    fn value_eq() {
        // int
        assert!(bool::from(value_ct_eq(&Value::from(42), &Value::from(42))));
        assert!(!bool::from(value_ct_eq(&Value::from(42), &Value::from(43))));
        // bstr
        assert!(bool::from(value_ct_eq(
            &Value::Bytes(b"a".to_vec()),
            &Value::Bytes(b"a".to_vec())
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Bytes(b"a".to_vec()),
            &Value::Bytes(b"b".to_vec())
        )));
        // tstr
        assert!(bool::from(value_ct_eq(&Value::from("a"), &Value::from("a"))));
        assert!(!bool::from(value_ct_eq(&Value::from("a"), &Value::from("b"))));
        // bool
        assert!(bool::from(value_ct_eq(&Value::from(true), &Value::from(true))));
        assert!(!bool::from(value_ct_eq(&Value::from(true), &Value::from(false))));
        // null
        assert!(bool::from(value_ct_eq(&Value::Null, &Value::Null)));
        // tag
        assert!(bool::from(value_ct_eq(
            &Value::Tag(42, Box::new("a".into())),
            &Value::Tag(42, Box::new("a".into()))
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Tag(42, Box::new("a".into())),
            &Value::Tag(43, Box::new("a".into()))
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Tag(42, Box::new("a".into())),
            &Value::Tag(42, Box::new("b".into()))
        )));
        // array
        assert!(bool::from(value_ct_eq(
            &Value::Array(vec!["a".into()]),
            &Value::Array(vec!["a".into()])
        )));
        assert!(bool::from(value_ct_eq(
            &Value::Array(vec!["a".into(), "b".into()]),
            &Value::Array(vec!["a".into(), "b".into()])
        )));
        assert!(bool::from(value_ct_eq(
            &Value::Array(vec!["a".into(), "b".into()]),
            &Value::Array(vec!["b".into(), "a".into()])
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Array(vec!["a".into()]),
            &Value::Array(vec!["b".into()])
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Array(vec!["a".into()]),
            &Value::Array(vec![])
        )));
        // map
        assert!(bool::from(value_ct_eq(
            &Value::Map(vec![("a".into(), "a".into())]),
            &Value::Map(vec![("a".into(), "a".into())])
        )));
        assert!(bool::from(value_ct_eq(
            &Value::Map(vec![("a".into(), "a".into()), ("b".into(), "b".into())]),
            &Value::Map(vec![("a".into(), "a".into()), ("b".into(), "b".into())])
        )));
        assert!(bool::from(value_ct_eq(
            &Value::Map(vec![("a".into(), "a".into()), ("b".into(), "b".into())]),
            &Value::Map(vec![("b".into(), "b".into()), ("a".into(), "a".into())])
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Map(vec![("a".into(), "a".into()), ("b".into(), "b".into())]),
            &Value::Map(vec![("a".into(), "a".into())])
        )));
        assert!(!bool::from(value_ct_eq(
            &Value::Map(vec![("a".into(), "a".into())]),
            &Value::Map(vec![("b".into(), "b".into())])
        )));
        // simple
        assert!(bool::from(value_ct_eq(&Value::Simple(42), &Value::Simple(42))));
        assert!(!bool::from(value_ct_eq(&Value::Simple(42), &Value::Simple(43))));
    }

    #[test]
    fn should_be_equal() {
        let ed25519_key_a: CoseKey = Ed25519Signer::generate(&mut rand::thread_rng()).try_into().unwrap();
        let ed25519_key_b: CoseKey = Ed25519Signer::generate(&mut rand::thread_rng()).try_into().unwrap();
        let p256_key_a: CoseKey = P256Signer::random(&mut rand::thread_rng()).try_into().unwrap();
        let p256_key_b: CoseKey = P256Signer::random(&mut rand::thread_rng()).try_into().unwrap();
        let p384_key_a: CoseKey = P384Signer::random(&mut rand::thread_rng()).try_into().unwrap();
        let p384_key_b: CoseKey = P384Signer::random(&mut rand::thread_rng()).try_into().unwrap();

        assert_eq!(ed25519_key_a, ed25519_key_a);
        assert_ne!(ed25519_key_a, ed25519_key_b);

        assert_eq!(p256_key_a, p256_key_a);
        assert_ne!(p256_key_a, p256_key_b);

        assert_eq!(p384_key_a, p384_key_a);
        assert_ne!(p384_key_a, p384_key_b);

        assert_ne!(ed25519_key_a, p256_key_a);
        assert_ne!(ed25519_key_a, p384_key_a);
        assert_ne!(p256_key_a, p384_key_a);
    }
}
