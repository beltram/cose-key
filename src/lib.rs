mod codec;
#[cfg(feature = "p256")]
mod ecdsa_p256;
#[cfg(feature = "p384")]
mod ecdsa_p384;
#[cfg(feature = "ed25519")]
mod eddsa_ed25519;
mod error;
#[cfg(feature = "pem")]
mod pem;

use ciborium::Value;
use coset::{Algorithm, KeyOperation, KeyType, Label, iana, iana::EnumI64};
pub use error::CoseKeyError;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseKey(coset::CoseKey);

impl std::hash::Hash for CoseKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match &self.kty {
            KeyType::Assigned(i) => i.to_i64().hash(state),
            KeyType::Text(s) => s.hash(state),
        };
        self.key_id.hash(state);
        match &self.alg {
            Some(Algorithm::PrivateUse(i)) => i.hash(state),
            Some(Algorithm::Assigned(i)) => i.to_i64().hash(state),
            Some(Algorithm::Text(s)) => s.hash(state),
            None => {}
        }
        for ops in &self.key_ops {
            match ops {
                KeyOperation::Assigned(i) => i.to_i64().hash(state),
                KeyOperation::Text(s) => s.hash(state),
            }
        }
        self.base_iv.hash(state);
        for (label, value) in &self.params {
            match label {
                Label::Int(i) => i.hash(state),
                Label::Text(s) => s.hash(state),
            }
            hash_value(value, state);
        }
    }
}

// SAFETY: so far no float has been IANA registered (could be for private use though). So it's kinda fine to do this.
impl Eq for CoseKey {}

fn hash_value<H: std::hash::Hasher>(value: &Value, state: &mut H) {
    use std::hash::Hash as _;
    match value {
        Value::Integer(i) => {
            let _ = i64::try_from(*i).inspect(|i| i.hash(state));
        }
        Value::Bytes(b) => {
            b.hash(state);
        }
        Value::Float(f) => f.to_be_bytes().hash(state),
        Value::Text(s) => s.hash(state),
        Value::Bool(b) => b.hash(state),
        Value::Tag(tag, v) => {
            tag.hash(state);
            hash_value(v, state);
        }
        Value::Array(array) => {
            for e in array {
                hash_value(e, state);
            }
        }
        Value::Map(map) => {
            for (k, v) in map {
                hash_value(k, state);
                hash_value(v, state);
            }
        }
        _ => {}
    };
}

/// Accessors
impl CoseKey {
    pub fn into_inner(self) -> coset::CoseKey {
        self.0
    }

    pub fn alg(&self) -> Option<iana::Algorithm> {
        self.alg.as_ref().and_then(|a| match a {
            Algorithm::Assigned(i) => iana::Algorithm::from_i64(i.to_i64()),
            _ => None,
        })
    }

    pub fn crv(&self) -> Option<iana::EllipticCurve> {
        self.params
            .iter()
            .find_map(|(k, v)| {
                matches!(k, Label::Int(i) if *i == iana::OkpKeyParameter::Crv.to_i64()).then_some(v)
            })
            .and_then(Value::as_integer)
            .and_then(|i| i64::try_from(i).ok())
            .and_then(iana::EllipticCurve::from_i64)
    }
}

impl std::ops::Deref for CoseKey {
    type Target = coset::CoseKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<coset::CoseKey> for CoseKey {
    fn from(k: coset::CoseKey) -> Self {
        Self(k)
    }
}

impl From<CoseKey> for coset::CoseKey {
    fn from(k: CoseKey) -> Self {
        k.0
    }
}

pub trait CoseKeyExt {
    fn alg() -> iana::Algorithm;
}

pub trait EcdsaCoseKeyExt: CoseKeyExt {
    fn crv() -> iana::EllipticCurve;
}
