use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer;
use std::collections::BTreeMap;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::CtppError;

/// A JWT-style `Claims` set, representing a JSON object whose members are the
/// claims.
///
/// <https://www.rfc-editor.org/info/rfc7519/#section-4>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Claims(BTreeMap<String, Value>);

impl Claims {
    /// Create a new [ClaimsBuilder] for the given time step.
    pub fn builder() -> ClaimsBuilder {
        ClaimsBuilder::new()
    }

    /// Parse [Claims] from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, CtppError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serialise these [Claims] to a JSON string.
    pub fn to_json(&self) -> Result<String, CtppError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse [Claims] from JSON-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CtppError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialise these [Claims] to JSON bytes in canonical form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CtppError> {
        Ok(serde_json_canonicalizer::to_vec(self)?)
    }

    /// Returns the value of the named claim, if it exists.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Claims {
    fn zeroize(&mut self) {
        for (mut k, mut v) in std::mem::take(&mut self.0) {
            k.zeroize();
            wipe_value(&mut v);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Claims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Claims {}

/// A builder for [Claims].
#[derive(Debug, Clone)]
pub struct ClaimsBuilder(BTreeMap<String, Value>);

impl ClaimsBuilder {
    /// Create a new [ClaimsBuilder] with empty claims.
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Add a claim with the given name and value, replacing any existing
    /// claim of the same name.
    pub fn claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Self {
        let mut name = name.into();
        let value = value.into();

        // `BTreeMap::insert` would drop both the replaced value and the
        // duplicate key without wiping them, so replace in place instead.
        match self.0.get_mut(&name) {
            Some(slot) => {
                let mut old = std::mem::replace(slot, value);

                #[cfg(feature = "zeroize")]
                {
                    wipe_value(&mut old);
                    name.zeroize();
                }

                #[cfg(not(feature = "zeroize"))]
                drop(old)
            }
            None => {
                self.0.insert(name, value);
            }
        }
        self
    }

    /// Consume this [ClaimsBuilder] and return the resulting [Claims].
    pub fn build(mut self) -> Claims {
        Claims(std::mem::take(&mut self.0))
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for ClaimsBuilder {
    fn zeroize(&mut self) {
        for (mut k, mut v) in std::mem::take(&mut self.0) {
            k.zeroize();
            wipe_value(&mut v);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for ClaimsBuilder {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for ClaimsBuilder {}

/// Wipes every `String` reachable from a `Value`, including object keys.
///
/// Numbers, bools and null cannot be safely wiped in place.
#[cfg(feature = "zeroize")]
fn wipe_value(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => {
            for item in items.iter_mut() {
                wipe_value(item);
            }
        }
        Value::Object(map) => {
            // Keys inside the map are immutable, so take ownership
            for (mut k, mut v) in std::mem::take(map) {
                k.zeroize();
                wipe_value(&mut v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        Claims::builder()
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", 1786554930)
            .claim("exp", 1786561137)
            .build()
    }

    #[test]
    fn new_builder_empty_claims() {
        let builder = Claims::builder();
        assert!(builder.0.is_empty());
    }

    #[test]
    fn json_round_trip() {
        let original = claims();
        let json = original.to_json().expect("valid Claims serialises");

        let reconstructed = Claims::from_json(&json)
            .expect("valid JSON string parses to Claims");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let original = claims();
        let bytes = original
            .to_bytes()
            .expect("valid Claims serialises to canonical JSON bytes");

        let reconstructed = Claims::from_bytes(&bytes)
            .expect("valid canonical JSON bytes parse to Claims");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn existing_claim_is_some() {
        let claims = claims();
        assert!(claims.claim("iss").is_some());
    }

    #[test]
    fn missing_claim_is_none() {
        let claims = claims();
        assert!(claims.claim("nbf").is_none());
    }

    #[test]
    fn claim_replaces_on_duplicate() {
        let claims = Claims::builder()
            .claim("sub", "Denisovan")
            .claim("sub", "Homo sapiens")
            .build();

        assert_eq!(
            claims.claim("sub"),
            Some(&serde_json::json!("Homo sapiens"))
        );
    }
}
