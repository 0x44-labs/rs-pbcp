use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer;
use std::collections::BTreeMap;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::TlphError;

/// A `Solution` represents a byte payload and set of named claims,
/// bound to a time step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Solution {
    step: u64,
    payload: Vec<u8>,
    claims: BTreeMap<String, Value>,
}

impl Solution {
    /// Create a new [SolutionBuilder] for the given time step and payload.
    pub fn builder(step: u64, payload: Vec<u8>) -> SolutionBuilder {
        SolutionBuilder::new(step, payload)
    }

    /// Parse a [Solution] from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, TlphError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serialise this [Solution] to a JSON string.
    pub fn to_json(&self) -> Result<String, TlphError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse a [Solution] from JSON-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TlphError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialise this [Solution] to JSON bytes in canonical form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlphError> {
        Ok(serde_json_canonicalizer::to_vec(self)?)
    }

    /// Returns the time step.
    pub const fn step(&self) -> u64 {
        self.step
    }

    /// Returns a reference to the payload.
    pub const fn payload(&self) -> &Vec<u8> {
        &self.payload
    }

    /// Returns the value of the named claim, if it exists.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Solution {
    fn zeroize(&mut self) {
        self.payload.zeroize();
        for (mut k, mut v) in std::mem::take(&mut self.claims) {
            k.zeroize();
            wipe_value(&mut v);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Solution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Solution {}

/// A builder for [Solution].
#[derive(Debug, Clone)]
pub struct SolutionBuilder {
    step: u64,
    payload: Vec<u8>,
    claims: BTreeMap<String, Value>,
}

impl SolutionBuilder {
    /// Create a new [SolutionBuilder] with empty claims.
    fn new(step: u64, payload: Vec<u8>) -> Self {
        Self {
            step,
            payload,
            claims: BTreeMap::new(),
        }
    }

    /// Add a claim with the given name and value, replacing any existing
    /// claim of the same name.
    ///
    /// Claims are expected as JWT-style claims.
    ///
    /// <https://www.rfc-editor.org/info/rfc7519/#section-4>
    pub fn claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Self {
        let mut name = name.into();
        let value = value.into();

        // `BTreeMap::insert` would drop both the replaced value and the
        // duplicate key without wiping them, so replace in place instead.
        match self.claims.get_mut(&name) {
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
                self.claims.insert(name, value);
            }
        }
        self
    }

    /// Consume this [SolutionBuilder] and return the resulting [Solution].
    pub fn build(mut self) -> Solution {
        Solution {
            step: self.step,
            payload: std::mem::take(&mut self.payload),
            claims: std::mem::take(&mut self.claims),
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SolutionBuilder {
    fn zeroize(&mut self) {
        self.payload.zeroize();
        for (mut k, mut v) in std::mem::take(&mut self.claims) {
            k.zeroize();
            wipe_value(&mut v);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SolutionBuilder {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for SolutionBuilder {}

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
    use crate::Params;

    use super::*;

    const TIME: u64 = 1786558105;

    fn time_step() -> u64 {
        let params = Params::default();
        params.time_step(Some(TIME))
    }

    fn sample_payload() -> Vec<u8> {
        b"This is a payload".to_vec()
    }

    fn sample() -> Solution {
        let step = time_step();
        let payload = sample_payload();
        let solution = Solution::builder(step, payload)
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", "1786554930")
            .claim("exp", "1786561137")
            .build();

        solution
    }

    #[test]
    fn new_builder_empty_claims() {
        let step = time_step();
        let payload = sample_payload();
        let builder = Solution::builder(step, payload);
        assert!(builder.claims.is_empty());
    }

    #[test]
    fn json_round_trip() {
        let original = sample();
        let json = original.to_json().expect("valid Solution serialises");

        let reconstructed = Solution::from_json(&json)
            .expect("valid JSON string parses to Solution");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let original = sample();
        let bytes = original
            .to_bytes()
            .expect("valid Solution serialises to canonical JSON bytes");

        let reconstructed = Solution::from_bytes(&bytes)
            .expect("valid canonical JSON bytes parse to Solution");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn accessors_return_their_own_field() {
        let solution = sample();
        let payload = sample_payload();

        assert_eq!(solution.step(), time_step());
        assert_eq!(solution.payload(), &payload);
    }

    #[test]
    fn existing_claim_is_some() {
        let solution = sample();
        assert!(solution.claim("iss").is_some());
    }

    #[test]
    fn missing_claim_is_none() {
        let solution = sample();
        assert!(solution.claim("nbf").is_none());
    }

    #[test]
    fn claim_replaces_on_duplicate() {
        let step = time_step();
        let payload = sample_payload();
        let solution = Solution::builder(step, payload)
            .claim("sub", "Denisovan")
            .claim("sub", "Homo sapiens")
            .build();

        assert_eq!(
            solution.claim("sub"),
            Some(&serde_json::json!("Homo sapiens"))
        );
    }
}
