use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer;
use std::collections::BTreeMap;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::TlphError;

/// A `Message` represents a set of named claims bound to a time step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    step: u64,
    claims: BTreeMap<String, Value>,
}

impl Message {
    /// Create a new [MessageBuilder] for the given time step.
    pub fn builder(step: u64) -> MessageBuilder {
        MessageBuilder::new(step)
    }

    /// Parse a [Message] from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, TlphError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serialise this [Message] to a JSON string.
    pub fn to_json(&self) -> Result<String, TlphError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse a [Message] from JSON-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TlphError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialise this [Message] to JSON bytes in canonical form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlphError> {
        Ok(serde_json_canonicalizer::to_vec(self)?)
    }

    /// Returns the time step.
    pub const fn step(&self) -> u64 {
        self.step
    }

    /// Returns the value of the named claim, if it exists.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Message {
    fn zeroize(&mut self) {
        for (mut k, mut v) in std::mem::take(&mut self.claims) {
            k.zeroize();
            wipe_value(&mut v);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Message {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Message {}

/// A builder for [Message].
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    step: u64,
    claims: BTreeMap<String, Value>,
}

impl MessageBuilder {
    /// Create a new [MessageBuilder] with empty claims.
    fn new(step: u64) -> Self {
        Self {
            step,
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

    /// Consume this [MessageBuilder] and return the resulting [Message].
    pub fn build(mut self) -> Message {
        Message {
            step: self.step,
            claims: std::mem::take(&mut self.claims),
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for MessageBuilder {
    fn zeroize(&mut self) {
        for (mut k, mut v) in std::mem::take(&mut self.claims) {
            k.zeroize();
            wipe_value(&mut v);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for MessageBuilder {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for MessageBuilder {}

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

    fn message() -> Message {
        let step = time_step();
        let message = Message::builder(step)
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", "1786554930")
            .claim("exp", "1786561137")
            .build();

        message
    }

    #[test]
    fn new_builder_empty_claims() {
        let step = time_step();
        let builder = Message::builder(step);
        assert!(builder.claims.is_empty());
    }

    #[test]
    fn json_round_trip() {
        let original = message();
        let json = original.to_json().expect("valid Message serialises");

        let reconstructed = Message::from_json(&json)
            .expect("valid JSON string parses to Message");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let original = message();
        let bytes = original
            .to_bytes()
            .expect("valid Message serialises to canonical JSON bytes");

        let reconstructed = Message::from_bytes(&bytes)
            .expect("valid canonical JSON bytes parse to Message");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn accessor_returns_own_field() {
        let message = message();
        assert_eq!(message.step(), time_step());
    }

    #[test]
    fn existing_claim_is_some() {
        let message = message();
        assert!(message.claim("iss").is_some());
    }

    #[test]
    fn missing_claim_is_none() {
        let message = message();
        assert!(message.claim("nbf").is_none());
    }

    #[test]
    fn claim_replaces_on_duplicate() {
        let step = time_step();
        let message = Message::builder(step)
            .claim("sub", "Denisovan")
            .claim("sub", "Homo sapiens")
            .build();

        assert_eq!(
            message.claim("sub"),
            Some(&serde_json::json!("Homo sapiens"))
        );
    }
}
