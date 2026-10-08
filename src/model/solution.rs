use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer;
use std::collections::BTreeMap;

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

    /// Returns a clone of the payload.
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// Returns the value of the named claim, if it exists.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }
}

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
    /// https://www.rfc-editor.org/info/rfc7519/#section-4
    pub fn claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Self {
        self.claims.insert(name.into(), value.into());
        self
    }

    /// Consume this [SolutionBuilder] and return the resulting [Solution].
    pub fn build(self) -> Solution {
        Solution {
            step: self.step,
            payload: self.payload,
            claims: self.claims,
        }
    }
}
