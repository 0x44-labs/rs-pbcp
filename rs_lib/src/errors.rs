use wasm_bindgen::{JsError, JsValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlphError {
    Truncated,
    UnsupportedVersion(u8),
    UnexpectedTag { expected: u8, found: u8 },
    InvalidAnswer,
    InvalidNonce,
}

impl std::fmt::Display for TlphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TlphError {}

impl From<TlphError> for JsValue {
    fn from(value: TlphError) -> Self {
        JsError::from(value).into()
    }
}
