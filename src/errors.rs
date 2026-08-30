#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlphError {
    GridTooSmall,
    GridNotSquare,

    IncompatibleByteLen,
    ProofTooSmall,

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
