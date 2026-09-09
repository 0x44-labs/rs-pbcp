#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlphError {
    GridTooSmall,
    GridNotSquare,
    GridWrongSize,
    ProofTooSmall,
}

impl std::fmt::Display for TlphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::GridTooSmall => "grid size has a minimum of 2 by 2",
            Self::GridNotSquare => "grid must have equal rows and columns",
            Self::GridWrongSize => "byte length not a multiple of type size",
            Self::ProofTooSmall => "proof is too small >= 36 expected",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TlphError {}
