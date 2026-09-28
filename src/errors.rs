#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlphError {
    StepTooSmall,
    StepTooBig,
    StepsTooFew,
    StepsTooMany,
    GridTooSmall,
    GridNotSquare,
    GridWrongSize,
    ProofTooSmall,
    OutOfRange,
}

impl std::fmt::Display for TlphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::StepTooSmall => "time step width is too small",
            Self::StepTooBig => "time step width is too big",
            Self::StepsTooFew => "time step count is too low",
            Self::StepsTooMany => "time step count is too high",
            Self::GridTooSmall => "grid size has a minimum of 2 by 2",
            Self::GridNotSquare => "grid must have equal rows and columns",
            Self::GridWrongSize => "byte length not a multiple of type size",
            Self::ProofTooSmall => "proof is too small",
            Self::OutOfRange => "proof outside valid step range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TlphError {}
