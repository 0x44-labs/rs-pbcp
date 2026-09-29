#[derive(Debug)]
pub enum TlphError {
    StepTooSmall,
    StepTooBig,
    StepsTooFew,
    StepsTooMany,
    GridTooSmall,
    GridNotSquare,
    SerdeJson(serde_json::Error),
    SerdeQs(serde_qs::Error),
    InvalidQuery(http::uri::InvalidUri),
    InvalidUri(http::Error),
    TvParams(traversev::TraverseVErr),
    UriParse,
    InvalidHost,
    GridWrongSize,
    WrongSession,
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
            Self::SerdeJson(e) => return core::fmt::Display::fmt(e, f),
            Self::SerdeQs(e) => return core::fmt::Display::fmt(e, f),
            Self::InvalidQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::InvalidUri(e) => return core::fmt::Display::fmt(e, f),
            Self::TvParams(e) => return core::fmt::Display::fmt(e, f),
            Self::UriParse => "not a valid tlph uri",
            Self::InvalidHost => "uri host invalid for tlph",
            Self::GridWrongSize => "byte length not a multiple of type size",
            Self::WrongSession => "proof does not match current session",
            Self::OutOfRange => "proof outside valid step range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TlphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SerdeJson(e) => Some(e),
            Self::SerdeQs(e) => Some(e),
            Self::InvalidQuery(e) => Some(e),
            Self::InvalidUri(e) => Some(e),
            Self::TvParams(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for TlphError {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeJson(value)
    }
}

impl From<serde_qs::Error> for TlphError {
    fn from(value: serde_qs::Error) -> Self {
        Self::SerdeQs(value)
    }
}

impl From<http::uri::InvalidUri> for TlphError {
    fn from(value: http::uri::InvalidUri) -> Self {
        Self::InvalidQuery(value)
    }
}

impl From<http::Error> for TlphError {
    fn from(value: http::Error) -> Self {
        Self::InvalidUri(value)
    }
}

impl From<traversev::TraverseVErr> for TlphError {
    fn from(value: traversev::TraverseVErr) -> Self {
        Self::TvParams(value)
    }
}
