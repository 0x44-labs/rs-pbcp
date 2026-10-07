/// Errors returned by TLPH.
#[derive(Debug)]
pub enum TlphError {
    /// URI host invalid for TLPH.
    InvalidHost,

    /// Solution could not be JSON serialised/deserialised.
    Json(serde_json::Error),

    /// Proof outside valid step range.
    OutOfRange,

    /// Unable to construct path and query.
    PathAndQuery(http::uri::InvalidUri),

    /// Proof string format invalid for TLPH.
    ProofFormat,

    /// Could not serialise/deserialise querystring.
    QueryString(serde_qs::Error),

    /// Time step count is too low.
    StepsTooFew,

    /// Time step count is too high.
    StepsTooMany,

    /// Time step width is too big.
    StepTooBig,

    /// Time step width is too small.
    StepTooSmall,

    /// Invalid parameters for TraverseV.
    TvParams(traversev::TraverseVErr),

    /// Failed to build URI.
    UriBuilder(http::Error),

    /// Parsed URI invalid for TLPH.
    UriParse,

    /// Proof does not match current session.
    WrongSession,
}

impl std::fmt::Display for TlphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::InvalidHost => "uri host invalid for tlph",
            Self::Json(e) => return core::fmt::Display::fmt(e, f),
            Self::OutOfRange => "proof outside valid step range",
            Self::PathAndQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::ProofFormat => "proof string format invalid for tlph",
            Self::QueryString(e) => return core::fmt::Display::fmt(e, f),
            Self::StepsTooFew => "time step count is too low",
            Self::StepsTooMany => "time step count is too high",
            Self::StepTooBig => "time step width is too big",
            Self::StepTooSmall => "time step width is too small",
            Self::TvParams(e) => return core::fmt::Display::fmt(e, f),
            Self::UriBuilder(e) => return core::fmt::Display::fmt(e, f),
            Self::UriParse => "parsed uri invalid for tlph",
            Self::WrongSession => "proof does not match current session",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TlphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::PathAndQuery(e) => Some(e),
            Self::QueryString(e) => Some(e),
            Self::TvParams(e) => Some(e),
            Self::UriBuilder(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for TlphError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<http::uri::InvalidUri> for TlphError {
    fn from(value: http::uri::InvalidUri) -> Self {
        Self::PathAndQuery(value)
    }
}

impl From<serde_qs::Error> for TlphError {
    fn from(value: serde_qs::Error) -> Self {
        Self::QueryString(value)
    }
}

impl From<traversev::TraverseVErr> for TlphError {
    fn from(value: traversev::TraverseVErr) -> Self {
        Self::TvParams(value)
    }
}

impl From<http::Error> for TlphError {
    fn from(value: http::Error) -> Self {
        Self::UriBuilder(value)
    }
}
