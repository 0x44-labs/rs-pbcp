/// Errors returned by TLPH.
#[derive(Debug)]
pub enum TlphError {
    /// Time step width is too small.
    StepTooSmall,

    /// Time step width is too big.
    StepTooBig,

    /// Time step count is too low.
    StepsTooFew,

    /// Time step count is too high.
    StepsTooMany,

    /// Solution could not be JSON serialised/deserialised.
    Json(serde_json::Error),

    /// Could not serialise/deserialise querystring.
    QueryString(serde_qs::Error),

    /// Failed to build URI.
    UriBuilder(http::Error),

    /// Unable to construct path and query.
    PathAndQuery(http::uri::InvalidUri),

    /// Invalid parameters for TraverseV.
    TvParams(traversev::TraverseVErr),

    /// Parsed URI invalid for TLPH.
    UriParse,

    /// URI host invalid for TLPH.
    InvalidHost,

    /// Proof does not match current session.
    WrongSession,

    /// Proof outside valid step range.
    OutOfRange,
}

impl std::fmt::Display for TlphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::StepTooSmall => "time step width is too small",
            Self::StepTooBig => "time step width is too big",
            Self::StepsTooFew => "time step count is too low",
            Self::StepsTooMany => "time step count is too high",
            Self::Json(e) => return core::fmt::Display::fmt(e, f),
            Self::QueryString(e) => return core::fmt::Display::fmt(e, f),
            Self::UriBuilder(e) => return core::fmt::Display::fmt(e, f),
            Self::PathAndQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::TvParams(e) => return core::fmt::Display::fmt(e, f),
            Self::UriParse => "parsed uri invalid for tlph",
            Self::InvalidHost => "uri host invalid for tlph",
            Self::WrongSession => "proof does not match current session",
            Self::OutOfRange => "proof outside valid step range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TlphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::QueryString(e) => Some(e),
            Self::UriBuilder(e) => Some(e),
            Self::PathAndQuery(e) => Some(e),
            Self::TvParams(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for TlphError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<serde_qs::Error> for TlphError {
    fn from(value: serde_qs::Error) -> Self {
        Self::QueryString(value)
    }
}

impl From<http::Error> for TlphError {
    fn from(value: http::Error) -> Self {
        Self::UriBuilder(value)
    }
}

impl From<http::uri::InvalidUri> for TlphError {
    fn from(value: http::uri::InvalidUri) -> Self {
        Self::PathAndQuery(value)
    }
}

impl From<traversev::TraverseVErr> for TlphError {
    fn from(value: traversev::TraverseVErr) -> Self {
        Self::TvParams(value)
    }
}
