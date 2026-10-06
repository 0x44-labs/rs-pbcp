#[derive(Debug)]
pub enum TlphError {
    StepTooSmall,
    StepTooBig,
    StepsTooFew,
    StepsTooMany,
    Json(serde_json::Error),
    QueryString(serde_qs::Error),
    UriBuilder(http::Error),
    PathAndQuery(http::uri::InvalidUri),
    TvParams(traversev::TraverseVErr),
    UriParse,
    InvalidHost,
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
            Self::Json(e) => return core::fmt::Display::fmt(e, f),
            Self::QueryString(e) => return core::fmt::Display::fmt(e, f),
            Self::UriBuilder(e) => return core::fmt::Display::fmt(e, f),
            Self::PathAndQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::TvParams(e) => return core::fmt::Display::fmt(e, f),
            Self::UriParse => "not a valid tlph uri",
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
            //Self::TvParams(e) => Some(e),
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
