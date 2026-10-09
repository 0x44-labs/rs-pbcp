/// Errors returned by TLPH.
#[derive(Debug)]
pub enum TlphError {
    /// URI host invalid for TLPH.
    InvalidHost,

    /// Message could not be JSON serialised/deserialised.
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

#[cfg(test)]
mod tests {
    use std::{error::Error, str::FromStr};

    use super::*;

    /// Expected [Display](core::fmt::Display) output.
    fn expected_display(err: &TlphError) -> &'static str {
        match err {
            TlphError::InvalidHost => "uri host invalid for tlph",
            TlphError::Json(e) => e.to_string().leak(),
            TlphError::OutOfRange => "proof outside valid step range",
            TlphError::PathAndQuery(e) => e.to_string().leak(),
            TlphError::ProofFormat => "proof string format invalid for tlph",
            TlphError::QueryString(e) => e.to_string().leak(),
            TlphError::StepsTooFew => "time step count is too low",
            TlphError::StepsTooMany => "time step count is too high",
            TlphError::StepTooBig => "time step width is too big",
            TlphError::StepTooSmall => "time step width is too small",
            TlphError::TvParams(e) => e.to_string().leak(),
            TlphError::UriBuilder(e) => e.to_string().leak(),
            TlphError::UriParse => "parsed uri invalid for tlph",
            TlphError::WrongSession => "proof does not match current session",
        }
    }

    fn json() -> TlphError {
        serde_json::from_str::<serde_json::Value>("{")
            .unwrap_err()
            .into()
    }

    fn path_and_query() -> TlphError {
        http::Uri::from_str("").unwrap_err().into()
    }

    fn query_string() -> TlphError {
        #[derive(Debug, serde::Deserialize)]
        struct Query {
            #[allow(dead_code)]
            timestamp: u32,
        }
        serde_qs::from_str::<Query>("n=abc").unwrap_err().into()
    }

    fn tv_params() -> TlphError {
        traversev::Params::new(0, 1, 1, 1).unwrap_err().into()
    }

    fn uri_builder() -> TlphError {
        http::uri::Builder::new()
            .scheme("not a scheme")
            .build()
            .unwrap_err()
            .into()
    }

    fn all_variants() -> Vec<(TlphError, &'static str)> {
        vec![
            (TlphError::InvalidHost, "InvalidHost"),
            (json(), "Json"),
            (TlphError::OutOfRange, "OutOfRange"),
            (path_and_query(), "PathAndQuery"),
            (TlphError::ProofFormat, "ProofFormat"),
            (query_string(), "QueryString"),
            (TlphError::StepsTooFew, "StepsTooFew"),
            (TlphError::StepsTooMany, "StepsTooMany"),
            (TlphError::StepTooBig, "StepTooBig"),
            (TlphError::StepTooSmall, "StepTooSmall"),
            (tv_params(), "TvParams"),
            (uri_builder(), "UriBuilder"),
            (TlphError::UriParse, "UriParse"),
            (TlphError::WrongSession, "WrongSession"),
        ]
    }

    #[test]
    fn display_matches_for_every_variant() {
        for (err, _) in all_variants() {
            assert_eq!(err.to_string(), expected_display(&err));
        }
    }

    #[test]
    fn debug_output_is_the_variant_name() {
        for (err, name) in all_variants() {
            let debug = format!("{err:?}");

            // Wrapped variants carry the wrapped error's debug output.
            if err.source().is_some() {
                assert!(debug.starts_with(&format!("{name}(")));
            } else {
                assert_eq!(debug, name);
            }
        }
    }

    #[test]
    fn conforms_to_std_error() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<TlphError>();

        for (err, name) in all_variants() {
            let expected = expected_display(&err);
            let wrapped = matches!(
                name,
                "Json"
                    | "PathAndQuery"
                    | "QueryString"
                    | "TvParams"
                    | "UriBuilder"
            );
            let dyn_err: &dyn std::error::Error = &err;

            // Wrapped variants expose the wrapped error as their source.
            match dyn_err.source() {
                Some(source) => {
                    assert!(wrapped);
                    assert_eq!(source.to_string(), expected);
                }
                None => assert!(!wrapped),
            }
            assert_eq!(dyn_err.to_string(), expected);
        }

        // Converts into a boxed error via `?`
        fn fallible() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err(TlphError::InvalidHost)?
        }
        let boxed = fallible().unwrap_err();
        assert_eq!(boxed.to_string(), "uri host invalid for tlph");
    }
}
