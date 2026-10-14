/// Errors returned by CTPP.
#[derive(Debug)]
pub enum CtppError {
    /// URI host invalid for CTPP.
    InvalidHost,

    /// Message could not be JSON serialised/deserialised.
    Json(serde_json::Error),

    /// Proof outside valid step range.
    OutOfRange,

    /// Invalid parameters for TraverseV.
    Params(traversev::TraverseVErr),

    /// Unable to construct path and query.
    PathAndQuery(http::uri::InvalidUri),

    /// Proof string format invalid for CTPP.
    ProofFormat,

    /// Could not serialise/deserialise querystring.
    QueryString(serde_qs::Error),

    /// Failed to build URI.
    UriBuilder(http::Error),

    /// Parsed URI invalid for CTPP.
    UriParse,

    /// Proof submitted to wrong challenge.
    WrongChallenge,
}

impl std::fmt::Display for CtppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::InvalidHost => "uri host invalid for ctpp",
            Self::Json(e) => return core::fmt::Display::fmt(e, f),
            Self::OutOfRange => "proof outside valid step range",
            Self::Params(e) => return core::fmt::Display::fmt(e, f),
            Self::PathAndQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::ProofFormat => "proof string format invalid for ctpp",
            Self::QueryString(e) => return core::fmt::Display::fmt(e, f),
            Self::UriBuilder(e) => return core::fmt::Display::fmt(e, f),
            Self::UriParse => "parsed uri invalid for ctpp",
            Self::WrongChallenge => "proof submitted to wrong challenge",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CtppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Params(e) => Some(e),
            Self::PathAndQuery(e) => Some(e),
            Self::QueryString(e) => Some(e),
            Self::UriBuilder(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for CtppError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<traversev::TraverseVErr> for CtppError {
    fn from(value: traversev::TraverseVErr) -> Self {
        Self::Params(value)
    }
}

impl From<http::uri::InvalidUri> for CtppError {
    fn from(value: http::uri::InvalidUri) -> Self {
        Self::PathAndQuery(value)
    }
}

impl From<serde_qs::Error> for CtppError {
    fn from(value: serde_qs::Error) -> Self {
        Self::QueryString(value)
    }
}

impl From<http::Error> for CtppError {
    fn from(value: http::Error) -> Self {
        Self::UriBuilder(value)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, str::FromStr};

    use super::*;

    /// Expected [Display](core::fmt::Display) output.
    fn expected_display(err: &CtppError) -> &'static str {
        match err {
            CtppError::InvalidHost => "uri host invalid for ctpp",
            CtppError::Json(e) => e.to_string().leak(),
            CtppError::OutOfRange => "proof outside valid step range",
            CtppError::Params(e) => e.to_string().leak(),
            CtppError::PathAndQuery(e) => e.to_string().leak(),
            CtppError::ProofFormat => "proof string format invalid for ctpp",
            CtppError::QueryString(e) => e.to_string().leak(),
            CtppError::UriBuilder(e) => e.to_string().leak(),
            CtppError::UriParse => "parsed uri invalid for ctpp",
            CtppError::WrongChallenge => "proof submitted to wrong challenge",
        }
    }

    fn json() -> CtppError {
        serde_json::from_str::<serde_json::Value>("{")
            .unwrap_err()
            .into()
    }

    fn path_and_query() -> CtppError {
        http::Uri::from_str("").unwrap_err().into()
    }

    fn query_string() -> CtppError {
        #[derive(Debug, serde::Deserialize)]
        struct Query {
            #[allow(dead_code)]
            timestamp: u32,
        }
        serde_qs::from_str::<Query>("n=abc").unwrap_err().into()
    }

    fn tv_params() -> CtppError {
        traversev::Params::new(0, 1, 1, 1).unwrap_err().into()
    }

    fn uri_builder() -> CtppError {
        http::uri::Builder::new()
            .scheme("not a scheme")
            .build()
            .unwrap_err()
            .into()
    }

    fn all_variants() -> Vec<(CtppError, &'static str)> {
        vec![
            (CtppError::InvalidHost, "InvalidHost"),
            (json(), "Json"),
            (CtppError::OutOfRange, "OutOfRange"),
            (path_and_query(), "PathAndQuery"),
            (CtppError::ProofFormat, "ProofFormat"),
            (query_string(), "QueryString"),
            (tv_params(), "TvParams"),
            (uri_builder(), "UriBuilder"),
            (CtppError::UriParse, "UriParse"),
            (CtppError::WrongChallenge, "WrongChallenge"),
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
        assert_bounds::<CtppError>();

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
            Err(CtppError::InvalidHost)?
        }
        let boxed = fallible().unwrap_err();
        assert_eq!(boxed.to_string(), "uri host invalid for ctpp");
    }
}
