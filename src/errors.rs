use crate::verifier::BackendError;

/// Errors returned by PBCP.
#[derive(Debug)]
pub enum PbcpError {
    /// Could not CBOR deserialise data.
    CborDe(ciborium::de::Error<std::io::Error>),

    /// Could not CBOR serialise data.
    CborSer(ciborium::ser::Error<std::io::Error>),

    /// Submitted proof is expired.
    Expired,

    /// URI host invalid for PBCP.
    InvalidHost,

    /// Message could not be JSON serialised/deserialised.
    Json(serde_json::Error),

    /// Proof nonce expects 16 bytes.
    NonceLen,

    /// Invalid parameters for TraverseV.
    Params(traversev::TraverseVErr),

    /// Unable to construct path and query.
    PathAndQuery(http::uri::InvalidUri),

    /// Could not serialise/deserialise querystring.
    QueryString(serde_qs::Error),

    /// Proof already submitted for this challenge.
    Replayed,

    /// Replay store operation failed.
    StoreFail(BackendError),

    /// Authentication tag expects 16 bytes.
    TagLen,

    /// Challenge exceeded the configured costs.
    TooCostly,

    /// Failed to build URI.
    UriBuilder(http::Error),

    /// Parsed URI invalid for PBCP.
    UriParse,

    /// Proof submitted to wrong challenge.
    WrongChallenge,
}

impl std::fmt::Display for PbcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::CborDe(e) => return core::fmt::Display::fmt(e, f),
            Self::CborSer(e) => return core::fmt::Display::fmt(e, f),
            Self::Expired => "submitted proof is expired",
            Self::InvalidHost => "uri host invalid for pbcp",
            Self::Json(e) => return core::fmt::Display::fmt(e, f),
            Self::NonceLen => "proof nonce expects 16 bytes",
            Self::Params(e) => return core::fmt::Display::fmt(e, f),
            Self::PathAndQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::QueryString(e) => return core::fmt::Display::fmt(e, f),
            Self::Replayed => "proof already submitted for this challenge",
            Self::StoreFail(e) => return core::fmt::Display::fmt(e, f),
            Self::TagLen => "auth tag expects 16 bytes",
            Self::TooCostly => "challenge exceeded the configured costs",
            Self::UriBuilder(e) => return core::fmt::Display::fmt(e, f),
            Self::UriParse => "parsed uri invalid for pbcp",
            Self::WrongChallenge => "proof submitted to wrong challenge",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PbcpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CborDe(e) => Some(e),
            Self::CborSer(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Params(e) => Some(e),
            Self::PathAndQuery(e) => Some(e),
            Self::QueryString(e) => Some(e),
            Self::StoreFail(e) => Some(e.as_ref()),
            Self::UriBuilder(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ciborium::de::Error<std::io::Error>> for PbcpError {
    fn from(value: ciborium::de::Error<std::io::Error>) -> Self {
        Self::CborDe(value)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for PbcpError {
    fn from(value: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::CborSer(value)
    }
}

impl From<serde_json::Error> for PbcpError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<traversev::TraverseVErr> for PbcpError {
    fn from(value: traversev::TraverseVErr) -> Self {
        Self::Params(value)
    }
}

impl From<http::uri::InvalidUri> for PbcpError {
    fn from(value: http::uri::InvalidUri) -> Self {
        Self::PathAndQuery(value)
    }
}

impl From<serde_qs::Error> for PbcpError {
    fn from(value: serde_qs::Error) -> Self {
        Self::QueryString(value)
    }
}

impl From<BackendError> for PbcpError {
    fn from(value: BackendError) -> Self {
        Self::StoreFail(value)
    }
}

impl From<http::Error> for PbcpError {
    fn from(value: http::Error) -> Self {
        Self::UriBuilder(value)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, str::FromStr};

    use super::*;

    /// Expected [Display](core::fmt::Display) output.
    fn expected_display(err: &PbcpError) -> &'static str {
        match err {
            PbcpError::CborDe(e) => e.to_string().leak(),
            PbcpError::CborSer(e) => e.to_string().leak(),
            PbcpError::Expired => "submitted proof is expired",
            PbcpError::InvalidHost => "uri host invalid for pbcp",
            PbcpError::Json(e) => e.to_string().leak(),
            PbcpError::NonceLen => "proof nonce expects 16 bytes",
            PbcpError::Params(e) => e.to_string().leak(),
            PbcpError::PathAndQuery(e) => e.to_string().leak(),
            PbcpError::QueryString(e) => e.to_string().leak(),
            PbcpError::Replayed => "proof already submitted for this challenge",
            PbcpError::StoreFail(e) => e.to_string().leak(),
            PbcpError::TagLen => "auth tag expects 16 bytes",
            PbcpError::TooCostly => "challenge exceeded the configured costs",
            PbcpError::UriBuilder(e) => e.to_string().leak(),
            PbcpError::UriParse => "parsed uri invalid for pbcp",
            PbcpError::WrongChallenge => "proof submitted to wrong challenge",
        }
    }

    fn cbor_de() -> PbcpError {
        ciborium::de::Error::<std::io::Error>::Syntax(0).into()
    }

    fn cbor_ser() -> PbcpError {
        ciborium::ser::Error::<std::io::Error>::Value("unserialisable".into())
            .into()
    }

    fn json() -> PbcpError {
        serde_json::from_str::<serde_json::Value>("{")
            .unwrap_err()
            .into()
    }

    fn params() -> PbcpError {
        traversev::Params::new(0, 1, 1, 1).unwrap_err().into()
    }

    fn path_and_query() -> PbcpError {
        http::Uri::from_str("").unwrap_err().into()
    }

    fn query_string() -> PbcpError {
        #[derive(Debug, serde::Deserialize)]
        struct Query {
            #[allow(dead_code)]
            timestamp: u32,
        }
        serde_qs::from_str::<Query>("n=abc").unwrap_err().into()
    }

    fn store_fail() -> PbcpError {
        let source: BackendError = "backend unavailable".into();
        source.into()
    }

    fn uri_builder() -> PbcpError {
        http::uri::Builder::new()
            .scheme("not a scheme")
            .build()
            .unwrap_err()
            .into()
    }

    fn all_variants() -> Vec<(PbcpError, &'static str)> {
        vec![
            (cbor_de(), "CborDe"),
            (cbor_ser(), "CborSer"),
            (PbcpError::Expired, "Expired"),
            (PbcpError::InvalidHost, "InvalidHost"),
            (json(), "Json"),
            (PbcpError::NonceLen, "NonceLen"),
            (params(), "Params"),
            (path_and_query(), "PathAndQuery"),
            (query_string(), "QueryString"),
            (PbcpError::Replayed, "Replayed"),
            (store_fail(), "StoreFail"),
            (PbcpError::TagLen, "TagLen"),
            (PbcpError::TooCostly, "TooCostly"),
            (uri_builder(), "UriBuilder"),
            (PbcpError::UriParse, "UriParse"),
            (PbcpError::WrongChallenge, "WrongChallenge"),
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
        assert_bounds::<PbcpError>();

        for (err, name) in all_variants() {
            let expected = expected_display(&err);
            let wrapped = matches!(
                name,
                "CborDe"
                    | "CborSer"
                    | "Json"
                    | "Params"
                    | "PathAndQuery"
                    | "QueryString"
                    | "StoreFail"
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
            Err(PbcpError::InvalidHost)?
        }
        let boxed = fallible().unwrap_err();
        assert_eq!(boxed.to_string(), "uri host invalid for pbcp");
    }
}
