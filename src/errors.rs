use crate::verifier::BackendError;

/// Errors returned by PBCP.
#[derive(Debug)]
pub enum PbcpError {
    /// Expected exactly 16 bytes.
    AuthTag,

    /// CBOR deserialisation failed.
    CborDe(ciborium::de::Error<std::io::Error>),

    /// CBOR serialisation failed.
    CborSer(ciborium::ser::Error<std::io::Error>),

    /// Cannot exceed 64 bytes.
    ChallengeNonce,

    /// Challenge expired.
    Expired,

    /// JSON serialisation/deserialisation failed.
    Json(serde_json::Error),

    /// Invalid TraverseV parameters.
    Params(traversev::TraverseVErr),

    /// Cannot construct path and query.
    PathAndQuery(http::uri::InvalidUri),

    /// Expected exactly 16 bytes.
    ProofNonce,

    /// Querystring serialisation/deserialisation failed.
    QueryString(serde_qs::Error),

    /// Proof already submitted for challenge.
    Replayed,

    /// Replay store external backend operation failed.
    StoreFail(BackendError),

    /// Challenge exceeded configured costs.
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
            Self::AuthTag => "expected exactly 16 bytes",
            Self::CborDe(e) => return core::fmt::Display::fmt(e, f),
            Self::CborSer(e) => return core::fmt::Display::fmt(e, f),
            Self::ChallengeNonce => "cannot exceed 64 bytes",
            Self::Expired => "challenge expired",
            Self::Json(e) => return core::fmt::Display::fmt(e, f),
            Self::Params(e) => return core::fmt::Display::fmt(e, f),
            Self::PathAndQuery(e) => return core::fmt::Display::fmt(e, f),
            Self::ProofNonce => "expected exactly 16 bytes",
            Self::QueryString(e) => return core::fmt::Display::fmt(e, f),
            Self::Replayed => "proof already submitted for challenge",
            Self::StoreFail(e) => return core::fmt::Display::fmt(e, f),
            Self::TooCostly => "challenge exceeded configured costs",
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
            PbcpError::AuthTag => "expected exactly 16 bytes",
            PbcpError::CborDe(e) => e.to_string().leak(),
            PbcpError::CborSer(e) => e.to_string().leak(),
            PbcpError::ChallengeNonce => "cannot exceed 64 bytes",
            PbcpError::Expired => "challenge expired",
            PbcpError::Json(e) => e.to_string().leak(),
            PbcpError::Params(e) => e.to_string().leak(),
            PbcpError::PathAndQuery(e) => e.to_string().leak(),
            PbcpError::ProofNonce => "expected exactly 16 bytes",
            PbcpError::QueryString(e) => e.to_string().leak(),
            PbcpError::Replayed => "proof already submitted for challenge",
            PbcpError::StoreFail(e) => e.to_string().leak(),
            PbcpError::TooCostly => "challenge exceeded configured costs",
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
            (PbcpError::AuthTag, "AuthTag"),
            (cbor_de(), "CborDe"),
            (cbor_ser(), "CborSer"),
            (PbcpError::ChallengeNonce, "ChallengeNonce"),
            (PbcpError::Expired, "Expired"),
            (json(), "Json"),
            (params(), "Params"),
            (path_and_query(), "PathAndQuery"),
            (PbcpError::ProofNonce, "ProofNonce"),
            (query_string(), "QueryString"),
            (PbcpError::Replayed, "Replayed"),
            (store_fail(), "StoreFail"),
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
            Err(PbcpError::Replayed)?
        }
        let boxed = fallible().unwrap_err();
        assert_eq!(boxed.to_string(), "proof already submitted for challenge");
    }
}
