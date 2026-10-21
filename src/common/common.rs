use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use http::Uri;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::errors::PbcpError;

pub(crate) const URI_SCHEME: &str = "pbcp";

pub(crate) fn non_default<T: PartialEq>(value: T, default: T) -> Option<T> {
    (value != default).then_some(value)
}

pub(crate) fn host_query<'a>(
    uri: &'a Uri,
    host: &str,
) -> Result<&'a str, PbcpError> {
    if uri.scheme_str() != Some(URI_SCHEME) {
        return Err(PbcpError::UriParse);
    }
    if uri.host() != Some(host) {
        return Err(PbcpError::InvalidHost);
    }
    match uri.query() {
        Some(q) => Ok(q),
        None => return Err(PbcpError::UriParse),
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("")
        .as_secs()
}

pub(crate) fn derive_secret(id: &Ulid, nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();

    hasher.update(&id.to_bytes());
    hasher.update(&nonce);

    let mut hash = hasher.finalize();
    let secret: [u8; 32] = hash.into();

    #[cfg(feature = "zeroize")]
    {
        hasher.zeroize();
        hash.zeroize();
    }

    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    type Error = PbcpError;

    fn parse_uri(authority: &str, query: &str) -> Uri {
        format!("pbcp://{authority}/?{query}")
            .parse()
            .expect("valid URI")
    }

    #[test]
    fn non_default_omits_default() {
        assert_eq!(non_default(0u32, 0), None);
        assert_eq!(non_default(1u32, 0), Some(1));
    }

    #[test]
    fn host_query_returns_query() {
        let uri = parse_uri("challenge", "a=b");
        let query = host_query(&uri, "challenge").expect("query");
        assert_eq!(query, "a=b");
    }

    #[test]
    fn host_query_rejects_wrong_scheme() {
        let uri: Uri = "http://challenge/?a=b".parse().expect("valid URI");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::UriParse)));
    }

    #[test]
    fn host_query_rejects_wrong_host() {
        let uri = parse_uri("proof", "a=b");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::InvalidHost)));
    }

    #[test]
    fn host_query_rejects_missing_query() {
        let uri: Uri = "pbcp://challenge/".parse().expect("valid URI");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::UriParse)));
    }
}
