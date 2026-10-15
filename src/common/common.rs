use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Uri;
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

pub(crate) fn with_decoded<T>(
    s: &str,
    f: impl FnOnce(&[u8]) -> T,
) -> Result<T, PbcpError> {
    let mut bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| PbcpError::ProofFormat)?;
    let out = f(&bytes);

    #[cfg(feature = "zeroize")]
    bytes.zeroize();

    Ok(out)
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
