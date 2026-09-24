use std::time::Duration;

use anyhow::{Result, bail, ensure};
use futures_util::StreamExt;
use reqwest::{
    Client, StatusCode, Url,
    header::{self, HeaderMap, HeaderValue},
};

use crate::vault::{MAX_ENVELOPE, Secret, sha256};

pub fn canonical_origin(input: &str) -> Result<String> {
    let url = Url::parse(input)?;
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "The server origin must not contain user information"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none() && matches!(url.path(), "" | "/"),
        "Enter only the server origin, without path, query, or fragment"
    );
    let authority = input
        .strip_prefix("http://")
        .and_then(|s| s.split('/').next())
        .unwrap_or("");
    let literal_loopback = authority == "127.0.0.1"
        || authority.starts_with("127.0.0.1:")
        || authority == "[::1]"
        || authority.starts_with("[::1]:");
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && literal_loopback),
        "HTTPS is required except literal http://127.0.0.1 or http://[::1]"
    );
    ensure!(
        url.host_str().is_some(),
        "The server origin needs a hostname"
    );
    Ok(url.origin().ascii_serialization())
}

pub fn validate_token(token: &str) -> Result<()> {
    ensure!(
        token.len() == 64
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "An access token must contain 64 lowercase hexadecimal characters"
    );
    Ok(())
}

pub fn valid_etag(etag: &str) -> bool {
    etag.len() == 66
        && etag.starts_with('"')
        && etag.ends_with('"')
        && etag.as_bytes()[1..65]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

pub struct Downloaded {
    pub envelope: Vec<u8>,
    pub etag: String,
}

pub enum RemoteRead {
    Missing,
    Unchanged,
    Found(Downloaded),
}

#[derive(Debug)]
pub struct PreconditionFailed;
impl std::fmt::Display for PreconditionFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Server changed during synchronization (HTTP 412)")
    }
}
impl std::error::Error for PreconditionFailed {}

pub struct Remote {
    client: Client,
    endpoint: String,
}

impl Remote {
    pub fn new(origin: &str, token: &Secret) -> Result<Self> {
        let origin = canonical_origin(origin)?;
        validate_token(token.expose())?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.expose()))?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, authorization);
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            endpoint: format!("{origin}/v1/vault"),
        })
    }
    pub async fn get(&self, etag: Option<&str>) -> Result<RemoteRead> {
        let mut request = self.client.get(&self.endpoint);
        if let Some(etag) = etag {
            ensure!(valid_etag(etag), "Invalid local ETag");
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        let response = request.send().await?;
        match response.status() {
            StatusCode::NOT_FOUND => return Ok(RemoteRead::Missing),
            StatusCode::NOT_MODIFIED if etag.is_some() => return Ok(RemoteRead::Unchanged),
            StatusCode::OK => (),
            status => bail!("Vault download failed: HTTP {status}"),
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .filter(|v| valid_etag(v))
            .ok_or_else(|| anyhow::anyhow!("Server returned an invalid ETag"))?
            .to_owned();
        ensure!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                == Some("application/octet-stream"),
            "Server returned an invalid vault content type"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_ENVELOPE as u64),
            "Server vault exceeds 16 MiB"
        );
        let mut body = response.bytes_stream();
        let mut envelope = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            ensure!(
                envelope.len() + chunk.len() <= MAX_ENVELOPE,
                "Server vault exceeds 16 MiB"
            );
            envelope.extend_from_slice(&chunk);
        }
        ensure!(!envelope.is_empty(), "Server returned an empty vault");
        ensure!(
            etag[1..65] == sha256(&envelope),
            "Server vault does not match its ETag"
        );
        Ok(RemoteRead::Found(Downloaded { envelope, etag }))
    }
    pub async fn put(&self, envelope: Vec<u8>, etag: Option<&str>) -> Result<String> {
        ensure!(
            !envelope.is_empty() && envelope.len() <= MAX_ENVELOPE,
            "Invalid upload size"
        );
        let expected = format!("\"{}\"", sha256(&envelope));
        let mut request = self
            .client
            .put(&self.endpoint)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(envelope);
        request = if let Some(etag) = etag {
            ensure!(valid_etag(etag), "Invalid upload precondition");
            request.header(header::IF_MATCH, etag)
        } else {
            request.header(header::IF_NONE_MATCH, "*")
        };
        let response = request.send().await?;
        if response.status() == StatusCode::PRECONDITION_FAILED {
            return Err(PreconditionFailed.into());
        }
        ensure!(
            matches!(response.status(), StatusCode::OK | StatusCode::CREATED),
            "Vault upload failed: HTTP {}",
            response.status()
        );
        let actual = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        ensure!(
            actual == expected,
            "Server upload acknowledgement does not match the submitted vault"
        );
        Ok(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_rejects_insecure_or_credential_bearing_urls() {
        for value in [
            "http://localhost:8080",
            "http://127.0.0.2",
            "ftp://127.0.0.1",
            "https://user:secret@example.com",
            "https://example.com/v1",
            "https://example.com/?token=a",
            "https://example.com/#frag",
        ] {
            assert!(canonical_origin(value).is_err(), "{value}");
        }
        assert_eq!(
            canonical_origin("http://[::1]:8080/").unwrap(),
            "http://[::1]:8080"
        );
        assert_eq!(
            canonical_origin("https://EXAMPLE.com/").unwrap(),
            "https://example.com"
        );
    }
}
