//! Generic OIDC Device Authorization Grant (RFC 8628).
//!
//! This module implements the standards-based protocol logic for device authorization
//! flows. It is intentionally generic and contains no service-specific code.

use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;
use url::Url;

/// The default client ID sent in device authorization requests when none is configured.
const DEFAULT_CLIENT_ID: &str = "uv";

/// Default `OAuth2` scope if none is configured.
const DEFAULT_SCOPE: &str = "openid";

/// Default polling interval in seconds if the server doesn't specify one.
const DEFAULT_INTERVAL: u64 = 5;

/// OIDC configuration for an index, specifiable via `[[tool.uv.index]]` or CLI flags.
///
/// When an index has OIDC configuration, `uv auth login` will use these parameters
/// for the device authorization flow instead of (or in addition to) `.well-known` discovery.
///
/// ```toml
/// [[tool.uv.index]]
/// name = "my-index"
/// url = "https://example.com/pypi/simple"
///
/// [tool.uv.index.oidc]
/// issuer = "https://auth.example.com"
/// client-id = "my-app"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct OidcConfig {
    /// The OIDC issuer URL. Discovery will be performed at
    /// `<issuer>/.well-known/openid-configuration`.
    ///
    /// If omitted, discovery is attempted at the index URL itself.
    pub issuer: Option<Url>,
    /// The `OAuth2` client ID to use in device authorization requests.
    ///
    /// Defaults to `"uv"` if not specified.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The `OAuth2` scope(s) to request during device authorization.
    ///
    /// Space-separated list of scopes. Defaults to `"openid"` if not specified.
    /// Different providers require different scopes, e.g., Azure DevOps
    /// requires `"499b84ac-1321-427f-aa17-267ca6975798/.default"`.
    #[serde(default)]
    pub scope: Option<String>,
}

/// OIDC Discovery Document (subset of `.well-known/openid-configuration`).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryDocument {
    /// The issuer identifier.
    pub issuer: String,
    /// The device authorization endpoint (RFC 8628).
    pub device_authorization_endpoint: String,
    /// The token endpoint.
    pub token_endpoint: String,
    /// Supported grant types advertised by the provider.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
}

/// RFC 8628 Section 3.2 -- Device Authorization Response.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// A verification code for the device.
    pub device_code: String,
    /// A code the user enters at the verification URI.
    pub user_code: String,
    /// The URI the user visits to authorize the device.
    pub verification_uri: String,
    /// Optional URI that includes the user code (for QR codes, etc.).
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Lifetime in seconds of the device code.
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

/// Token response from the device token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceTokenResponse {
    /// The access token (RFC 6749 Section 5.1). Required on success.
    #[serde(default)]
    pub access_token: Option<String>,
    /// The token type (e.g., "Bearer").
    #[serde(default)]
    pub token_type: Option<String>,
    /// Token lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// RFC 8628 error code (e.g., `authorization_pending`, `slow_down`).
    #[serde(default)]
    pub error: Option<String>,
    /// Human-readable error description.
    #[serde(default)]
    pub error_description: Option<String>,
}

/// PKCE (Proof Key for Code Exchange) challenge pair using S256 method.
pub struct PkceChallenge {
    /// The code verifier (random string sent to the token endpoint).
    pub code_verifier: String,
    /// The S256 code challenge (SHA256 hash of verifier, base64url-encoded).
    pub code_challenge: String,
}

/// Errors that can occur during the OIDC device authorization flow.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("OIDC discovery failed: {0}")]
    DiscoveryFailed(String),
    #[error("Device authorization request failed: {0}")]
    DeviceAuthorizationFailed(String),
    #[error("Device authorization timed out")]
    TokenExpired,
    #[error("Authorization denied by user")]
    AccessDenied,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL
}

/// Generate a PKCE challenge pair using the S256 method.
///
/// Generates a random code verifier (32 bytes, base64url-encoded) and computes
/// the S256 code challenge (SHA256 hash of the verifier, base64url-encoded).
pub fn generate_pkce() -> PkceChallenge {
    let mut random_bytes = [0u8; 32];
    for byte in &mut random_bytes {
        *byte = fastrand::u8(..);
    }
    let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(random_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(hasher.finalize());

    PkceChallenge {
        code_verifier,
        code_challenge,
    }
}

/// Attempt OIDC discovery for the given base URL.
///
/// Fetches `<base_url>/.well-known/openid-configuration`. Returns `Ok(None)` if the
/// server does not support OIDC (404, connection error, invalid JSON), allowing the
/// caller to fall back to other authentication methods.
pub async fn discover(
    client: &reqwest::Client,
    base_url: &Url,
) -> Result<Option<OidcDiscoveryDocument>, OidcError> {
    let mut discovery_url = base_url.clone();

    // Ensure the path ends with a slash before appending
    if !discovery_url.path().ends_with('/') {
        discovery_url.set_path(&format!("{}/", discovery_url.path()));
    }

    let Ok(discovery_url) = discovery_url.join(".well-known/openid-configuration") else {
        return Ok(None);
    };

    debug!("Attempting OIDC discovery at {discovery_url}");

    let response = match client.get(discovery_url).send().await {
        Ok(response) => response,
        Err(err) => {
            debug!("OIDC discovery request failed: {err}");
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        debug!("OIDC discovery returned status {}", response.status());
        return Ok(None);
    }

    let document: OidcDiscoveryDocument = match response.json().await {
        Ok(doc) => doc,
        Err(err) => {
            debug!("Failed to parse OIDC discovery document: {err}");
            return Ok(None);
        }
    };

    debug!(
        "OIDC discovery succeeded: issuer={}, device_authorization_endpoint={}, token_endpoint={}",
        document.issuer, document.device_authorization_endpoint, document.token_endpoint
    );

    Ok(Some(document))
}

/// Resolve an endpoint URL from the discovery document.
///
/// If the endpoint is a relative path, resolves it against the base URL.
/// If it is an absolute URL, uses it as-is.
fn resolve_endpoint(base_url: &Url, endpoint: &str) -> Result<Url, OidcError> {
    // Try parsing as absolute URL first
    if let Ok(url) = Url::parse(endpoint) {
        return Ok(url);
    }
    // Otherwise resolve as relative
    base_url
        .join(endpoint)
        .map_err(|err| OidcError::DeviceAuthorizationFailed(format!("Invalid endpoint URL: {err}")))
}

/// Start the device authorization flow (RFC 8628 Section 3.1-3.2).
///
/// Sends a POST to the `device_authorization_endpoint` with PKCE challenge
/// and returns the device code, user code, and verification URI.
///
/// If `client_id` is `None`, defaults to `"uv"`.
/// If `scope` is `None`, defaults to `"openid"`.
pub async fn device_authorize(
    client: &reqwest::Client,
    base_url: &Url,
    discovery: &OidcDiscoveryDocument,
    pkce: &PkceChallenge,
    client_id: Option<&str>,
    scope: Option<&str>,
) -> Result<DeviceAuthorizationResponse, OidcError> {
    let endpoint = resolve_endpoint(base_url, &discovery.device_authorization_endpoint)?;
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID);
    let scope = scope.unwrap_or(DEFAULT_SCOPE);

    debug!(
        "Requesting device authorization at {endpoint} with client_id={client_id} scope={scope}"
    );

    let response = client
        .post(endpoint)
        .form(&[
            ("client_id", client_id),
            ("scope", scope),
            ("code_challenge", &pkce.code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(OidcError::DeviceAuthorizationFailed(format!(
            "status {status}: {body}"
        )));
    }

    let device_response: DeviceAuthorizationResponse = response.json().await.map_err(|err| {
        OidcError::DeviceAuthorizationFailed(format!("Failed to parse response: {err}"))
    })?;

    debug!(
        "Device authorization successful: user_code={}, verification_uri={}",
        device_response.user_code, device_response.verification_uri
    );

    Ok(device_response)
}

/// Poll the token endpoint until the user completes authorization (RFC 8628 Section 3.3-3.5).
///
/// Polls at the interval specified by the device authorization response, handling
/// `authorization_pending` (continue), `slow_down` (increase interval), and error
/// conditions per the RFC.
///
/// If `client_id` is `None`, defaults to `"uv"`.
pub async fn poll_for_token(
    client: &reqwest::Client,
    base_url: &Url,
    discovery: &OidcDiscoveryDocument,
    device_response: &DeviceAuthorizationResponse,
    pkce: &PkceChallenge,
    client_id: Option<&str>,
) -> Result<DeviceTokenResponse, OidcError> {
    let endpoint = resolve_endpoint(base_url, &discovery.token_endpoint)?;
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID);
    let mut interval = device_response.interval;

    debug!("Polling token endpoint at {endpoint} with interval {interval}s");

    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;

        let response = client
            .post(endpoint.clone())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_response.device_code),
                ("client_id", client_id),
                ("code_verifier", &pkce.code_verifier),
            ])
            .send()
            .await?;

        // Parse regardless of status code -- RFC 8628 uses 400 for pending/slow_down errors
        let token_response: DeviceTokenResponse = response.json().await.map_err(|err| {
            OidcError::DeviceAuthorizationFailed(format!("Failed to parse token response: {err}"))
        })?;

        match token_response.error.as_deref() {
            Some("authorization_pending") => {
                debug!("Authorization pending, continuing to poll...");
            }
            Some("slow_down") => {
                // RFC 8628 Section 3.5: increase interval by 5 seconds
                interval += 5;
                debug!("Received slow_down, increasing interval to {interval}s");
            }
            Some("expired_token") => {
                return Err(OidcError::TokenExpired);
            }
            Some("access_denied") => {
                return Err(OidcError::AccessDenied);
            }
            Some(other) => {
                let description = token_response
                    .error_description
                    .unwrap_or_else(|| other.to_string());
                return Err(OidcError::DeviceAuthorizationFailed(description));
            }
            None => {
                debug!("Token polling succeeded");
                return Ok(token_response);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pkce() {
        let pkce = generate_pkce();

        // Verifier should be base64url-encoded 32 bytes (43 chars without padding)
        assert_eq!(pkce.code_verifier.len(), 43);

        // Challenge should be SHA256 of verifier, base64url-encoded (43 chars)
        assert_eq!(pkce.code_challenge.len(), 43);

        // Verify the challenge is the correct SHA256 of the verifier
        let mut hasher = Sha256::new();
        hasher.update(pkce.code_verifier.as_bytes());
        let expected = BASE64_URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(pkce.code_challenge, expected);
    }

    #[test]
    fn test_generate_pkce_uniqueness() {
        let pkce1 = generate_pkce();
        let pkce2 = generate_pkce();
        assert_ne!(pkce1.code_verifier, pkce2.code_verifier);
        assert_ne!(pkce1.code_challenge, pkce2.code_challenge);
    }

    #[test]
    fn test_deserialize_discovery_document() {
        let json = r#"{
            "issuer": "https://example.com",
            "device_authorization_endpoint": "/oauth/device/code",
            "token_endpoint": "/oauth/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"]
        }"#;

        let doc: OidcDiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://example.com");
        assert_eq!(doc.device_authorization_endpoint, "/oauth/device/code");
        assert_eq!(doc.token_endpoint, "/oauth/token");
        assert_eq!(doc.grant_types_supported.len(), 1);
    }

    #[test]
    fn test_deserialize_discovery_document_minimal() {
        let json = r#"{
            "issuer": "https://example.com",
            "device_authorization_endpoint": "/device",
            "token_endpoint": "/token"
        }"#;

        let doc: OidcDiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://example.com");
        assert!(doc.grant_types_supported.is_empty());
    }

    #[test]
    fn test_deserialize_device_authorization_response() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "WXYZ-1234",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WXYZ-1234",
            "expires_in": 900,
            "interval": 5
        }"#;

        let response: DeviceAuthorizationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.device_code, "abc123");
        assert_eq!(response.user_code, "WXYZ-1234");
        assert_eq!(response.verification_uri, "https://example.com/device");
        assert_eq!(
            response.verification_uri_complete.as_deref(),
            Some("https://example.com/device?user_code=WXYZ-1234")
        );
        assert_eq!(response.expires_in, 900);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn test_deserialize_device_authorization_response_defaults() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "WXYZ-1234",
            "verification_uri": "https://example.com/device",
            "expires_in": 900
        }"#;

        let response: DeviceAuthorizationResponse = serde_json::from_str(json).unwrap();
        assert!(response.verification_uri_complete.is_none());
        assert_eq!(response.interval, DEFAULT_INTERVAL);
    }

    #[test]
    fn test_deserialize_token_response_success() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiJ9.test.sig",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#;

        let response: DeviceTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            response.access_token.as_deref(),
            Some("eyJhbGciOiJSUzI1NiJ9.test.sig")
        );
        assert!(response.error.is_none());
    }

    #[test]
    fn test_deserialize_token_response_pending() {
        let json = r#"{
            "error": "authorization_pending",
            "error_description": "The authorization request is still pending."
        }"#;

        let response: DeviceTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.error.as_deref(), Some("authorization_pending"));
        assert!(response.access_token.is_none());
    }

    #[test]
    fn test_resolve_endpoint_absolute() {
        let base = Url::parse("http://localhost:4242").unwrap();
        let result = resolve_endpoint(&base, "https://auth.example.com/device").unwrap();
        assert_eq!(result.as_str(), "https://auth.example.com/device");
    }

    #[test]
    fn test_resolve_endpoint_relative() {
        let base = Url::parse("http://localhost:4242").unwrap();
        let result = resolve_endpoint(&base, "/oauth/device/code").unwrap();
        assert_eq!(result.as_str(), "http://localhost:4242/oauth/device/code");
    }

    #[test]
    fn test_resolve_endpoint_relative_no_leading_slash() {
        let base = Url::parse("http://localhost:4242/base/").unwrap();
        let result = resolve_endpoint(&base, "device/authorize").unwrap();
        assert_eq!(
            result.as_str(),
            "http://localhost:4242/base/device/authorize"
        );
    }
}
