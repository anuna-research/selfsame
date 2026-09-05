//! Explicit, process-local configuration for the native integration test host.
//!
//! This non-default feature changes neither URL recognition nor TLS identity.
//! Only numeric loopback HTTP CONNECT proxies are accepted. Nothing reads trust
//! configuration from the environment. Install once, before starting requests.

use std::{net::IpAddr, sync::OnceLock};

/// Closed configuration failures; input and certificate bytes are never returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// The root is absent, malformed, or not a usable certificate.
    #[error("HostRootRefused")]
    Root,
    /// The proxy is not an HTTP origin with a numeric loopback IP and nonzero port.
    #[error("HostProxyRefused")]
    Proxy,
    /// This process already installed its test configuration.
    #[error("HostAlreadyConfigured")]
    AlreadyConfigured,
}

/// Recognised configuration. Construction performs no network or custody I/O.
pub struct HostConfig {
    root: reqwest::Certificate,
    proxy: reqwest::Proxy,
}

impl HostConfig {
    /// Recognise one PEM certificate and a loopback-only HTTP CONNECT proxy.
    pub fn new(root_pem: &[u8], proxy_url: &str) -> Result<Self, ConfigError> {
        let url = reqwest::Url::parse(proxy_url).map_err(|_| ConfigError::Proxy)?;
        let ip = url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .ok_or(ConfigError::Proxy)?;
        let port = url.port_or_known_default().ok_or(ConfigError::Proxy)?;
        // URL parsing removes an explicitly written default port. Require a
        // canonical explicit authority, including :80, by round-trip equality.
        let origin = format!(
            "http://{}:{port}",
            url.host_str().ok_or(ConfigError::Proxy)?
        );
        if url.scheme() != "http"
            || !ip.is_loopback()
            || port == 0
            || (proxy_url != origin && proxy_url != format!("{origin}/"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigError::Proxy);
        }
        let proxy = reqwest::Proxy::https(url).map_err(|_| ConfigError::Proxy)?;
        let mut roots =
            reqwest::Certificate::from_pem_bundle(root_pem).map_err(|_| ConfigError::Root)?;
        if roots.len() != 1 {
            return Err(ConfigError::Root);
        }
        let root = roots.remove(0);
        // reqwest parses DER when building the rustls connector, not when
        // constructing Certificate. Check that boundary before installation.
        reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root.clone())
            .build()
            .map_err(|_| ConfigError::Root)?;
        Ok(Self { root, proxy })
    }
}

static CONFIG: OnceLock<HostConfig> = OnceLock::new();

/// Enable the recognised configuration once in this test process.
pub fn install(config: HostConfig) -> Result<(), ConfigError> {
    CONFIG
        .set(config)
        .map_err(|_| ConfigError::AlreadyConfigured)
}

pub(crate) fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    match CONFIG.get() {
        Some(config) => apply(builder, config),
        None => builder,
    }
}

fn apply(builder: reqwest::ClientBuilder, config: &HostConfig) -> reqwest::ClientBuilder {
    // Explicit proxy disables ambient/system proxy and NO_PROXY discovery.
    builder
        .no_proxy()
        .proxy(config.proxy.clone())
        .add_root_certificate(config.root.clone())
        // The local host refuses even WebFinger redirects. Production's
        // bounded WebFinger policy remains intact when no config is installed.
        .redirect(reqwest::redirect::Policy::none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn native_host_config_rejects_nonloopback_proxy_and_invalid_root() {
        let pem = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem();
        for proxy in [
            "http://192.0.2.1:4000",
            "http://example.test:4000",
            "http://localhost:4000",
            "https://127.0.0.1:4000",
            "http://127.0.0.1:0",
            "http://127.0.0.1",
            "http://user:secret@127.0.0.1:4000",
            "http://127.0.0.1:4000/path",
            "http://127.0.0.1:4000/?q=1",
            "http://127.0.0.1:4000/#fragment",
        ] {
            assert!(matches!(
                HostConfig::new(pem.as_bytes(), proxy),
                Err(ConfigError::Proxy)
            ));
        }
        for pem in [
            b"".as_slice(),
            b"not PEM",
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        ] {
            assert!(matches!(
                HostConfig::new(pem, "http://127.0.0.1:4000"),
                Err(ConfigError::Root)
            ));
        }
        assert!(HostConfig::new(pem.as_bytes(), "http://[::1]:4000").is_ok());
        assert!(HostConfig::new(pem.as_bytes(), "http://127.0.0.1:80").is_ok());
    }

    #[tokio::test]
    async fn native_host_root_and_connect_proxy_preserve_canonical_https_and_sni() {
        let fixture = crate::test_tls::Fixture::spawn("localhost", true, false);
        let config = HostConfig::new(
            fixture.pem.as_bytes(),
            &format!("http://{}", fixture.address),
        )
        .unwrap();
        // Port 1 is never contacted: CONNECT carries the
        // canonical target; the isolated fixture terminates TLS for that name.
        let client = apply(crate::client_builder(Duration::from_secs(2)), &config)
            .build()
            .unwrap();
        let response = client
            .get("https://localhost:1/profile")
            .send()
            .await
            .expect("configured local root/proxy must reach the isolated TLS fixture");
        assert_eq!(response.text().await.unwrap(), "ok");
        let seen = fixture.join();
        assert_eq!(
            seen.connect.as_deref(),
            Some("CONNECT localhost:1 HTTP/1.1")
        );
        assert_eq!(seen.sni.as_deref(), Some("localhost"));
        assert!(seen.request.starts_with("GET /profile HTTP/1.1\r\n"));
        assert!(seen
            .request
            .to_lowercase()
            .contains("host: localhost:1\r\n"));
    }

    #[tokio::test]
    async fn native_host_override_still_rejects_wrong_hostname_plaintext_and_redirects() {
        let fixture = crate::test_tls::Fixture::spawn("wrong.example.test", true, false);
        let config = HostConfig::new(
            fixture.pem.as_bytes(),
            &format!("http://{}", fixture.address),
        )
        .unwrap();
        let client = apply(crate::client_builder(Duration::from_secs(2)), &config)
            .build()
            .unwrap();
        assert!(client
            .get("https://localhost:1/profile")
            .send()
            .await
            .is_err());
        assert!(fixture.join().request.is_empty());

        let fixture = crate::test_tls::Fixture::spawn("localhost", true, true);
        let config = HostConfig::new(
            fixture.pem.as_bytes(),
            &format!("http://{}", fixture.address),
        )
        .unwrap();
        let client = apply(crate::client_builder(Duration::from_secs(2)), &config)
            .build()
            .unwrap();
        assert!(client
            .get("http://localhost:1/profile")
            .send()
            .await
            .is_err());
        let response = client
            .get("https://localhost:1/profile")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert!(!fixture.join().request.to_lowercase().contains("cookie:"));
    }

    #[tokio::test]
    #[ignore = "installs process-global HTTP configuration; run alone"]
    async fn native_host_explicit_setter_routes_actual_client() {
        let fixture = crate::test_tls::Fixture::spawn("localhost", true, false);
        let config = HostConfig::new(
            fixture.pem.as_bytes(),
            &format!("http://{}", fixture.address),
        )
        .unwrap();
        install(config).unwrap();
        let response = crate::client(Duration::from_secs(2))
            .unwrap()
            .get("https://localhost:1/profile")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(
            fixture.join().connect.as_deref(),
            Some("CONNECT localhost:1 HTTP/1.1")
        );
    }

    #[tokio::test]
    #[ignore = "installs process-global HTTP configuration; run alone"]
    async fn native_host_webfinger_setter_routes_canonical_account_authority() {
        let fixture = crate::test_tls::Fixture::spawn("accounts.example.test", true, true);
        let config = HostConfig::new(
            fixture.pem.as_bytes(),
            &format!("http://{}", fixture.address),
        )
        .unwrap();
        install(config).unwrap();
        let account =
            selfsame_app_identity::alias::AcctUri::parse("acct:fixture@accounts.example.test")
                .unwrap();
        // A 302 arrives over verified TLS, and remains a refused response.
        // No JRD or reciprocal binding is simulated by this transport fixture.
        assert!(matches!(
            crate::webfinger::fetch(&account).await,
            Err(crate::NetError::Refused(_))
        ));
        let seen = fixture.join();
        assert_eq!(
            seen.connect.as_deref(),
            Some("CONNECT accounts.example.test:443 HTTP/1.1")
        );
        assert_eq!(seen.sni.as_deref(), Some("accounts.example.test"));
        assert!(seen.request.starts_with("GET /.well-known/webfinger?resource=acct%3Afixture%40accounts.example.test HTTP/1.1\r\n"));
    }
}
