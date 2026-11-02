//! Certificate authority for TLS interception.
//!
//! * The root CA (ECDSA P-256) is generated once and persisted to disk.
//! * All leaf certificates share **one** key pair, so minting a certificate for a
//!   new host is a single signature operation (no key generation).
//! * Ready-to-use [`ServerConfig`]s are cached per host.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use quick_cache::sync::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::{CertifiedKey, SigningKey},
};
use time::{Duration, OffsetDateTime};

pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_H1: &[u8] = b"http/1.1";

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("certificate error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("tls error: {0}")]
    Rustls(#[from] rustls::Error),
}

pub type Result<T, E = CaError> = std::result::Result<T, E>;

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    leaf_key: KeyPair,
    leaf_signing_key: Arc<dyn SigningKey>,
    provider: Arc<CryptoProvider>,
    configs: Cache<String, Arc<ServerConfig>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key";

impl CertificateAuthority {
    /// Load the CA from `dir`, generating and persisting a new one if absent.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| CaError::Io { path, source }
        };

        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path).map_err(io(&cert_path))?;
            let key_pem = std::fs::read_to_string(&key_path).map_err(io(&key_path))?;
            tracing::info!(path = %cert_path.display(), "loaded CA certificate");
            return Self::from_pem(&cert_pem, &key_pem);
        }

        std::fs::create_dir_all(dir).map_err(io(dir))?;
        let (cert_pem, key_pem) = generate_ca()?;
        std::fs::write(&cert_path, &cert_pem).map_err(io(&cert_path))?;
        write_private(&key_path, key_pem.as_bytes()).map_err(io(&key_path))?;
        tracing::info!(path = %cert_path.display(), "generated new CA certificate");
        Self::from_pem(&cert_pem, &key_pem)
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let ca_key = KeyPair::from_pem(key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, ca_key)?;
        let ca_der = pem_to_der(cert_pem).ok_or(rcgen::Error::CouldNotParseCertificate)?;

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let leaf_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signing_key = provider.key_provider.load_private_key(leaf_der)?;

        Ok(Self {
            issuer,
            ca_der,
            ca_pem: cert_pem.to_owned(),
            leaf_key,
            leaf_signing_key,
            provider,
            configs: Cache::new(10_000),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    pub fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }

    /// Mint (or fetch from cache) a leaf certificate for `host`.
    pub fn certified_key(&self, host: &str) -> Result<CertifiedKey> {
        let mut params = CertificateParams::default();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(397);
        params.serial_number = Some(self.random_serial()?);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into()?),
        }];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&self.leaf_key, &self.issuer)?;
        Ok(CertifiedKey::new(
            vec![cert.der().clone(), self.ca_der.clone()],
            self.leaf_signing_key.clone(),
        ))
    }

    /// A TLS server config presenting a certificate for `host`, cached per host.
    /// Concurrent calls for the same host mint only one certificate.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.configs.get_or_insert_with(&host, || {
            let key = self.certified_key(&host)?;
            let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
            cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];
            Ok(Arc::new(cfg))
        })
    }

    fn random_serial(&self) -> Result<SerialNumber> {
        let mut buf = [0u8; 16];
        self.provider
            .secure_random
            .fill(&mut buf)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        buf[0] &= 0x7f; // keep it positive
        buf[0] |= 0x01; // and non-zero leading byte
        Ok(SerialNumber::from_slice(&buf))
    }
}

fn generate_ca() -> Result<(String, String)> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Nosy CA");
    dn.push(DnType::OrganizationName, "Nosy");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn pem_to_der(pem: &str) -> Option<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes()).ok()
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        RootCertStore,
        client::{WebPkiServerVerifier, danger::ServerCertVerifier},
        pki_types::{ServerName, UnixTime},
    };

    fn verify(ca: &CertificateAuthority, host: &str) -> std::result::Result<(), rustls::Error> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_der().clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            ca.crypto_provider().clone(),
        )
        .build()
        .unwrap();
        let key = ca.certified_key(host).unwrap();
        verifier
            .verify_server_cert(
                &key.cert[0],
                &key.cert[1..],
                &ServerName::try_from(host.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
    }

    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let a = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let b = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(a.ca_der(), b.ca_der());
    }

    #[test]
    fn leaf_validates_against_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
        verify(&ca, "example.com").unwrap();
        verify(&ca, "127.0.0.1").unwrap();
    }

    #[test]
    fn server_config_is_cached() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let a = ca.server_config("Example.com").unwrap();
        let b = ca.server_config("example.com.").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.alpn_protocols, vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()]);
    }

    #[test]
    fn serials_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let a = ca.certified_key("a.com").unwrap();
        let b = ca.certified_key("a.com").unwrap();
        assert_ne!(a.cert[0], b.cert[0]);
    }
}
