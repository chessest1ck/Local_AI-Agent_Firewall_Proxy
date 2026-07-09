use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair, DistinguishedName, DnType, Issuer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

pub struct MitmCa {
    ca_params: CertificateParams,
    ca_key_pair: KeyPair,
    ca_cert_der: CertificateDer<'static>,
}

impl MitmCa {
    pub fn new() -> Result<Self> {
        info!("Generating new temporary Root CA for MITM...");
        
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Local AI-Agent Firewall Proxy");
        dn.push(DnType::CommonName, "Local AI-Agent Firewall Root CA");
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let key_pair = KeyPair::generate()?;
        let ca_cert = params.self_signed(&key_pair)?;

        // Output instructions for user to trust it.
        let pem_cert = ca_cert.pem();
        warn!("===================================================");
        warn!("NEW ROOT CA GENERATED.");
        warn!("If you want to avoid TLS errors in your agent, trust this certificate:");
        warn!("Save this to 'ca.crt' and set NODE_EXTRA_CA_CERTS='ca.crt' for Node.js");
        println!("{}", pem_cert);
        warn!("===================================================");

        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_params: params,
            ca_key_pair: key_pair,
            ca_cert_der,
        })
    }

    pub fn issue_cert(&self, domain: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Local AI-Agent Firewall Proxy MITM");
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate()?;
        
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key_pair);
        let cert = params.signed_by(&key_pair, &issuer)?;
        
        let key_der = key_pair.serialize_der();

        let cert_chain = vec![
            CertificateDer::from(cert.der().to_vec()),
            self.ca_cert_der.clone(),
        ];

        let private_key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

        Ok((cert_chain, private_key))
    }

    pub fn get_acceptor(&self, domain: &str) -> Result<TlsAcceptor> {
        let (cert_chain, key) = self.issue_cert(domain)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("Failed to build ServerConfig")?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}
