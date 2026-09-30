//! `ClientHello` shapes of released clients.
//!
//! A preset here is a complete statement of the hello that a released client
//! sends.  Installing one on a [`ClientConfig`] makes rustls state that
//! client's shape instead of its own, down to the order of the extensions.
//!
//! Every number is transcribed from a packet capture of the release, not from
//! its source.  The capture, its parser and the per-field dumps live outside
//! this crate -- see `docs/fingerprint-firefox.md` and the capture archive in
//! the Xray-rs tree -- and the tests in this crate assert these tables against
//! copies of those numbers held independently, so a table edited to the wrong
//! value here cannot pass.
//!
//! Fork-only: upstream rustls has no such presets.

use alloc::vec;
use alloc::vec::Vec;

use crate::ClientConfig;
use crate::client::{ClientHelloProfile, EchGreaseConfig};
use crate::crypto::SupportedKxGroup;
use crate::crypto::aws_lc_rs::hpke::{
    DH_KEM_X25519_HKDF_SHA256_AES_128, DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
};
use crate::crypto::aws_lc_rs::kx_group::{SECP256R1, X25519, X25519MLKEM768};
use crate::crypto::hpke::{Hpke, HpkePublicKey};
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;

/// Firefox's `ssl_MakeFakeSid`: `out[i] = 0x5a + sum(random[0..=i])`.
///
/// Firefox fills `legacy_session_id` with this function of `ClientHello.random`
/// rather than with fresh random bytes, so an observer can recompute the field
/// rather than treating it as entropy.
fn fake_sid(random: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc: u8 = 0;
    for (o, r) in out.iter_mut().zip(random) {
        acc = acc.wrapping_add(*r);
        *o = 0x5a_u8.wrapping_add(acc);
    }
    out
}

/// The `ClientHello` of Firefox ESR 153.
///
/// [`Self::apply`] installs it -- the profile, the ALPN list, the certificate
/// decompressors and the GREASE ECH extension -- which is the whole of what a
/// caller does to send this shape.  What it does not cover, and why:
///
/// * The one known difference that remains: this fork has no `zstd`
///   certificate decompressor, so the `certificate_compression` extension
///   states two algorithms where Firefox states three (`zlib`, `brotli`,
///   `zstd` in that order).
#[derive(Debug)]
pub struct FirefoxEsr153 {
    key_share_groups: Vec<&'static dyn SupportedKxGroup>,
    /// The public key the GREASE ECH extension encapsulates to.  Nothing holds
    /// its private half, which is what makes it a placeholder: the extension
    /// is never decrypted, and the encapsulation only has to be one the KEM
    /// could have produced.
    placeholder_key: HpkePublicKey,
}

/// Firefox's GREASE ECH cipher suites.
///
/// NSS supports two symmetric suites for HPKE, and draft-ietf-tls-esni section
/// 6.2 asks the extension's selection to vary between the client's supported
/// configurations rather than state one forever, so both are offered.  They
/// share the X25519 key encapsulation mechanism, which is what the placeholder
/// key is generated for.
static GREASE_SUITES: [&dyn Hpke; 2] = [
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];

/// Firefox's GREASE ECH payload, in bytes.
///
/// The inner hello is padded to a constant length and the AEAD tag is appended,
/// so the extension body is 281 B in every hello and 285 B on the wire.
const GREASE_PAYLOAD_LEN: usize = 239;

impl FirefoxEsr153 {
    /// The shape of the first `ClientHello` Firefox ESR 153 sends.
    ///
    /// The key shares are Firefox's three (`x25519mlkem768`, `x25519`,
    /// `secp256r1`) taken from this crate's provider; a profile promises key
    /// shares it can complete, so they cannot be named from a provider that
    /// does not offer them.
    pub fn new() -> Self {
        let key_share_groups: Vec<&'static dyn SupportedKxGroup> =
            vec![X25519MLKEM768, X25519, SECP256R1];
        // GREASE ECH states a real encapsulation, so it needs a public key the
        // KEM accepts.  The private half is dropped: the extension's payload is
        // not a real inner hello, so nothing is ever expected to open it.
        let (placeholder_key, _) = GREASE_SUITES[0]
            .generate_key_pair()
            .expect("an X25519 key pair can always be generated");
        Self {
            key_share_groups,
            placeholder_key,
        }
    }

    /// Install this shape on a client configuration.
    ///
    /// Sets the profile, the ALPN list, the certificate decompressors and the
    /// GREASE ECH extension.  See the type documentation for what is left out.
    pub fn apply(&self, config: &mut ClientConfig) {
        config.client_hello_profile = Some(Arc::new(Self {
            key_share_groups: self.key_share_groups.clone(),
            placeholder_key: self.placeholder_key.clone(),
        }));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Firefox's order (`zlib`, `brotli`, `zstd`), which is by algorithm
        // number, not the order this crate's defaults come in.  The `zstd`
        // entry has no counterpart here; see the type documentation.
        config.cert_decompressors = vec![
            #[cfg(feature = "zlib")]
            crate::compress::ZLIB_DECOMPRESSOR,
            #[cfg(feature = "brotli")]
            crate::compress::BROTLI_DECOMPRESSOR,
        ];
        // Firefox's GREASE ECH: an extension every hello carries, whose
        // cipher suite is drawn from both of the suites above and whose payload
        // is always the same size.  `new` names the first suite and
        // `with_suites` the set the draw comes from.
        config.set_ech_grease(
            EchGreaseConfig::new(GREASE_SUITES[0], self.placeholder_key.clone())
                .with_suites(&GREASE_SUITES)
                .with_payload_len(GREASE_PAYLOAD_LEN),
        );
    }

    /// Firefox's `cipherSuites[]`.  The four static-RSA and three CBC-SHA
    /// entries are suites rustls cannot run; they are offered anyway, and a
    /// server that selects one ends the handshake.
    const CIPHER_SUITES: [CipherSuite; 16] = [
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    ];

    /// Firefox's `SSL_NamedGroupConfig`, whose last two entries are FFDHE
    /// groups no built-in provider offers.
    const NAMED_GROUPS: [NamedGroup; 7] = [
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
        NamedGroup::secp521r1,
        NamedGroup::FFDHE2048,
        NamedGroup::FFDHE3072,
    ];

    /// Firefox's wire order for its first `ClientHello`, minus ECH GREASE
    /// (`0xfe0d`), which rustls emits in its position-mandated tail -- where
    /// Firefox puts it too -- so anything the profile offers that is missing
    /// here still lands at the end.  Taken from the `chsni` capture, so
    /// `server_name` leads.
    const EXTENSION_ORDER: [ExtensionType; 16] = [
        ExtensionType::ServerName,
        ExtensionType::ExtendedMasterSecret,
        ExtensionType::RenegotiationInfo,
        ExtensionType::EllipticCurves,
        ExtensionType::ECPointFormats,
        ExtensionType::SessionTicket,
        ExtensionType::ALProtocolNegotiation,
        ExtensionType::StatusRequest,
        ExtensionType::DelegatedCredentials,
        ExtensionType::SCT,
        ExtensionType::KeyShare,
        ExtensionType::SupportedVersions,
        ExtensionType::SignatureAlgorithms,
        ExtensionType::PSKKeyExchangeModes,
        ExtensionType::RecordSizeLimit,
        ExtensionType::CompressCertificate,
    ];

    /// Firefox's `signature_algorithms`: 11 schemes, with no Ed25519.
    const SIGNATURE_SCHEMES: [SignatureScheme; 11] = [
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PKCS1_SHA1,
    ];

    /// The extensions rustls has no implementation for, as Firefox states them.
    const RAW_EXTENSIONS: [(ExtensionType, &[u8]); 5] = [
        (ExtensionType::RenegotiationInfo, &[0x00]),
        (ExtensionType::SessionTicket, &[]),
        (
            ExtensionType::DelegatedCredentials,
            &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03],
        ),
        (ExtensionType::SCT, &[]),
        (ExtensionType::RecordSizeLimit, &[0x40, 0x01]),
    ];
}

impl Default for FirefoxEsr153 {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHelloProfile for FirefoxEsr153 {
    fn extension_order(&self, available: &[ExtensionType]) -> Option<Vec<ExtensionType>> {
        let mut order: Vec<_> = Self::EXTENSION_ORDER
            .iter()
            .copied()
            .filter(|typ| available.contains(typ))
            .collect();
        let extra: Vec<_> = available
            .iter()
            .copied()
            .filter(|typ| !order.contains(typ))
            .collect();
        order.extend(extra);
        Some(order)
    }

    fn cipher_suites(&self, _available: &[SupportedCipherSuite]) -> Option<Vec<CipherSuite>> {
        Some(Self::CIPHER_SUITES.to_vec())
    }

    fn named_groups(&self, _available: &[NamedGroup]) -> Option<Vec<NamedGroup>> {
        Some(Self::NAMED_GROUPS.to_vec())
    }

    fn key_share_groups(
        &self,
        _available: &[&'static dyn SupportedKxGroup],
    ) -> Option<Vec<&'static dyn SupportedKxGroup>> {
        Some(self.key_share_groups.clone())
    }

    fn signature_schemes(&self, _available: &[SignatureScheme]) -> Option<Vec<SignatureScheme>> {
        Some(Self::SIGNATURE_SCHEMES.to_vec())
    }

    fn session_id(&self, client_random: &[u8; 32]) -> Option<[u8; 32]> {
        Some(fake_sid(client_random))
    }

    fn raw_extensions(&self) -> Vec<(ExtensionType, Vec<u8>)> {
        Self::RAW_EXTENSIONS
            .iter()
            .map(|(typ, body)| (*typ, body.to_vec()))
            .collect()
    }
}
