#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use std::sync::OnceLock;

use pki_types::{CertificateDer, ServerName};

use crate::client::{
    ClientConfig, ClientConnection, ClientHelloProfile, EchGreaseConfig, EchMode, Resumption,
    Tls12Resumption,
};
use crate::crypto::{ActiveKeyExchange, CryptoProvider, SupportedKxGroup};
use crate::enums::{CipherSuite, ProtocolVersion, SignatureScheme};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, HelloRetryRequest, Random,
    ServerHelloPayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload, OutboundOpaqueMessage};
use crate::sync::Arc;
use crate::{Error, PeerIncompatible, PeerMisbehaved, RootCertStore, SupportedCipherSuite};

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use std::sync::OnceLock;

    use super::super::*;
    use crate::client::AlwaysResolvesClientRawPublicKeys;
    use crate::crypto::cipher::MessageEncrypter;
    use crate::crypto::tls13::OkmBlock;
    use crate::enums::CertificateType;
    use crate::msgs::base::PayloadU8;
    use crate::msgs::enums::ECCurveType;
    use crate::msgs::handshake::{
        CertificateChain, EcParameters, HelloRetryRequestExtensions, KeyShareEntry,
        ServerEcdhParams, ServerExtensions, ServerKeyExchange, ServerKeyExchangeParams,
        ServerKeyExchangePayload,
    };
    use crate::msgs::message::PlainMessage;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{PrivateKeyDer, UnixTime};
    use crate::sign::CertifiedKey;
    use crate::tls13::key_schedule::{derive_traffic_iv, derive_traffic_key};
    use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use crate::{DigitallySignedStruct, DistinguishedName, KeyLog, version};

    /// Tests that session_ticket(35) extension
    /// is not sent if the client does not support TLS 1.2.
    #[test]
    fn test_no_session_ticket_request_on_tls_1_3() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.resumption = Resumption::in_memory_sessions(128)
            .tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(ch.extensions.session_ticket.is_none());
    }

    #[test]
    fn client_hello_profile_pins_extension_order() {
        let profile = Arc::new(ReverseExtensionOrder::default());
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_profile = Some(profile.clone());

        let order = client_hello_extension_order(config).unwrap();
        let offered = profile
            .offered
            .get()
            .expect("profile was consulted");
        assert!(
            offered.len() > 3,
            "expected several mutable extensions, got {offered:?}"
        );

        // Extensions rustls must keep in a fixed position (eg. the ECH and PSK
        // tail) are not part of the profile's input and follow it untouched.
        let mut expected: Vec<_> = offered.iter().rev().copied().collect();
        expected.extend(
            order
                .iter()
                .copied()
                .filter(|ext| !offered.contains(ext)),
        );

        assert_eq!(order, expected);
    }

    #[test]
    fn client_hello_profile_rejects_non_permutation() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_profile = Some(Arc::new(BogusExtensionOrder));

        let order = client_hello_extension_order(config).unwrap();

        assert_ne!(order, vec![ExtensionType::Cookie]);
        assert!(order.len() > 3, "expected the offered set, got {order:?}");
    }

    /// The extensions Firefox 153 advertises for features rustls does not
    /// implement, with the bytes the capture shows.  They are emitted verbatim,
    /// participate in the profile's order, and one of them replaces a slot
    /// rustls has (`renegotiation_info`) rather than being sent twice.
    #[test]
    fn client_hello_profile_emits_raw_extensions_verbatim() {
        let profile = Arc::new(RawExtensions {
            raw: vec![
                (ExtensionType::SCT, vec![]),
                (ExtensionType::RecordSizeLimit, vec![0x40, 0x01]),
                (
                    ExtensionType::DelegatedCredentials,
                    vec![0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03],
                ),
                (ExtensionType::RenegotiationInfo, vec![0x00]),
            ],
            ..Default::default()
        });
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_profile = Some(profile.clone());

        let exts = client_hello_extensions(config).unwrap();
        let body = |typ| {
            let mut found = exts.iter().filter(|(t, _)| *t == typ);
            let first = found
                .next()
                .map(|(_, body)| body.clone());
            assert!(found.next().is_none(), "{typ:?} emitted more than once");
            first
        };
        assert_eq!(body(ExtensionType::SCT), Some(vec![]));
        assert_eq!(body(ExtensionType::RecordSizeLimit), Some(vec![0x40, 0x01]));
        assert_eq!(
            body(ExtensionType::DelegatedCredentials),
            Some(vec![
                0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03
            ])
        );
        assert_eq!(body(ExtensionType::RenegotiationInfo), Some(vec![0x00]));

        // The raw types are offered to `extension_order`, so a permutation that
        // names them fixes their position like any other extension.
        let offered = profile
            .offered
            .get()
            .expect("profile was consulted");
        for typ in [
            ExtensionType::SCT,
            ExtensionType::RecordSizeLimit,
            ExtensionType::DelegatedCredentials,
            ExtensionType::RenegotiationInfo,
        ] {
            assert!(offered.contains(&typ), "{typ:?} missing from {offered:?}");
        }
    }

    /// `signature_algorithms` is the one extension whose content comes from
    /// somewhere other than the hello itself: rustls takes it from the
    /// certificate verifier.  A profile states its own list, and what the
    /// verifier would have said does not leak into the offer.
    #[test]
    fn client_hello_profile_pins_signature_schemes() {
        let profile = Arc::new(SignatureSchemes::default());
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_profile = Some(profile.clone());

        let exts = client_hello_extensions(config).unwrap();
        let body = exts
            .iter()
            .find(|(typ, _)| *typ == ExtensionType::SignatureAlgorithms)
            .expect("no signature_algorithms extension")
            .1
            .clone();

        // Two-byte list length, then one `u16` per scheme.
        assert_eq!(body.len(), 2 + 2 * FIREFOX_ESR153_SIGNATURE_SCHEMES.len());
        let mut expected = Vec::new();
        for scheme in FIREFOX_ESR153_SIGNATURE_SCHEMES {
            expected.extend_from_slice(&u16::from(scheme).to_be_bytes());
        }
        assert_eq!(body[2..], expected[..]);

        // The verifier's list is what would have gone out without the profile.
        // It differs from Firefox's -- no provider states Firefox's exact
        // list -- so the override is observable here.
        let offered = profile
            .offered
            .get()
            .expect("profile was consulted");
        assert!(
            *offered != FIREFOX_ESR153_SIGNATURE_SCHEMES,
            "nothing to override: {offered:?}"
        );
    }

    /// The whole Firefox ESR 153 shape, assembled from the capture: extension
    /// set and order, cipher suites, groups, key shares, session id, the
    /// extensions rustls does not implement, and a GREASE ECH extension of
    /// Firefox's constant size.  Certificate compression drops out when the
    /// decompressor features it needs are compiled out.
    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_profile_reproduces_firefox_esr153_shape() {
        use crate::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
        use crate::crypto::hpke::Hpke;

        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        crate::client::FirefoxEsr153::new().apply(&mut config);
        // Firefox pads its inner hello to a constant size, so the GREASE ECH
        // extension is the same length in every ClientHello it sends.
        let (placeholder_key, _) = DH_KEM_X25519_HKDF_SHA256_AES_128
            .generate_key_pair()
            .unwrap();
        config.set_ech_grease(
            EchGreaseConfig::new(DH_KEM_X25519_HKDF_SHA256_AES_128, placeholder_key)
                .with_payload_len(239),
        );
        let for_record_len = config.clone();

        let compression = !config.cert_decompressors.is_empty();
        let exts = client_hello_extensions(config).unwrap();
        let types: Vec<_> = exts
            .iter()
            .map(|(typ, _)| *typ)
            .collect();

        let expected: Vec<_> = FIREFOX_ESR153_EXTENSION_ORDER
            .iter()
            .copied()
            .filter(|typ| *typ != ExtensionType::CompressCertificate || compression)
            .chain([ExtensionType::EncryptedClientHello])
            .collect();
        assert_eq!(
            types, expected,
            "extension set or order differs from Firefox"
        );

        let body = |typ| {
            exts.iter()
                .find(|(seen, _)| *seen == typ)
                .unwrap_or_else(|| panic!("{typ:?} missing"))
                .1
                .clone()
        };
        // Body lengths and values, as `parsed-153.3.0esr.txt` reports them.
        assert_eq!(body(ExtensionType::ServerName).len(), 5 + "localhost".len());
        assert!(body(ExtensionType::ExtendedMasterSecret).is_empty());
        assert_eq!(body(ExtensionType::RenegotiationInfo), vec![0x00]);
        assert_eq!(body(ExtensionType::EllipticCurves).len(), 16);
        assert_eq!(body(ExtensionType::ECPointFormats).len(), 2);
        assert!(body(ExtensionType::SessionTicket).is_empty());
        assert_eq!(body(ExtensionType::ALProtocolNegotiation).len(), 14);
        assert_eq!(body(ExtensionType::StatusRequest).len(), 5);
        assert_eq!(
            body(ExtensionType::DelegatedCredentials),
            vec![0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]
        );
        assert!(body(ExtensionType::SCT).is_empty());
        assert_eq!(body(ExtensionType::KeyShare).len(), 1327);
        assert_eq!(body(ExtensionType::SupportedVersions).len(), 5);
        // Two-byte list length, then Firefox's eleven schemes with no Ed25519.
        let mut sigalgs = vec![0x00, 0x16];
        for scheme in FIREFOX_ESR153_SIGNATURE_SCHEMES {
            sigalgs.extend_from_slice(&u16::from(scheme).to_be_bytes());
        }
        assert_eq!(body(ExtensionType::SignatureAlgorithms), sigalgs);
        assert_eq!(body(ExtensionType::PSKKeyExchangeModes).len(), 2);
        assert_eq!(body(ExtensionType::RecordSizeLimit), vec![0x40, 0x01]);
        // Firefox pads the inner hello of its GREASE ECH to a constant size, so
        // this extension is the same length in every ClientHello it sends.
        assert_eq!(body(ExtensionType::EncryptedClientHello).len(), 281);
        if compression {
            // Firefox states `zlib`, `brotli`, `zstd` in that order (7 bytes);
            // this fork has no `zstd` decompressor, so the table is Firefox's
            // first two entries, in Firefox's order (by algorithm number).
            let algorithms: &[u16] = &[
                #[cfg(feature = "zlib")]
                0x00_01,
                #[cfg(feature = "brotli")]
                0x00_02,
            ];
            // The list's length is in bytes, two per algorithm (RFC 8879).
            let mut expected = vec![(algorithms.len() * 2) as u8];
            for algorithm in algorithms {
                expected.extend_from_slice(&algorithm.to_be_bytes());
            }
            assert_eq!(body(ExtensionType::CompressCertificate), expected);
        }

        let bytes: usize = types
            .iter()
            .map(|typ| 4 + body(*typ).len())
            .sum();
        std::println!("firefox-shaped extensions: {types:?}");
        std::println!("extension bytes: {bytes}");

        // Firefox's first `ClientHello` is 1899 B on the wire (`README.md`,
        // size table).  With the profile on, ours is that minus exactly the two
        // differences left: the shorter name this test asks for (7 B) and
        // Firefox's third decompressor (2 B; the whole 11 B extension is
        // missing when the features are compiled out).
        let record_len = client_hello_record_len(for_record_len).unwrap();
        let sni_delta = 21 - (5 + "localhost".len());
        let compression_delta = if compression { 2 } else { 11 };
        std::println!("record bytes: {record_len}");
        assert_eq!(record_len + sni_delta + compression_delta, 1899);
    }

    /// Firefox sends a GREASE ECH extension of one constant size (281 B body /
    /// 285 B on the wire for 153, per `parsed-153.3.0esr.txt`).  Both halves of
    /// that matter for a shape: the extension is in the list JA3/JA4 read, and
    /// its length does not vary with the rest of the ClientHello the way
    /// rustls' own sizing of the dummy payload does.
    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn grease_ech_payload_can_be_pinned() {
        use crate::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
        use crate::crypto::hpke::Hpke;

        let (placeholder_key, _) = DH_KEM_X25519_HKDF_SHA256_AES_128
            .generate_key_pair()
            .unwrap();
        let grease = EchGreaseConfig::new(DH_KEM_X25519_HKDF_SHA256_AES_128, placeholder_key)
            .with_payload_len(239);

        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_ech(EchMode::Grease(grease))
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let exts = client_hello_extensions(config).unwrap();
        let body = exts
            .iter()
            .find(|(typ, _)| *typ == ExtensionType::EncryptedClientHello)
            .expect("no ECH extension")
            .1
            .clone();

        // outer(1) + cipher suite(4) + config_id(1) + enc(2 + 32) + payload(2 + 239)
        assert_eq!(body.len(), 281);
        assert_eq!(body[0], 0x00, "client hello outer");
        assert_eq!(&body[1..3], &[0x00, 0x01], "HKDF-SHA256");
        assert_eq!(&body[3..5], &[0x00, 0x01], "AES-128-GCM");
        assert_eq!(&body[6..8], &[0x00, 0x20], "32-byte X25519 encapsulation");
        assert_eq!(&body[40..42], &[0x00, 0xef], "239-byte payload");
    }

    /// draft-ietf-tls-esni asks GREASE ECH to "vary [the cipher suite] to
    /// exercise all supported configurations", so a configuration that names
    /// several suites must not keep sending one.  Nothing else about those
    /// extensions differs on the wire -- same KEM, same tag length, same pinned
    /// payload -- so the two `aead_id` bytes are the whole observation.
    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn grease_ech_cipher_suite_varies_across_handshakes() {
        use crate::crypto::aws_lc_rs::hpke::{
            DH_KEM_X25519_HKDF_SHA256_AES_128, DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        };
        use crate::crypto::hpke::Hpke;

        static SUITES: [&dyn Hpke; 2] = [
            DH_KEM_X25519_HKDF_SHA256_AES_128,
            DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        ];

        let (placeholder_key, _) = SUITES[0].generate_key_pair().unwrap();
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_ech(EchMode::Grease(
                    EchGreaseConfig::new(SUITES[0], placeholder_key)
                        .with_suites(&SUITES)
                        .with_payload_len(239),
                ))
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();

        let mut seen = Vec::new();
        for _ in 0..64 {
            let exts = client_hello_extensions(config.clone()).unwrap();
            let body = exts
                .iter()
                .find(|(typ, _)| *typ == ExtensionType::EncryptedClientHello)
                .expect("no ECH extension")
                .1
                .clone();
            assert_eq!(body.len(), 281, "the payload length is pinned");
            let aead = u16::from_be_bytes([body[3], body[4]]);
            assert!(
                matches!(aead, 1 | 3),
                "suite outside the configured pair: {aead}"
            );
            if !seen.contains(&aead) {
                seen.push(aead);
            }
        }
        // Sixty-four handshakes all landing on one of two suites has a
        // probability of 2^-63, so this cannot pass by chance.
        assert_eq!(seen.len(), 2, "the suite never varied: {seen:?}");
    }

    /// Firefox derives `legacy_session_id` from `ClientHello.random`
    /// (`ssl_MakeFakeSid`) so the field costs no entropy and a passive observer
    /// can recompute it.  A profile states that derivation; the point of the
    /// test is that the random handed to the profile is the one that goes out.
    #[test]
    fn client_hello_profile_pins_session_id_from_client_random() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_profile = Some(Arc::new(FakeSid));

        let (random, session_id) = client_hello_random_and_session_id(config).unwrap();
        assert_eq!(session_id.len(), 32);
        assert_eq!(&session_id[..], &fake_sid(&random)[..]);
    }

    /// Without a profile the field is still what rustls always made it: 32
    /// random bytes on a fresh TLS 1.3 TCP handshake.
    #[test]
    fn session_id_defaults_to_random_bytes() {
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();

        let (random, session_id) = client_hello_random_and_session_id(config).unwrap();
        assert_eq!(session_id.len(), 32);
        assert_ne!(&session_id[..], &fake_sid(&random)[..]);
    }

    #[test]
    fn client_hello_profile_pins_cipher_suites_groups_and_key_shares() {
        // Each dimension JA3 reads off reaches the wire as the profile stated
        // it, in the order it stated.  The lists here are deliberately not what
        // rustls would have chosen: reversed, thinned and re-ordered.
        let provider = super::provider::default_provider();
        let cipher_suites: Vec<_> = provider
            .cipher_suites
            .iter()
            .rev()
            .map(|cs| cs.suite())
            .collect();
        let named_groups: Vec<_> = provider
            .kx_groups
            .iter()
            .rev()
            .map(|group| group.name())
            .collect();
        let key_share_groups: Vec<_> = provider
            .kx_groups
            .iter()
            .rev()
            .take(2)
            .copied()
            .collect();
        let key_share_names: Vec<_> = key_share_groups
            .iter()
            .map(|group| group.name())
            .collect();

        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_profile = Some(Arc::new(PinnedShape {
            cipher_suites: cipher_suites.clone(),
            named_groups: named_groups.clone(),
            key_share_groups,
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(ch.cipher_suites, cipher_suites);
        assert_eq!(
            ch.extensions.named_groups.as_deref(),
            Some(&named_groups[..])
        );
        assert_eq!(
            ch.extensions
                .key_shares
                .as_ref()
                .unwrap()
                .iter()
                .map(|share| share.group)
                .collect::<Vec<_>>(),
            key_share_names
        );
    }

    #[test]
    fn client_hello_profile_rejects_key_share_group_it_cannot_start() {
        // Advertising a group we cannot use is fine: the offer is just bytes,
        // and a server that insists on it gets a fatal `HelloRetryRequest`
        // failure.  Sending a *share* for one is not, because a share promises
        // a private key we do not have.
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let unstartable: &'static dyn SupportedKxGroup = &UnstartableKxGroup;
        config.client_hello_profile = Some(Arc::new(PinnedShape {
            key_share_groups: vec![unstartable],
            ..Default::default()
        }));

        assert!(matches!(
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap()),
            Err(Error::General(_))
        ));
    }

    /// A key share is sized by its group, and the sizes are what the captured
    /// Firefox `ClientHello` shows: 1216 / 32 / 65 bytes for this triple, plus
    /// 4 bytes of group and length per entry and the list's own 2 byte length.
    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_profile_key_shares_match_firefox_sizes() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        crate::client::FirefoxEsr153::new().apply(&mut config);

        let ch = client_hello_sent_for_config(config).unwrap();
        let shares = ch
            .extensions
            .key_shares
            .as_ref()
            .unwrap();

        let mut encoded = Vec::new();
        shares.clone().encode(&mut encoded);
        assert_eq!(encoded.len(), 1327);
    }

    /// A profile can name suites rustls has no implementation for -- that is
    /// what reproducing someone else's offer means -- but being unable to run
    /// one is not a reason to accept it.  A server that selects such a suite
    /// ends the handshake.
    #[test]
    fn client_hello_profile_fails_on_a_suite_rustls_cannot_run() {
        let provider = super::provider::default_provider();
        let mut config = ClientConfig::builder_with_provider(provider.clone().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_profile = Some(Arc::new(PinnedShape {
            cipher_suites: vec![CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256],
            ..Default::default()
        }));
        let config = Arc::new(config);

        let mut conn =
            ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        // A TLS 1.2 ServerHello (no `supported_versions` extension) selecting one
        // of the static-RSA suites the profile added.
        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random::new(config.provider.secure_random).unwrap(),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions::default()),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(PeerMisbehaved::SelectedUnofferedCipherSuite.into())
        );
    }

    #[test]
    fn test_no_renegotiation_scsv_on_tls_1_3() {
        let ch = client_hello_sent_for_config(
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth(),
        )
        .unwrap();
        assert!(
            !ch.cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        );
    }

    #[test]
    fn test_client_does_not_offer_sha1() {
        for version in crate::ALL_VERSIONS {
            let config =
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots())
                    .with_no_client_auth();
            let ch = client_hello_sent_for_config(config).unwrap();
            assert!(
                !ch.extensions
                    .signature_schemes
                    .as_ref()
                    .unwrap()
                    .contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }

    #[test]
    fn test_client_rejects_hrr_with_varied_session_id() {
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        // server replies with HRR, but does not echo `session_id` as required.
        let hrr = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: HelloRetryRequestExtensions {
                        cookie: Some(PayloadU16::new(vec![1, 2, 3, 4])),
                        ..HelloRetryRequestExtensions::default()
                    },
                }),
            )),
        };

        conn.read_tls(&mut hrr.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId.into()
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }

        let config = Arc::new(config);
        let mut conn =
            ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random::new(config.provider.secure_random).unwrap(),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions::default()),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into())
        );
    }

    #[test]
    fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
        let cas_sending_server_verifier =
            ServerVerifierWithAuthorityNames(vec![DistinguishedName::from(b"hello".to_vec())]);

        for (protocol_version, cas_extension_expected) in
            [(&version::TLS12, false), (&version::TLS13, true)]
        {
            let client_hello = client_hello_sent_for_config(
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[protocol_version])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(cas_sending_server_verifier.clone()))
                    .with_no_client_auth(),
            )
            .unwrap();
            assert_eq!(
                client_hello
                    .extensions
                    .certificate_authority_names
                    .is_some(),
                cas_extension_expected
            );
        }
    }

    /// Regression test for <https://github.com/seanmonstar/reqwest/issues/2191>
    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_with_custom_verifier_can_accept_ecdsa_sha1_signatures() {
        let verifier = Arc::new(ExpectSha1EcdsaVerifier::default());
        let config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let cert = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::Certificate(CertificateChain(vec![CertificateDer::from(
                    &b"does not matter"[..],
                )])),
            )),
        };
        conn.read_tls(&mut cert.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_kx = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(
                    ServerKeyExchange {
                        dss: DigitallySignedStruct::new(
                            SignatureScheme::ECDSA_SHA1_Legacy,
                            b"also does not matter".to_vec(),
                        ),
                        params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
                            curve_params: EcParameters {
                                curve_type: ECCurveType::NamedCurve,
                                named_group: NamedGroup::X25519,
                            },
                            public: PayloadU8::new(vec![0xab; 32]),
                        }),
                    },
                )),
            )),
        };
        conn.read_tls(&mut server_kx.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_done = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHelloDone,
            )),
        };
        conn.read_tls(&mut server_done.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        assert!(
            verifier
                .seen_sha1_signature
                .load(Ordering::SeqCst)
        );
    }

    #[derive(Debug, Default)]
    struct ExpectSha1EcdsaVerifier {
        seen_sha1_signature: AtomicBool,
    }

    impl ServerCertVerifier for ExpectSha1EcdsaVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            assert_eq!(dss.scheme, SignatureScheme::ECDSA_SHA1_Legacy);
            self.seen_sha1_signature
                .store(true, Ordering::SeqCst);
            Ok(HandshakeSignatureValid::assertion())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_SHA1_Legacy]
        }
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions::default()),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::X509),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::X509),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_accepts_rpk_server() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::RawPublicKey),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Ok(())
        );
    }

    fn client_requiring_rpk_receives_server_ee(
        encrypted_extensions: ServerExtensions<'_>,
    ) -> Result<(), Error> {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut conn = ClientConnection::new(
            client_config_for_rpk(fake_server_crypto.clone()).into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(encrypted_extensions)),
            )),
        };

        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let enc_ee = encrypter
            .encrypt(PlainMessage::from(ee).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut enc_ee.encode().as_slice())
            .unwrap();
        conn.process_new_packets().map(|_| ())
    }

    fn client_config_for_rpk(key_log: Arc<dyn KeyLog>) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifierRequiringRpk))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
                client_certified_key(),
            ))));
        config.key_log = key_log;
        config
    }

    fn client_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(client_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new(public_key_as_cert, key)
    }

    fn client_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/client.key").as_slice(),
        )
        .unwrap()
    }

    fn x25519_provider() -> CryptoProvider {
        // ensures X25519 is offered irrespective of cfg(feature = "fips"), which eases
        // creation of fake server messages.
        CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        }
    }

    #[derive(Clone, Debug)]
    struct ServerVerifierWithAuthorityNames(Vec<DistinguishedName>);

    impl ServerCertVerifier for ServerVerifierWithAuthorityNames {
        fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
            Some(self.0.as_slice())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }
    }

    #[derive(Debug)]
    struct ServerVerifierRequiringRpk;

    impl ServerCertVerifier for ServerVerifierRequiringRpk {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct FakeServerCrypto {
        server_handshake_secret: OnceLock<Vec<u8>>,
    }

    impl FakeServerCrypto {
        fn new() -> Self {
            Self {
                server_handshake_secret: OnceLock::new(),
            }
        }

        fn server_handshake_encrypter(&self) -> Box<dyn MessageEncrypter> {
            let cipher_suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();

            let secret = self
                .server_handshake_secret
                .get()
                .unwrap();

            let expander = cipher_suite
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(secret));

            // Derive Encrypter
            let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
            let iv = derive_traffic_iv(expander.as_ref());
            cipher_suite.aead_alg.encrypter(key, iv)
        }
    }

    impl KeyLog for FakeServerCrypto {
        fn will_log(&self, _label: &str) -> bool {
            true
        }

        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
                self.server_handshake_secret
                    .set(secret.to_vec())
                    .unwrap();
            }
        }
    }
}

// invalid with fips, as we can't offer X25519 separately
#[cfg(all(
    feature = "aws-lc-rs",
    feature = "prefer-post-quantum",
    not(feature = "fips")
))]
#[test]
fn hybrid_kx_component_share_offered_if_supported_separately() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(crate::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 2);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
    assert_eq!(key_shares[1].group, NamedGroup::X25519);
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn hybrid_kx_component_share_not_offered_unless_supported_separately() {
    use crate::crypto::aws_lc_rs;
    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    };
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
}

/// The wire length of the `ClientHello` record rustls is about to send.
fn client_hello_record_len(config: ClientConfig) -> Result<usize, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();
    Ok(bytes.len())
}

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

/// The order in which the extensions appeared on the wire.
fn client_hello_extension_order(config: ClientConfig) -> Result<Vec<ExtensionType>, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let mut reader = Reader::init(&bytes);
    let _ = reader.take(5).expect("record header");
    let _ = reader
        .take(4)
        .expect("handshake header");
    let _ = reader.take(2).expect("legacy version");
    let _ = reader.take(32).expect("random");

    let session_id_len = usize::from(u8::read(&mut reader).expect("session id length"));
    let _ = reader
        .take(session_id_len)
        .expect("session id");
    let cipher_suites_len = usize::from(u16::read(&mut reader).expect("cipher suite length"));
    let _ = reader
        .take(cipher_suites_len)
        .expect("cipher suites");
    let compression_len = usize::from(u8::read(&mut reader).expect("compression length"));
    let _ = reader
        .take(compression_len)
        .expect("compressions");

    let extensions_len = usize::from(u16::read(&mut reader).expect("extensions length"));
    let mut extensions = reader
        .sub(extensions_len)
        .expect("extensions");

    let mut order = Vec::new();
    while extensions.any_left() {
        order.push(ExtensionType::read(&mut extensions).expect("extension type"));
        let length = usize::from(u16::read(&mut extensions).expect("extension length"));
        let _ = extensions
            .take(length)
            .expect("extension body");
    }

    Ok(order)
}

/// The `ClientHello.random` and `legacy_session_id` as they appear on the wire.
fn client_hello_random_and_session_id(config: ClientConfig) -> Result<([u8; 32], Vec<u8>), Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let mut reader = Reader::init(&bytes);
    let _ = reader.take(5).expect("record header");
    let _ = reader
        .take(4)
        .expect("handshake header");
    let _ = reader.take(2).expect("legacy version");
    let random: [u8; 32] = reader
        .take(32)
        .expect("random")
        .try_into()
        .unwrap();

    let session_id_len = usize::from(u8::read(&mut reader).expect("session id length"));
    let session_id = reader
        .take(session_id_len)
        .expect("session id")
        .to_vec();

    Ok((random, session_id))
}

/// Firefox's `ssl_MakeFakeSid`: `out[i] = 0x5a + sum(random[0..=i])`.
fn fake_sid(random: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc: u8 = 0;
    for (o, r) in out.iter_mut().zip(random) {
        acc = acc.wrapping_add(*r);
        *o = 0x5a_u8.wrapping_add(acc);
    }
    out
}

/// The ClientHello extensions as `(type, body)` pairs, in wire order.
fn client_hello_extensions(config: ClientConfig) -> Result<Vec<(ExtensionType, Vec<u8>)>, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let mut reader = Reader::init(&bytes);
    let _ = reader.take(5).expect("record header");
    let _ = reader
        .take(4)
        .expect("handshake header");
    let _ = reader.take(2).expect("legacy version");
    let _ = reader.take(32).expect("random");
    let session_id_len = usize::from(u8::read(&mut reader).expect("session id length"));
    let _ = reader
        .take(session_id_len)
        .expect("session id");
    let cipher_suites_len = usize::from(u16::read(&mut reader).expect("cipher suite length"));
    let _ = reader
        .take(cipher_suites_len)
        .expect("cipher suites");
    let compression_len = usize::from(u8::read(&mut reader).expect("compression length"));
    let _ = reader
        .take(compression_len)
        .expect("compressions");
    let extensions_len = usize::from(u16::read(&mut reader).expect("extensions length"));
    let mut extensions = reader
        .sub(extensions_len)
        .expect("extensions");

    let mut out = Vec::new();
    while extensions.any_left() {
        let typ = ExtensionType::read(&mut extensions).expect("extension type");
        let length = usize::from(u16::read(&mut extensions).expect("extension length"));
        let body = extensions
            .take(length)
            .expect("extension body")
            .to_vec();
        out.push((typ, body));
    }
    Ok(out)
}

/// Emits the offered extensions in reverse order, recording what it was offered.
#[derive(Debug, Default)]
struct ReverseExtensionOrder {
    offered: OnceLock<Vec<ExtensionType>>,
}

impl ClientHelloProfile for ReverseExtensionOrder {
    fn extension_order(&self, available: &[ExtensionType]) -> Option<Vec<ExtensionType>> {
        let _ = self.offered.set(available.to_vec());
        let mut order = available.to_vec();
        order.reverse();
        Some(order)
    }
}

/// Returns an order that is not a permutation of what it was offered.
#[derive(Debug)]
struct BogusExtensionOrder;

impl ClientHelloProfile for BogusExtensionOrder {
    fn extension_order(&self, _available: &[ExtensionType]) -> Option<Vec<ExtensionType>> {
        Some(vec![ExtensionType::Cookie])
    }
}

/// States exactly the dimensions it is given, so a mechanism test can assert
/// each one reaches the wire unchanged.
#[derive(Debug, Default)]
struct PinnedShape {
    cipher_suites: Vec<CipherSuite>,
    named_groups: Vec<NamedGroup>,
    key_share_groups: Vec<&'static dyn SupportedKxGroup>,
}

impl ClientHelloProfile for PinnedShape {
    fn cipher_suites(&self, _available: &[SupportedCipherSuite]) -> Option<Vec<CipherSuite>> {
        (!self.cipher_suites.is_empty()).then(|| self.cipher_suites.clone())
    }

    fn named_groups(&self, _available: &[NamedGroup]) -> Option<Vec<NamedGroup>> {
        (!self.named_groups.is_empty()).then(|| self.named_groups.clone())
    }

    fn key_share_groups(
        &self,
        _available: &[&'static dyn SupportedKxGroup],
    ) -> Option<Vec<&'static dyn SupportedKxGroup>> {
        (!self.key_share_groups.is_empty()).then(|| self.key_share_groups.clone())
    }
}

/// States Firefox's `signature_algorithms`, recording the verifier's list it
/// replaces.
#[derive(Debug, Default)]
struct SignatureSchemes {
    offered: OnceLock<Vec<SignatureScheme>>,
}

impl ClientHelloProfile for SignatureSchemes {
    fn signature_schemes(&self, available: &[SignatureScheme]) -> Option<Vec<SignatureScheme>> {
        let _ = self.offered.set(available.to_vec());
        Some(FIREFOX_ESR153_SIGNATURE_SCHEMES.to_vec())
    }
}

/// Derives `legacy_session_id` from the client random, as Firefox does.
#[derive(Debug)]
struct FakeSid;

impl ClientHelloProfile for FakeSid {
    fn session_id(&self, client_random: &[u8; 32]) -> Option<[u8; 32]> {
        Some(fake_sid(client_random))
    }
}

/// Advertises raw extensions verbatim, recording the order it was offered.
#[derive(Debug, Default)]
struct RawExtensions {
    raw: Vec<(ExtensionType, Vec<u8>)>,
    offered: OnceLock<Vec<ExtensionType>>,
}

impl ClientHelloProfile for RawExtensions {
    fn raw_extensions(&self) -> Vec<(ExtensionType, Vec<u8>)> {
        self.raw.clone()
    }

    fn extension_order(&self, available: &[ExtensionType]) -> Option<Vec<ExtensionType>> {
        let _ = self.offered.set(available.to_vec());
        let mut order = available.to_vec();
        order.reverse();
        Some(order)
    }
}

/// Firefox ESR 153's wire order for its first `ClientHello`, minus ECH GREASE
/// (`0xfe0d`): rustls emits that one in its position-mandated tail, which is
/// where Firefox puts it too, so anything the profile offers that is missing
/// here still lands at the end.  Taken from `parsed-153.3.0esr.txt` (the
/// `chsni` capture, so `server_name` leads) -- a copy of the capture's numbers,
/// held here so the shipped [`crate::client::FirefoxEsr153`] is asserted
/// against the capture rather than against itself.
const FIREFOX_ESR153_EXTENSION_ORDER: [ExtensionType; 16] = [
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

/// Firefox ESR 153's `signature_algorithms`: 11 schemes, with no Ed25519.
const FIREFOX_ESR153_SIGNATURE_SCHEMES: [SignatureScheme; 11] = [
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

/// A group no provider offers, standing in for a profile that promises a key
/// share it cannot start.
#[derive(Debug)]
struct UnstartableKxGroup;

impl SupportedKxGroup for UnstartableKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        unreachable!("never started: it is not one of the provider's groups")
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::FFDHE2048
    }
}

fn roots() -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}
