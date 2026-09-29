//! Pluggable shaping of the outgoing `ClientHello`.
//!
//! By default rustls states its own capabilities: the cipher suites its
//! provider implements, the groups it can do key exchange with, and a key share
//! for the group it expects to use.  The extensions that carry no ordering
//! requirement are emitted in a hashed order, which keeps the emitting
//! implementation unobservable but also makes the resulting `ClientHello`
//! unmatchable against a specific client.
//!
//! A [`ClientHelloProfile`] pins those choices so the wire image can be made to
//! match a known implementation.  Installing no profile leaves every default in
//! place.

use alloc::vec::Vec;
use core::fmt;

use crate::NamedGroup;
use crate::crypto::SupportedKxGroup;
use crate::enums::CipherSuite;
use crate::msgs::enums::ExtensionType;
use crate::suites::SupportedCipherSuite;

/// Overrides for the shape of the `ClientHello` rustls emits.
///
/// Every method has a default that reproduces rustls's own behaviour, so an
/// implementation only states the dimensions it wants to change.  Every method
/// that returns `Some` replaces the corresponding default outright; nothing is
/// merged into it.
///
/// Extensions whose position is fixed by the protocol (`pre_shared_key`,
/// `encrypted_client_hello`, and the ECH outer extension list) are not
/// addressable here: rustls always emits those last, as required.
pub trait ClientHelloProfile: fmt::Debug + Send + Sync {
    /// Order of the extensions that carry no ordering requirement.
    ///
    /// `available` is the set rustls would otherwise emit in a hashed order.
    /// Returning `None`, or anything that is not a permutation of `available`,
    /// leaves the hashed order in place.
    fn extension_order(&self, available: &[ExtensionType]) -> Option<Vec<ExtensionType>> {
        let _ = available;
        None
    }

    /// Cipher suites to offer, in the order they appear on the wire.
    ///
    /// `available` is what the provider implements.  The returned list is
    /// emitted verbatim, so it may name suites rustls does not implement: those
    /// are offered like any other, and this is deliberate -- a profile exists to
    /// reproduce someone else's offer, not to constrain it to our abilities.
    ///
    /// Offering a suite is not the same as being able to use it.  If a server
    /// selects one rustls has no implementation for, the handshake ends in an
    /// alert rather than continuing with something else.
    fn cipher_suites(&self, available: &[SupportedCipherSuite]) -> Option<Vec<CipherSuite>> {
        let _ = available;
        None
    }

    /// Named groups to advertise, in the order they appear on the wire.
    ///
    /// As with [`Self::cipher_suites`], the returned list is emitted verbatim
    /// and may name groups rustls cannot use.  A server that asks to use one of
    /// those (with a `HelloRetryRequest`) ends the handshake.
    fn named_groups(&self, available: &[NamedGroup]) -> Option<Vec<NamedGroup>> {
        let _ = available;
        None
    }

    /// Groups to send a key share for, in the order they appear on the wire.
    ///
    /// Unlike the lists above this one is a promise rustls has to keep: a key
    /// share is a public key, and completing the exchange later needs the
    /// matching private key.  Every entry must therefore be one of `available`;
    /// naming anything else fails the handshake instead of being ignored,
    /// because the alternative is silently offering a different `ClientHello`
    /// than the profile asked for.
    ///
    /// rustls's hybrid optimisation (offering the classical component of a
    /// hybrid exchange as an extra share) is not applied on top of this list:
    /// what the profile names is what goes on the wire.
    fn key_share_groups(
        &self,
        available: &[&'static dyn SupportedKxGroup],
    ) -> Option<Vec<&'static dyn SupportedKxGroup>> {
        let _ = available;
        None
    }

    /// Value to send as `legacy_session_id`, given the `ClientHello.random` that
    /// goes out beside it.
    ///
    /// In TLS 1.3 this field carries no meaning; it is sent only so a middlebox
    /// mistakes the handshake for one it understands (RFC 8446 appendix D.4).
    /// rustls fills it with fresh random bytes, which makes it a non-constant
    /// that is still, unlike every other field, unrelated to the rest of the
    /// hello.  Firefox instead derives it from `ClientHello.random` itself
    /// (`ssl_MakeFakeSid`), so a passive observer can recompute it and check
    /// that no entropy was spent on it.
    ///
    /// Returning `Some` sends those 32 bytes verbatim.  It applies only where
    /// rustls would otherwise generate a session id -- a fresh TLS 1.3
    /// handshake over TCP.  QUIC keeps an empty session id (RFC 9001 section
    /// 8.4) and a resumed TLS 1.2 session keeps the id it already chose, both
    /// untouched.
    fn session_id(&self, client_random: &[u8; 32]) -> Option<[u8; 32]> {
        let _ = client_random;
        None
    }
}
