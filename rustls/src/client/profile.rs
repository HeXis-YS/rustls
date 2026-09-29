//! Pluggable shaping of the outgoing `ClientHello`.
//!
//! rustls emits the extensions that carry no ordering requirement in a hashed
//! order, which keeps the emitting implementation unobservable but also makes
//! the resulting `ClientHello` unmatchable against a specific client.  A
//! [`ClientHelloProfile`] pins that order so the wire image can be made to
//! match a known implementation.
//!
//! Installing no profile leaves every default in place.

use alloc::vec::Vec;
use core::fmt;

use crate::msgs::enums::ExtensionType;

/// Overrides for the shape of the `ClientHello` rustls emits.
///
/// Every method has a default that reproduces rustls's own behaviour, so an
/// implementation only states the dimensions it wants to change.
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
}
