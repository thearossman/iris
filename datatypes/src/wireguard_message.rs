//! A WireGuard connection summary.
//! Subscribable alias for [`iris_core::protocols::stream::wireguard::WireGuard`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_fn};
use iris_core::protocols::stream::wireguard::WireGuard;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=wireguard"))]
pub type WireGuardMessage = Box<WireGuard>;

impl FromSession for WireGuardMessage {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("WireGuardMessage,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Wireguard(wg) = &session.data {
            return Some(wg);
        }
        None
    }
}
