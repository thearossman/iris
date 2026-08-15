//! An IKE header.
//! Subscribable alias for [`iris_core::protocols::stream::ike::Ike`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_fn};
use iris_core::protocols::stream::ike::Ike;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=ike"))]
pub type IkeHeader = Box<Ike>;

impl FromSession for IkeHeader {
    #[cfg_attr(not(feature = "skip_expand"), datatype_fn("IkeHeader,level=L7EndHdrs"))]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Ike(ike) = &session.data {
            return Some(ike);
        }
        None
    }
}
