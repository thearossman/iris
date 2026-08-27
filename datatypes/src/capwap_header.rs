//! A CAPWAP header.
//! Subscribable alias for [`iris_core::protocols::stream::capwap::Capwap`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_fn};
use iris_core::protocols::stream::capwap::Capwap;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=capwap"))]
pub type CapwapHeader = Box<Capwap>;

impl FromSession for CapwapHeader {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("CapwapHeader,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Capwap(capwap) = &session.data {
            return Some(capwap);
        }
        None
    }
}
