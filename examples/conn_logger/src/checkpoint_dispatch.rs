/// Off-RX-core emission for `FlowWindows` checkpoints.
///
/// `FlowWindows::close_checkpoint` (mid-connection) and `FlowWindows::flush_final`
/// (the last partial checkpoint, at connection termination) both dispatch through
/// `CHECKPOINT_DISPATCHER` instead of serializing and writing inline on the
/// RX/datatype-update core. A small pool of dedicated worker cores (set up in
/// `main()`, see `examples/basic_dispatching/src/bin/dedicated.rs` for the pattern
/// this mirrors) drains the channel and does the actual JSON serialization + write,
/// so no connection's history — however long, however it terminates — can stall
/// packet processing.
use crate::flow_windows::CheckpointRecord;
use crate::AnonFt;

use iris_core::multicore::{ChannelDispatcher, ChannelMode};
use iris_core::CoreId;

use serde::Serialize;
use std::sync::{Arc, OnceLock};

pub(crate) static CHECKPOINT_DISPATCHER: OnceLock<Arc<ChannelDispatcher<CheckpointOutRecord>>> =
    OnceLock::new();

#[derive(Debug, Serialize)]
pub(crate) struct CheckpointOutRecord {
    #[serde(rename = "type")]
    pub(crate) record_type: &'static str,
    pub(crate) five_tuple: AnonFt,
    #[serde(flatten)]
    pub(crate) checkpoint: CheckpointRecord,
}

/// Create the dispatcher and register it globally. Must be called once from
/// `main()`, before the runtime starts, so `FlowWindows` can look it up via
/// `CHECKPOINT_DISPATCHER.get()`. Returns the `Arc` so `main()` can hand it to a
/// `DedicatedWorkerThreadSpawner` (the spawner itself isn't set up here since its
/// handle type isn't nameable outside `iris_core` — see `dedicated.rs`, which
/// inlines the same setup in `main()` for the same reason).
pub(crate) fn init(
    rx_cores: Vec<CoreId>,
    channel_size: usize,
) -> Arc<ChannelDispatcher<CheckpointOutRecord>> {
    let dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::PerCore(rx_cores),
        channel_size,
        "checkpoint_dispatcher".to_string(),
    ));
    CHECKPOINT_DISPATCHER
        .set(dispatcher.clone())
        .map_err(|_| "checkpoint dispatcher already initialized")
        .unwrap();
    dispatcher
}
