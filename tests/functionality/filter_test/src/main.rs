use iris_compiler::*;
use iris_core::FiveTuple;
use iris_core::subscription::FilterResult;
use iris_core::{Runtime, config::default_config};
use iris_datatypes::{ConnRecord, TlsHandshake};

// Try with multiple data types
#[filter("level=InL4Conn")]
fn test_filter(conn: &ConnRecord, _: &TlsHandshake) -> FilterResult {
    if conn.total_pkts() > 1 {
        FilterResult::Accept
    } else {
        FilterResult::Continue
    }
}

#[callback("tls and test_filter,level=InL4Conn")]
fn test_callback(_: &ConnRecord, ft: &FiveTuple) -> bool {
    println!("invoked: {:?}", ft);
    false
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
