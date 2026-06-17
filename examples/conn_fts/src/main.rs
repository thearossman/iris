/// Example that prints common TCP connection metrics at connection teardown:
/// RTT (smoothed + variance), retransmits, bytes in flight, loss/reorder events,
/// queuing delay, latency inflation, and throughput.
use clap::Parser;
use iris_compiler::*;
use iris_core::{FiveTuple, Runtime, config::load_config};
use iris_datatypes::conn_fts::*;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

#[callback("tcp,level=L4Terminated")]
fn record_conn(
    five_tuple: &FiveTuple,
    rtt: &TcpRtt,
    rtx: &TcpRetransmits,
    inflight: &TcpInFlight,
    loss_reorder: &TcpLossReorder,
    queueing: &TcpQueuingDelay,
    latency: &TcpLatencyInflation,
    throughput: &TcpThroughput,
) {
    let min_rtt_str = rtt
        .min_rtt()
        .map(|d| format!("{:.3}ms", d.as_micros() as f64 / 1000.0))
        .unwrap_or_else(|| "N/A".into());

    println!(
        "{} | \
        RTT srtt={:.3}ms var={:.3}ms min={} samples={} | \
        RTX orig={} resp={} | \
        Loss orig={} resp={} Reorder orig={} resp={} | \
        InFlight {} | \
        Queueing {} | \
        Latency {} | \
        Throughput {}",
        five_tuple,
        rtt.srtt_us as f64 / 1000.0,
        rtt.rttvar_us as f64 / 1000.0,
        min_rtt_str,
        rtt.sample_count,
        rtx.orig,
        rtx.resp,
        loss_reorder.loss_orig,
        loss_reorder.loss_resp,
        loss_reorder.reorder_orig,
        loss_reorder.reorder_resp,
        serde_json::to_string(&inflight.samples).unwrap_or_default(),
        serde_json::to_string(&queueing.samples).unwrap_or_default(),
        serde_json::to_string(&latency.samples).unwrap_or_default(),
        serde_json::to_string(&throughput.samples).unwrap_or_default(),
    );
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
