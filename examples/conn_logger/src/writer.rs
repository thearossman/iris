use array_init::array_init;
use iris_core::CoreId;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

/// One more than the maximum CoreId.raw() value.  Must match the number of
/// RX cores configured in the runtime config file.  The +1 accounts for the
/// main core that never processes packets.
const ARR_LEN: usize = 17;

/// 64 KB per-core write buffer — amortises syscall overhead across ~100+
/// records before a flush is needed.
const BUF_CAPACITY: usize = 64 * 1024;

pub const OUTFILE_PREFIX: &str = "conn_log_";

static WRITERS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();

fn writers() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    WRITERS.get_or_init(|| {
        let ptrs: Vec<*mut BufWriter<File>> = (0..ARR_LEN)
            .map(|core_id| {
                let path = format!("{}{}.jsonl", OUTFILE_PREFIX, core_id);
                let w = BufWriter::with_capacity(
                    BUF_CAPACITY,
                    File::create(&path).expect("create output file"),
                );
                Box::into_raw(Box::new(w))
            })
            .collect();
        array_init(|i| AtomicPtr::new(ptrs[i]))
    })
}

/// Force file creation before the runtime starts so that partial runs still
/// produce output files.
pub fn init_writers() {
    let _ = writers();
}

/// Borrow the per-core writer, call `f` to write the record body, then
/// append a newline.  Writes go into a 64 KB `BufWriter` — no intermediate
/// heap allocation is needed by the caller.
#[inline]
pub fn with_writer<F: FnOnce(&mut BufWriter<File>)>(core_id: &CoreId, f: F) {
    let idx = core_id.raw() as usize;
    if idx >= ARR_LEN {
        return;
    }
    let w = unsafe { &mut *writers()[idx].load(Ordering::Relaxed) };
    f(w);
    let _ = w.write_all(b"\n");
}

/// Flush and remove empty per-core files after the runtime finishes.
pub fn finalize_writers() {
    for core_id in 0..ARR_LEN {
        let path = format!("{}{}.jsonl", OUTFILE_PREFIX, core_id);
        let p = std::path::Path::new(&path);
        if let Ok(m) = std::fs::metadata(p) {
            if m.len() == 0 {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}
