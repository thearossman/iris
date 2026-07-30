use array_init::array_init;
use iris_core::CoreId;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

pub const COMBINED_FILE: &str = "conn_log.jsonl";

/// One more than the maximum CoreId.raw() value in use — covers the main
/// core, every RX/sink core configured in the runtime config file, *and*
/// the checkpoint dispatcher's worker cores (see checkpoint_dispatch and
/// main's `--checkpoint-worker-cores`), since those workers also call
/// `with_writer`. Bump if any of those core lists are configured with ids
/// at or above this value.
const ARR_LEN: usize = 64;

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
///
/// The newline is written only if `f` succeeds; a failed serialization
/// produces no output rather than a truncated JSONL record.
#[inline]
pub fn with_writer<F>(core_id: &CoreId, f: F)
where
    F: FnOnce(&mut BufWriter<File>) -> serde_json::Result<()>,
{
    let idx = core_id.raw() as usize;
    assert!(
        idx < ARR_LEN,
        "core_id {} out of bounds; increase ARR_LEN in writer.rs to at least {}",
        idx,
        idx + 1
    );
    let w = unsafe { &mut *writers()[idx].load(Ordering::Relaxed) };
    if f(w).is_ok() {
        let _ = w.write_all(b"\n");
    }
}

/// Flush all per-core write buffers to disk.  Must be called before
/// `finalize_writers` so that the file-size check sees all written data.
pub fn flush_writers() {
    for i in 0..ARR_LEN {
        let w = unsafe { &mut *writers()[i].load(Ordering::Relaxed) };
        let _ = w.flush();
    }
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

/// Concatenate all non-empty per-core files into `COMBINED_FILE` and remove
/// the per-core files.  Must be called after `finalize_writers` (which has
/// already pruned the empty ones).  Uses `io::copy` to stream each file
/// directly into the output buffer without loading records into memory.
pub fn combine_writers() {
    use std::io::copy;

    let out_file = File::create(COMBINED_FILE).expect("create combined output file");
    let mut out = BufWriter::with_capacity(BUF_CAPACITY, out_file);

    for core_id in 0..ARR_LEN {
        let path = format!("{}{}.jsonl", OUTFILE_PREFIX, core_id);
        let p = std::path::Path::new(&path);
        if let Ok(mut f) = File::open(p) {
            copy(&mut f, &mut out).expect("copy per-core file to combined output");
            drop(f);
            let _ = std::fs::remove_file(p);
        }
    }
}
