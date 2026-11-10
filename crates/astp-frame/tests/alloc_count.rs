//! Allocation counter for [`FrameReader`](astp_frame::FrameReader).
//!
//! This file is its own integration-test binary, so the global allocator
//! here does not affect the other tests. The `unsafe` impl is the
//! `GlobalAlloc` contract and stays out of the library.
//!
//! PR #9, same counter: every 16-byte PING was 1 allocation and 16 bytes
//! of extra peak on the first frame, then 0. A DISCONNECT whose reason
//! is 60000 bytes was 6 allocations and 125664 bytes of extra peak.

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use astp_frame::{encode, Frame, FrameBody, FrameReader};

struct CountingAlloc;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn note_alloc(size: usize) {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    let live = LIVE.fetch_add(size, Ordering::Relaxed).saturating_add(size);
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn note_free(size: usize) {
    LIVE.fetch_sub(size, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the size and alignment the caller requested.
        // The pointer comes from the system allocator and is not dereferenced.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same as `alloc`, except the system allocator zeroes the block.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr` was allocated by this allocator with `layout`.
        // On success the old block is gone and the new block has `new_size` bytes.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            REALLOCS.fetch_add(1, Ordering::Relaxed);
            note_free(layout.size());
            note_alloc(new_size);
        }
        new
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) };
        note_free(layout.size());
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

struct Sample {
    allocs: usize,
    reallocs: usize,
    extra_peak: usize,
}

fn sample<T>(body: impl FnOnce() -> T) -> (T, Sample) {
    let base = LIVE.load(Ordering::Relaxed);
    ALLOCS.store(0, Ordering::Relaxed);
    REALLOCS.store(0, Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let value = body();
    let allocs = ALLOCS.load(Ordering::Relaxed);
    let reallocs = REALLOCS.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed);
    let extra_peak = peak.saturating_sub(base);
    (
        value,
        Sample {
            allocs,
            reallocs,
            extra_peak,
        },
    )
}

fn drive<T>(fut: impl Future<Output = T>) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = std::pin::pin!(fut);
    // `Cursor` is always ready, and `read_frame` loops until the frame
    // is finished or the socket returns `Pending`. One poll is enough.
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("frame reader stalled"),
    }
}

fn ping(byte: u8) -> Frame {
    Frame {
        key_epoch: None,
        body: FrameBody::Ping([byte; 8]),
    }
}

fn read_one(frames: &mut FrameReader<std::io::Cursor<Vec<u8>>>) -> (Frame, Sample) {
    let (value, sample) = sample(|| drive(frames.read_frame()).unwrap().unwrap());
    (value, sample)
}

#[test]
fn small_frames_allocate_once_and_a_large_frame_drops_the_buffer() {
    let mut bytes = Vec::new();
    for i in 0..10u8 {
        bytes.extend(encode(&ping(i), None).unwrap());
    }
    let mut frames = FrameReader::new(std::io::Cursor::new(bytes));

    let (first, warmup) = read_one(&mut frames);
    assert_eq!(first, ping(0));
    eprintln!(
        "warmup ping: allocs={} extra_peak={}",
        warmup.allocs, warmup.extra_peak
    );
    assert_eq!(
        warmup.allocs, 1,
        "the first small frame should allocate once"
    );

    let mut steady = Vec::new();
    for i in 1..10u8 {
        let (frame, sample) = read_one(&mut frames);
        assert_eq!(frame, ping(i));
        steady.push(sample.allocs);
    }
    assert!(
        steady.iter().all(|n| *n == 0),
        "small frames after warmup allocated {steady:?}"
    );

    let big = Frame {
        key_epoch: None,
        body: FrameBody::Disconnect {
            code: 1,
            reason: "x".repeat(60_000),
        },
    };
    let mut bytes = encode(&big, None).unwrap();
    bytes.extend(encode(&ping(1), None).unwrap());
    bytes.extend(encode(&ping(2), None).unwrap());
    let mut frames = FrameReader::new(std::io::Cursor::new(bytes));
    let (frame, large) = read_one(&mut frames);
    assert_eq!(frame, big);
    eprintln!(
        "large frame: allocs={} reallocs={} extra_peak={}",
        large.allocs, large.reallocs, large.extra_peak
    );
    assert!(large.allocs >= 1, "large frame made no allocation");
    // One owned copy of the reason, plus the reader buffer, and not a
    // second full copy of that buffer at the same time.
    assert!(
        large.extra_peak < 125_000,
        "large frame peak {} is above the single-buffer plus string ceiling",
        large.extra_peak
    );

    let (frame, after_large) = read_one(&mut frames);
    assert_eq!(frame, ping(1));
    eprintln!(
        "ping after large: allocs={} extra_peak={}",
        after_large.allocs, after_large.extra_peak
    );
    assert!(
        after_large.allocs >= 1,
        "the buffer should have been dropped after the large frame"
    );

    let (frame, reused) = read_one(&mut frames);
    assert_eq!(frame, ping(2));
    eprintln!(
        "ping after that: allocs={} extra_peak={}",
        reused.allocs, reused.extra_peak
    );
    assert_eq!(reused.allocs, 0, "the small buffer should be reused");
    assert_eq!(large.reallocs, 1, "a large frame should grow exactly once");
    assert_eq!(
        large.allocs, 3,
        "expected the first chunk, one exact reserve, and the decoded string"
    );

    // One test function: this binary's global allocator is process-wide,
    // so a second `#[test]` would be counted inside this window.
    payloads_4097_to_8192_do_not_reallocate_each_frame();
    header_errors_and_overlong_encode_stay_small();
}

fn disconnect(payload: usize) -> Frame {
    Frame {
        key_epoch: None,
        body: FrameBody::Disconnect {
            code: 1,
            reason: "x".repeat(payload - 2),
        },
    }
}

fn payloads_4097_to_8192_do_not_reallocate_each_frame() {
    for payload in [4097usize, 6000, 8192] {
        let frame = disconnect(payload);
        let once = encode(&frame, None).unwrap();
        let mut bytes = Vec::new();
        for _ in 0..4 {
            bytes.extend_from_slice(&once);
        }
        let mut frames = FrameReader::new(std::io::Cursor::new(bytes));
        let (first, warm) = read_one(&mut frames);
        assert_eq!(first, frame);
        eprintln!(
            "medium {payload} warmup: allocs={} reallocs={} extra_peak={}",
            warm.allocs, warm.reallocs, warm.extra_peak
        );
        for i in 1..4 {
            let (got, sample) = read_one(&mut frames);
            assert_eq!(got, frame);
            eprintln!(
                "medium {payload} frame {i}: allocs={} reallocs={} extra_peak={}",
                sample.allocs, sample.reallocs, sample.extra_peak
            );
            assert_eq!(
                sample.reallocs, 0,
                "payload {payload} frame {i} reallocated the buffer"
            );
        }
    }
}

fn header_errors_and_overlong_encode_stay_small() {
    let too_long = vec![0x01u8, 0x01, 0, 0, 0x00, 0x01, 0x00, 0x00];
    let mut frames = FrameReader::new(std::io::Cursor::new(too_long));
    let (_, header) = sample(|| drive(frames.read_frame()));
    assert!(
        header.extra_peak < 4096,
        "header error peak {}",
        header.extra_peak
    );

    let huge = disconnect(70_000);
    let (_, encoded) = sample(|| encode(&huge, None));
    assert!(
        encoded.extra_peak < 4096,
        "encode peak {}",
        encoded.extra_peak
    );
}
