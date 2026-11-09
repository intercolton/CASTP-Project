//! Append-only JSONL log with size-based rotation.
//!
//! `events.jsonl` is the live file; when the next line would push it past
//! `max_bytes` it is renamed to `events.jsonl.1` (older files shift to `.2`,
//! `.3`, …) and the oldest beyond `keep_files` is deleted. Every line is
//! flushed as it is written so a crash loses at most the line in flight.

use crate::event::ProbeEvent;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum JsonlError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid event: {0}")]
    Invalid(String),
}

pub struct JsonlWriter {
    path: PathBuf,
    max_bytes: u64,
    keep_files: usize,
    file: File,
    size: u64,
}

impl JsonlWriter {
    /// Opens (creating directories as needed) `path` for appending.
    /// `max_bytes` must be at least 1 KiB; `keep_files` rotated files are kept.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64, keep_files: usize) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(JsonlWriter {
            path,
            max_bytes: max_bytes.max(1024),
            keep_files,
            file,
            size,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Validates and appends one event.
    pub fn write(&mut self, event: &ProbeEvent) -> Result<(), JsonlError> {
        event.validate().map_err(JsonlError::Invalid)?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        if self.size > 0 && self.size + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.size += line.len() as u64;
        Ok(())
    }

    fn rotated(&self, n: usize) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    fn rotate(&mut self) -> io::Result<()> {
        if self.keep_files == 0 {
            self.file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?;
            self.size = 0;
            return Ok(());
        }
        let oldest = self.rotated(self.keep_files);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }
        for n in (1..self.keep_files).rev() {
            let from = self.rotated(n);
            if from.exists() {
                fs::rename(&from, self.rotated(n + 1))?;
            }
        }
        fs::rename(&self.path, self.rotated(1))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

/// One line that failed to parse, kept so the analyzer can report it.
#[derive(Debug)]
pub struct BadLine {
    pub line_no: usize,
    pub error: String,
}

/// Reads every event from a JSONL file. Blank lines are skipped; malformed
/// lines are returned separately instead of aborting the whole read.
pub fn read_events(path: &Path) -> io::Result<(Vec<ProbeEvent>, Vec<BadLine>)> {
    let reader = BufReader::new(File::open(path)?);
    let mut events = Vec::new();
    let mut bad = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ProbeEvent>(&line) {
            Ok(e) => match e.validate() {
                Ok(()) => events.push(e),
                Err(err) => bad.push(BadLine {
                    line_no: i + 1,
                    error: err,
                }),
            },
            Err(err) => bad.push(BadLine {
                line_no: i + 1,
                error: err.to_string(),
            }),
        }
    }
    Ok((events, bad))
}

/// The live file followed by its rotated siblings that exist, oldest first.
pub fn rotated_set(path: &Path, keep_files: usize) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = (1..=keep_files)
        .rev()
        .map(|n| {
            let mut s = path.as_os_str().to_owned();
            s.push(format!(".{n}"));
            PathBuf::from(s)
        })
        .filter(|p| p.exists())
        .collect();
    if path.exists() {
        out.push(path.to_path_buf());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{TestType, Transport};
    use crate::ErrorCode;

    fn ev(i: usize) -> ProbeEvent {
        ProbeEvent::new(
            format!("t{i}"),
            "c",
            "n",
            "g",
            TestType::TcpConnect,
            Transport::Tcp,
        )
        .succeed()
    }

    #[test]
    fn writes_valid_lines_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/events.jsonl");
        let mut w = JsonlWriter::open(&p, 1 << 20, 3).unwrap();
        for i in 0..5 {
            w.write(&ev(i)).unwrap();
        }
        let (events, bad) = read_events(&p).unwrap();
        assert_eq!(events.len(), 5);
        assert!(bad.is_empty());
        assert_eq!(events[4].test_id, "t4");
    }

    #[test]
    fn rejects_invalid_event() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::open(dir.path().join("e.jsonl"), 1 << 20, 1).unwrap();
        let mut e = ev(0);
        e.success = false; // no error_code
        assert!(matches!(w.write(&e), Err(JsonlError::Invalid(_))));
        let e = ev(1).fail(ErrorCode::TcpTimeout, "x");
        w.write(&e).unwrap();
    }

    #[test]
    fn rotation_bounds_disk_usage() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("events.jsonl");
        let mut w = JsonlWriter::open(&p, 2048, 2).unwrap();
        for i in 0..200 {
            w.write(&ev(i)).unwrap();
        }
        let set = rotated_set(&p, 2);
        assert_eq!(set.len(), 3, "live file plus two rotated");
        assert!(!dir.path().join("events.jsonl.3").exists());
        let total: u64 = set.iter().map(|f| fs::metadata(f).unwrap().len()).sum();
        assert!(total <= 3 * 2048, "total {total}");
        // Newest event is in the live file, and nothing is torn.
        let (events, bad) = read_events(&p).unwrap();
        assert!(bad.is_empty());
        assert_eq!(events.last().unwrap().test_id, "t199");
    }

    #[test]
    fn reader_reports_bad_lines_without_failing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        let good = serde_json::to_string(&ev(0)).unwrap();
        fs::write(&p, format!("{good}\nnot json\n\n{good}\n")).unwrap();
        let (events, bad) = read_events(&p).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].line_no, 2);
    }

    #[test]
    fn reopening_continues_size_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        {
            let mut w = JsonlWriter::open(&p, 4096, 1).unwrap();
            w.write(&ev(0)).unwrap();
        }
        let w = JsonlWriter::open(&p, 4096, 1).unwrap();
        assert!(w.size > 0);
    }
}
