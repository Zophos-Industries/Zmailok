//! Reads the mail server's log: a file (only the new part since last time) or the postfix journal.
//! Counts postfix delivery outcomes. No network access.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

/// On the very first run, only the last part of a big log file is read.
const FIRST_RUN_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Default, Clone, Copy, Debug)]
pub struct Tally {
    pub sent: u64,
    pub bounced: u64,
    pub deferred: u64,
    /// Lines that mention a complaint or feedback report. Postfix does not write these by default.
    pub complaints: u64,
}

impl Tally {
    /// Final outcomes only: a deferred message is still being retried, so it is not counted yet.
    pub fn total(&self) -> u64 {
        self.sent + self.bounced
    }
}

pub fn tally<'a>(lines: impl Iterator<Item = &'a str>) -> Tally {
    let mut t = Tally::default();
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.contains("feedback") || lower.contains("complaint") {
            t.complaints += 1;
        }
        if line.contains("status=sent") {
            t.sent += 1;
        } else if line.contains("status=bounced") {
            t.bounced += 1;
        } else if line.contains("status=deferred") {
            t.deferred += 1;
        }
    }
    t
}

/// New complete lines of a file since `offset`, and the offset to continue from next time.
/// A file that became shorter (log rotation) is read from the start again.
pub fn read_file(path: &Path, offset: Option<u64>) -> io::Result<(Vec<String>, u64)> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let start = match offset {
        Some(o) if o <= len => o,
        Some(_) => 0,
        None => len.saturating_sub(FIRST_RUN_BYTES),
    };
    f.seek(SeekFrom::Start(start))?;
    let mut buf = String::new();
    BufReader::new(f).read_to_string(&mut buf)?;
    // Only complete lines: a line still being written is picked up next time.
    let complete = buf.rfind('\n').map_or(0, |i| i + 1);
    let mut lines: Vec<String> = buf[..complete].lines().map(String::from).collect();
    if start > 0 && offset.is_none() && !lines.is_empty() {
        lines.remove(0); // the first line of a partial read may be cut in the middle
    }
    Ok((lines, start + complete as u64))
}

/// Journal lines of postfix since a unix time. Needs permission to read the journal.
pub fn read_journal(since_unix: i64) -> io::Result<Vec<String>> {
    let out = Command::new("journalctl")
        .args(["-u", "postfix", "--no-pager", "-o", "cat", "--since", &format!("@{since_unix}")])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_string()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_postfix_outcomes() {
        let log = [
            "Oct 12 10:00:01 mx postfix/smtp[1]: A1: to=<a@x.com>, status=sent (250 OK)",
            "Oct 12 10:00:02 mx postfix/smtp[1]: A2: to=<b@x.com>, status=bounced (550 no such user)",
            "Oct 12 10:00:03 mx postfix/smtp[1]: A3: to=<c@x.com>, status=deferred (421 try later)",
            "Oct 12 10:00:04 mx postfix/smtp[1]: A4: to=<d@x.com>, status=sent (250 OK)",
            "Oct 12 10:00:05 mx some line with a Feedback Loop report",
        ];
        let t = tally(log.iter().copied());
        assert_eq!((t.sent, t.bounced, t.deferred, t.complaints), (2, 1, 1, 1));
        assert_eq!(t.total(), 3, "deferred is not a final outcome");
    }

    #[test]
    fn reads_only_new_complete_lines_and_survives_rotation() {
        let path = std::env::temp_dir().join(format!("zm-agent-log-{}.log", std::process::id()));
        std::fs::write(&path, "one status=sent\ntwo status=sent\nhalf").unwrap();
        let (lines, off) = read_file(&path, Some(0)).unwrap();
        assert_eq!(lines, ["one status=sent", "two status=sent"], "the unfinished line waits");
        std::fs::write(&path, "one status=sent\ntwo status=sent\nhalf more status=bounced\n").unwrap();
        let (lines, off2) = read_file(&path, Some(off)).unwrap();
        assert_eq!(lines, ["half more status=bounced"]);
        std::fs::write(&path, "fresh status=sent\n").unwrap(); // rotated: shorter than before
        let (lines, _) = read_file(&path, Some(off2)).unwrap();
        assert_eq!(lines, ["fresh status=sent"]);
        std::fs::remove_file(path).ok();
    }
}
