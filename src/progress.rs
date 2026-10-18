//! Transient CLI progress; independent of compilation and report rendering.
use std::{
    io::{self, IsTerminal, Write},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use sbpf_eye::compiler_diff::render::OutputFormat;

pub struct Progress {
    worker: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
}

impl Progress {
    pub fn start(format: OutputFormat) -> Self {
        let enabled = enabled(
            format,
            io::stdout().is_terminal(),
            io::stderr().is_terminal(),
            std::env::var("TERM").ok().as_deref(),
        );
        let worker = enabled.then(|| {
            let (stop, receiver) = mpsc::channel();
            let handle = thread::spawn(move || {
                let started = Instant::now();
                let frames = ['|', '/', '-', '\\'];
                let mut frame = 0;
                let mut width = 0;
                loop {
                    let line = format!(
                        "{} Compiler diff... {}s",
                        frames[frame % frames.len()],
                        started.elapsed().as_secs()
                    );
                    width = width.max(line.len());
                    // Lock only while writing so errors can still reach stderr.
                    let mut stderr = io::stderr().lock();
                    let _ = write!(stderr, "\r{line:width$}");
                    let _ = stderr.flush();
                    drop(stderr);
                    if receiver.recv_timeout(Duration::from_millis(120))
                        != Err(mpsc::RecvTimeoutError::Timeout)
                    {
                        break;
                    }
                    frame += 1;
                }
                let mut stderr = io::stderr().lock();
                let _ = write!(stderr, "\r{:width$}\r", "");
                let _ = stderr.flush();
            });
            (stop, handle)
        });
        Self { worker }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some((stop, handle)) = self.worker.take() {
            let _ = stop.send(());
            let _ = handle.join();
        }
    }
}

fn enabled(format: OutputFormat, stdout_tty: bool, stderr_tty: bool, term: Option<&str>) -> bool {
    format == OutputFormat::Terminal
        && stdout_tty
        && stderr_tty
        && term.is_some_and(|term| !term.is_empty() && term != "dumb")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_interactive_terminal_reports_animate() {
        assert!(enabled(OutputFormat::Terminal, true, true, Some("xterm")));
        for format in [OutputFormat::Json, OutputFormat::Markdown] {
            assert!(!enabled(format, true, true, Some("xterm")));
        }
        for (stdout, stderr) in [(false, true), (true, false), (false, false)] {
            assert!(!enabled(
                OutputFormat::Terminal,
                stdout,
                stderr,
                Some("xterm")
            ));
        }
        for term in [None, Some(""), Some("dumb")] {
            assert!(!enabled(OutputFormat::Terminal, true, true, term));
        }
    }
}
