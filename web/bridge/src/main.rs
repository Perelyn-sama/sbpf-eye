use std::{env, fs, io::Write};
fn main() {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let path = env::args().nth(1).ok_or("Expected ELF filename argument")?;
        let bytes = fs::read(&path)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("8 MiB maximum binary size".into());
        }
        let stream = env::args().any(|a| a == "--stream");
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        let report = sbpf_eye_web_bridge::inspect_with_checkpoint(&bytes, &path, |report| {
            if stream {
                // If the client disappeared, the final write reports the I/O failure.
                let _ = serde_json::to_writer(&mut out, report);
                let _ = out.write_all(b"\n");
                let _ = out.flush();
            }
        });
        serde_json::to_writer(&mut out, &report)?;
        out.flush()?;
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
