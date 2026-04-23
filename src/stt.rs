use std::process::{Child, Command, Stdio};

const REC_FILE: &str = "/tmp/offcode_rec.wav";

pub fn start_recording(rec_cmd: &str) -> Result<Child, String> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("{rec_cmd} {REC_FILE}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start recording: {e}"))
}

// Stop recording gracefully (SIGTERM so sox/arecord can finalize the WAV header)
// then transcribe with whisper and return the text.
pub fn stop_and_transcribe(mut child: Child, stt_cmd: &str) -> Result<String, String> {
    // SIGINT so ffmpeg/sox can write the WAV trailer cleanly before exiting
    let pid = child.id();
    let _ = Command::new("kill").args(["-INT", &pid.to_string()]).status();
    let _ = child.wait();

    // Brief pause so the file is fully flushed to disk
    std::thread::sleep(std::time::Duration::from_millis(300));

    if stt_cmd.is_empty() {
        let _ = std::fs::remove_file(REC_FILE);
        return Err("stt_cmd not configured. Set it in config.toml, e.g.:\nstt_cmd = \"whisper-cli -m ~/models/ggml-base.bin -nt -np -f\"".to_string());
    }

    let file_size = std::fs::metadata(REC_FILE).map(|m| m.len()).unwrap_or(0);
    if file_size < 1000 {
        let _ = std::fs::remove_file(REC_FILE);
        return Err(format!("Audio file too small ({file_size} bytes) — microphone not recording?"));
    }

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("{stt_cmd} {REC_FILE}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Transcription failed: {e}"))?;

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    let _ = std::fs::remove_file(REC_FILE);

    if text.is_empty() {
        let detail = if stderr.is_empty() {
            "whisper returned no output".to_string()
        } else {
            stderr.lines().last().unwrap_or(&stderr).to_string()
        };
        Err(format!("Transcription empty: {detail}"))
    } else {
        Ok(text)
    }
}

// Run in a background thread, send result via callback
pub fn transcribe_async(
    child: Child,
    stt_cmd: String,
    tx: std::sync::mpsc::Sender<Result<String, String>>,
) {
    std::thread::spawn(move || {
        let _ = tx.send(stop_and_transcribe(child, &stt_cmd));
    });
}
