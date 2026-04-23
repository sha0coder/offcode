use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex, atomic::{AtomicUsize, Ordering}};

pub fn tts_cmd(lang: &str) -> String {
    if cfg!(target_os = "macos") {
        let voice = match lang {
            "es" => "Mónica",
            "fr" => "Amelie",
            "de" => "Anna",
            "it" => "Alice",
            "pt" => "Joana",
            _    => "Ava",
        };
        format!("say -v {voice}")
    } else {
        let voice = match lang {
            "es" => "es+f3",
            "fr" => "fr+f3",
            "de" => "de+f3",
            "it" => "it+f3",
            "pt" => "pt+f3",
            _    => "en+f3",
        };
        format!("espeak-ng -v {voice} -s 150")
    }
}

enum Msg {
    Speak { text: String, lang: String },
    Stop,
}

// Persistent speaker thread — sentences are played sequentially so they don't overlap.
pub struct Speaker {
    tx:      mpsc::SyncSender<Msg>,
    active:  Arc<AtomicUsize>,
    _cur_pid: Arc<Mutex<Option<u32>>>,
}

impl Speaker {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel::<Msg>(32);
        let active  = Arc::new(AtomicUsize::new(0));
        let cur_pid = Arc::new(Mutex::new(None::<u32>));
        let active2  = active.clone();
        let cur_pid2 = cur_pid.clone();

        std::thread::spawn(move || {
            for msg in &rx {
                match msg {
                    Msg::Stop => {
                        // Kill the currently playing process
                        if let Some(pid) = cur_pid2.lock().unwrap().take() {
                            let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).status();
                        }
                        // Drain queued sentences
                        while rx.try_recv().is_ok() {}
                        active2.store(0, Ordering::Relaxed);
                    }
                    Msg::Speak { text, lang } => {
                        let cmd = tts_cmd(&lang);
                        if let Ok(mut child) = Command::new("sh")
                            .arg("-c").arg(&cmd)
                            .stdin(Stdio::piped())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()
                        {
                            *cur_pid2.lock().unwrap() = Some(child.id());
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(text.as_bytes());
                            }
                            let _ = child.wait();
                            *cur_pid2.lock().unwrap() = None;
                        }
                        active2.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        });
        Self { tx, active, _cur_pid: cur_pid }
    }

    pub fn say(&self, text: &str, lang: &str) {
        let text = text.trim().to_string();
        if text.is_empty() { return; }
        self.active.fetch_add(1, Ordering::Relaxed);
        if self.tx.try_send(Msg::Speak { text, lang: lang.to_string() }).is_err() {
            self.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn stop(&self) {
        let _ = self.tx.try_send(Msg::Stop);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed) > 0
    }
}

// Extract completed sentences from the buffer (ends with . ! ? or blank line).
// Returns them and leaves any incomplete tail in the buffer.
pub fn drain_sentences(buf: &mut String) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut start = 0;
    let bytes = buf.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i] as char;

        // Blank line boundary
        if c == '\n' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            let chunk = buf[start..i].trim().to_string();
            if !chunk.is_empty() { sentences.push(chunk); }
            start = i + 2;
            i = start;
            continue;
        }

        // Sentence-ending punctuation followed by space/newline/end
        if matches!(c, '.' | '!' | '?') {
            let next = bytes.get(i + 1).copied().unwrap_or(b' ') as char;
            if next.is_whitespace() || i + 1 == bytes.len() {
                let chunk = buf[start..=i].trim().to_string();
                if !chunk.is_empty() { sentences.push(chunk); }
                start = i + 1;
            }
        }

        i += 1;
    }

    *buf = buf[start..].to_string();
    sentences
}

// Clean LLM response text for speech (strip code blocks, URLs, markdown).
pub fn clean_for_speech(text: &str) -> String {
    let mut out = String::new();
    let mut in_code_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") { in_code_block = !in_code_block; continue; }
        if in_code_block { continue; }
        if looks_like_noise(trimmed) { continue; }
        let stripped = strip_inline_md(trimmed);
        if stripped.trim().is_empty() { continue; }
        out.push_str(&stripped);
        out.push(' ');
    }
    out.trim().to_string()
}

fn looks_like_noise(line: &str) -> bool {
    if line.is_empty() { return false; }
    if line.contains("http://") || line.contains("https://") { return true; }
    if line.starts_with('/') || line.starts_with("./") || line.starts_with("../") { return true; }
    let alpha = line.chars().filter(|c| c.is_alphabetic()).count();
    let total = line.chars().count();
    total > 4 && alpha * 100 / total < 30
}

fn strip_inline_md(s: &str) -> String {
    let s = s.trim_start_matches('#').trim();
    let s = s.replace("**", "").replace('*', "").replace("__", "").replace('_', " ");
    let mut out = String::new();
    let mut in_code = false;
    for c in s.chars() {
        if c == '`' { in_code = !in_code; continue; }
        if !in_code { out.push(c); }
    }
    out
}
