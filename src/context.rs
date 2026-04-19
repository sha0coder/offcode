use std::path::PathBuf;

use crate::ollama::Message;

pub fn ctx_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".offcode.ctx")
}

/// Load persisted history and prepend the system message.
pub fn load(system_msg: &Message) -> Vec<Message> {
    let mut messages = vec![system_msg.clone()];
    let path = ctx_path();
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(history) = serde_json::from_str::<Vec<Message>>(&data) {
                if !history.is_empty() {
                    messages.extend(history);
                }
            }
        }
    }
    messages
}

/// Persist history to disk (skips the system message at index 0).
pub fn save(messages: &[Message]) {
    if messages.len() <= 1 {
        let _ = std::fs::remove_file(ctx_path());
        return;
    }
    if let Ok(data) = serde_json::to_string(&messages[1..]) {
        let _ = std::fs::write(ctx_path(), data);
    }
}

/// Delete the context file.
pub fn clear() {
    let _ = std::fs::remove_file(ctx_path());
}

/// Drop oldest messages (index 1+) until estimated token count fits within
/// 85% of num_ctx. Always keeps at least the last KEEP_TAIL messages so the
/// model has recent context even if the session is very long.
pub fn trim(messages: &mut Vec<Message>, num_ctx: u32) {
    const KEEP_TAIL: usize = 6;
    let limit = (num_ctx as usize * 85) / 100;

    loop {
        if messages.len() <= KEEP_TAIL + 1 {
            break;
        }
        let estimated: usize = messages.iter().map(|m| m.content.len() / 4).sum();
        if estimated <= limit {
            break;
        }
        messages.remove(1);
    }
}
