use std::sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}};

use ratatui::{
    crossterm::{
        event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
        execute,
    },
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use serde_json::Value;

use crate::config::Config;
use crate::ollama::{ChatRequest, Client, Message, Options};
use crate::tools;
use crate::ConfirmAction;

// ── line editor (input, cursor, history, completion) ─────────────────────────

enum KeyOutcome { Submit, Complete, Handled, Unhandled }

enum CompleteOutcome { None, Replaced, Extended, Ambiguous(Vec<String>) }

struct LineEdit {
    input: String,
    cursor: usize,
    history: Vec<String>,
    history_idx: Option<usize>,
    draft: String,
}

impl LineEdit {
    fn new() -> Self {
        Self { input: String::new(), cursor: 0, history: Vec::new(), history_idx: None, draft: String::new() }
    }

    fn set(&mut self, s: String) {
        self.input = s;
        self.cursor = self.input.len();
        self.history_idx = None;
        self.draft.clear();
    }

    fn take(&mut self) -> Option<String> {
        let text = self.input.trim().to_string();
        if text.is_empty() { return None; }
        self.input.clear();
        self.cursor = 0;
        self.history_idx = None;
        self.draft.clear();
        if self.history.last().map(String::as_str) != Some(text.as_str()) {
            self.history.push(text.clone());
        }
        Some(text)
    }

    fn handle_key(&mut self, key: KeyEvent) -> KeyOutcome {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('p') => { self.history_prev(); return KeyOutcome::Handled; }
                KeyCode::Char('n') => { self.history_next(); return KeyOutcome::Handled; }
                KeyCode::Char('a') => { self.cursor = 0; return KeyOutcome::Handled; }
                KeyCode::Char('e') => { self.cursor = self.input.len(); return KeyOutcome::Handled; }
                KeyCode::Char('b') => { self.move_left(); return KeyOutcome::Handled; }
                KeyCode::Char('f') => { self.move_right(); return KeyOutcome::Handled; }
                KeyCode::Char('w') => { self.kill_word_back(); return KeyOutcome::Handled; }
                KeyCode::Char('u') => { self.kill_to_start(); return KeyOutcome::Handled; }
                KeyCode::Char('k') => { self.kill_to_end(); return KeyOutcome::Handled; }
                _ => {}
            }
        }
        match key.code {
            KeyCode::Tab => KeyOutcome::Complete,
            KeyCode::Enter => KeyOutcome::Submit,
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let prev = self.input[..self.cursor]
                        .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                    self.input.remove(prev);
                    self.cursor = prev;
                }
                KeyOutcome::Handled
            }
            KeyCode::Delete => {
                if self.cursor < self.input.len() { self.input.remove(self.cursor); }
                KeyOutcome::Handled
            }
            KeyCode::Left => { self.move_left(); KeyOutcome::Handled }
            KeyCode::Right => { self.move_right(); KeyOutcome::Handled }
            KeyCode::Home => { self.cursor = 0; KeyOutcome::Handled }
            KeyCode::End => { self.cursor = self.input.len(); KeyOutcome::Handled }
            KeyCode::Char(c) => {
                self.input.insert(self.cursor, c);
                self.cursor += c.len_utf8();
                KeyOutcome::Handled
            }
            _ => KeyOutcome::Unhandled,
        }
    }

    fn complete(&mut self, start: usize, candidates: &[String]) -> CompleteOutcome {
        if self.cursor != self.input.len() || start > self.input.len() {
            return CompleteOutcome::None;
        }
        let token = &self.input[start..];
        match candidates.len() {
            0 => CompleteOutcome::None,
            1 => {
                let head = self.input[..start].to_string();
                self.input = format!("{}{} ", head, candidates[0]);
                self.cursor = self.input.len();
                CompleteOutcome::Replaced
            }
            _ => {
                let lcp = lcp_of(candidates);
                if lcp.len() > token.len() {
                    let head = self.input[..start].to_string();
                    self.input = format!("{head}{lcp}");
                    self.cursor = self.input.len();
                    CompleteOutcome::Extended
                } else {
                    CompleteOutcome::Ambiguous(candidates.to_vec())
                }
            }
        }
    }

    fn insert_str(&mut self, s: &str) {
        self.input.insert_str(self.cursor, s);
        self.cursor += s.len();
        self.history_idx = None;
    }

    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.input[..self.cursor]
                .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
        }
    }

    fn move_right(&mut self) {
        if self.cursor < self.input.len() {
            let c = self.input[self.cursor..].chars().next().unwrap();
            self.cursor += c.len_utf8();
        }
    }

    fn kill_word_back(&mut self) {
        let head = &self.input[..self.cursor];
        let boundaries: Vec<(usize, char)> = head.char_indices().collect();
        let mut n = boundaries.len();
        while n > 0 && boundaries[n - 1].1.is_whitespace() { n -= 1; }
        while n > 0 && !boundaries[n - 1].1.is_whitespace() { n -= 1; }
        let start = boundaries.get(n).map(|(i, _)| *i).unwrap_or(self.cursor);
        self.input.replace_range(start..self.cursor, "");
        self.cursor = start;
    }

    fn kill_to_start(&mut self) {
        self.input.replace_range(..self.cursor, "");
        self.cursor = 0;
    }

    fn kill_to_end(&mut self) {
        self.input.truncate(self.cursor);
    }

    fn history_prev(&mut self) {
        if self.history.is_empty() { return; }
        let new_idx = match self.history_idx {
            None => { self.draft = self.input.clone(); self.history.len() - 1 }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_idx = Some(new_idx);
        self.input = self.history[new_idx].clone();
        self.cursor = self.input.len();
    }

    fn history_next(&mut self) {
        match self.history_idx {
            None => {}
            Some(i) if i + 1 >= self.history.len() => {
                self.history_idx = None;
                self.input = std::mem::take(&mut self.draft);
                self.cursor = self.input.len();
            }
            Some(i) => {
                let next = i + 1;
                self.history_idx = Some(next);
                self.input = self.history[next].clone();
                self.cursor = self.input.len();
            }
        }
    }
}

fn lcp_of(strs: &[String]) -> String {
    let mut iter = strs.iter();
    let mut prefix = match iter.next() {
        Some(s) => s.clone(),
        None => return String::new(),
    };
    for s in iter {
        let common: String = prefix.chars().zip(s.chars()).take_while(|(a, b)| a == b).map(|(a, _)| a).collect();
        prefix = common;
        if prefix.is_empty() { break; }
    }
    prefix
}

// ── worker ↔ app events ───────────────────────────────────────────────────────

enum WorkerMsg {
    ThinkToken(String),
    Token(String),
    ToolBegin { name: String, args: Value },
    ToolEnd { result_preview: String },
    AddMessage(Message),
    ConfirmRequest {
        name: String,
        args: Value,
        reply: mpsc::SyncSender<ConfirmAction>,
    },
    CompactReady(String),
    Done,
    Error(String),
}

// ── display entries ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
enum Role {
    User,
    Assistant,
    Think,
    Tool,
    Error,
    Info,
}

#[derive(Clone, Debug)]
struct Entry {
    role: Role,
    label: String,
    text: String,
}

impl Entry {
    fn user(text: String) -> Self {
        Self { role: Role::User, label: "you".into(), text }
    }
    fn assistant(text: String) -> Self {
        Self { role: Role::Assistant, label: "offcode".into(), text }
    }
    fn think(text: String) -> Self {
        Self { role: Role::Think, label: "thinking".into(), text }
    }
    fn tool(name: String, args: String) -> Self {
        Self { role: Role::Tool, label: name, text: args }
    }
    fn error(text: String) -> Self {
        Self { role: Role::Error, label: "error".into(), text }
    }
    fn info(text: String) -> Self {
        Self { role: Role::Info, label: "info".into(), text }
    }
}

// ── slash commands (used by /help and Tab completion) ────────────────────────

const COMMANDS: &[&str] = &[
    "/help", "/clear", "/reset", "/compact", "/tools", "/think", "/yolo",
    "/model", "/models", "/voice", "/lang", "/exit", "/quit",
];

// ── app ───────────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Mode {
    Input,
    Generating,
    Recording,
    Transcribing,
}

struct PendingConfirm {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    args: Value,
    reply: mpsc::SyncSender<ConfirmAction>,
}

pub struct App {
    cfg: Config,
    client: Client,
    history: Vec<Message>,
    entries: Vec<Entry>,
    editor: LineEdit,
    scroll: u16,
    auto_scroll: bool,
    mode: Mode,
    queued: Option<String>,
    cancel: Arc<AtomicBool>,
    rx: mpsc::Receiver<WorkerMsg>,
    _tx: mpsc::Sender<WorkerMsg>,
    pub should_quit: bool,
    tick: u64,
    model_names_cache: Option<Vec<String>>,
    pending_confirm: Option<PendingConfirm>,
    rec_child: Option<std::process::Child>,
    stt_rx: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    speaker: crate::tts::Speaker,
    tts_buf: String,
}

fn entries_from_history(history: &[Message]) -> Vec<Entry> {
    let mut out = Vec::new();
    for m in history.iter().skip(1) {
        match m.role.as_str() {
            "user" => out.push(Entry::user(m.content.clone())),
            "assistant" => {
                if !m.content.trim().is_empty() {
                    out.push(Entry::assistant(m.content.clone()));
                }
                if let Some(calls) = &m.tool_calls {
                    for c in calls {
                        out.push(Entry::tool(
                            c.function.name.clone(),
                            c.function.arguments.to_string(),
                        ));
                    }
                }
            }
            "tool" => {
                let preview: String = m.content.lines().take(4).collect::<Vec<_>>().join("\n");
                out.push(Entry::info(preview));
            }
            _ => {}
        }
    }
    if !out.is_empty() {
        out.insert(0, Entry::info(format!(
            "Restored {} messages from previous session.", history.len() - 1
        )));
    }
    out
}

impl App {
    pub fn new(cfg: Config, client: Client) -> Self {
        let (tx, rx) = mpsc::channel();
        let system_msg = Message {
            role: "system".to_string(),
            content: super::build_system_prompt(&cfg),
            tool_calls: None,
        };
        let history = if cfg.no_ctx {
            vec![system_msg]
        } else {
            crate::context::load(&system_msg)
        };
        let entries = entries_from_history(&history);
        Self {
            cfg,
            client,
            history,
            entries,
            editor: LineEdit::new(),
            scroll: 0,
            auto_scroll: true,
            mode: Mode::Input,
            rx,
            _tx: tx,
            should_quit: false,
            tick: 0,
            queued: None,
            cancel: Arc::new(AtomicBool::new(false)),
            model_names_cache: None,
            pending_confirm: None,
            rec_child: None,
            stt_rx: None,
            speaker: crate::tts::Speaker::new(),
            tts_buf: String::new(),
        }
    }

    fn do_complete(&mut self) {
        let input = self.editor.input.clone();
        if !input.starts_with('/') {
            return;
        }
        let (start, candidates): (usize, Vec<String>) = if let Some(sp) = input.find(' ') {
            let head = &input[..sp];
            let tail = &input[sp + 1..];
            if head == "/model" || head == "/models" {
                let names = self.ensure_model_names();
                let cands = names.iter().filter(|n| n.starts_with(tail)).cloned().collect();
                (sp + 1, cands)
            } else {
                return;
            }
        } else {
            let cands = COMMANDS
                .iter()
                .filter(|c| c.starts_with(input.as_str()))
                .map(|s| s.to_string())
                .collect();
            (0, cands)
        };
        if let CompleteOutcome::Ambiguous(cs) = self.editor.complete(start, &candidates) {
            self.entries.push(Entry::info(cs.join("  ")));
            self.auto_scroll = true;
        }
    }

    fn ensure_model_names(&mut self) -> Vec<String> {
        if self.model_names_cache.is_none() {
            let names = self
                .client
                .list_models()
                .map(|ms| ms.into_iter().map(|m| m.name).collect())
                .unwrap_or_default();
            self.model_names_cache = Some(names);
        }
        self.model_names_cache.clone().unwrap_or_default()
    }

    // ── key handling ──────────────────────────────────────────────────────────

    pub fn handle_paste(&mut self, text: &str) {
        // Replace newlines with spaces so the single-line editor stays coherent
        // but the whole paste lands as one prompt instead of N submits.
        let flat = text.replace('\n', " ").replace('\r', "");
        self.editor.insert_str(&flat);
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Global quit shortcuts
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }

        // Ctrl+R — toggle recording (STT)
        if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.toggle_recording();
            return;
        }

        // Ctrl+S — stop speech
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.speaker.stop();
            self.tts_buf.clear();
            return;
        }

        if key.code == KeyCode::Esc {
            if self.pending_confirm.is_some() {
                self.deliver_confirm(ConfirmAction::Reject(String::new()));
                return;
            }
            // If TTS is speaking, Esc stops it (second Esc quits)
            if self.cfg.tts && self.speaker.is_active() {
                self.speaker.stop();
                self.tts_buf.clear();
                return;
            }
            match self.mode {
                Mode::Generating => {
                    self.cancel.store(true, Ordering::Relaxed);
                    self.queued = None;
                }
                Mode::Input => self.should_quit = true,
                Mode::Recording => { self.toggle_recording(); }
                Mode::Transcribing => {}
            }
            return;
        }

        // Allow typing and scrolling at all times
        self.handle_input_key(key);
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        // Scroll keys belong to the surrounding view, not the line editor.
        match key.code {
            KeyCode::Up => {
                self.auto_scroll = false;
                self.scroll = self.scroll.saturating_sub(1);
                return;
            }
            KeyCode::Down => {
                self.scroll += 1;
                return;
            }
            KeyCode::PageUp => {
                self.auto_scroll = false;
                self.scroll = self.scroll.saturating_sub(10);
                return;
            }
            KeyCode::PageDown => {
                self.scroll += 10;
                return;
            }
            _ => {}
        }
        match self.editor.handle_key(key) {
            KeyOutcome::Submit => self.submit(),
            KeyOutcome::Complete => self.do_complete(),
            KeyOutcome::Handled | KeyOutcome::Unhandled => {}
        }
    }

    // ── submission ────────────────────────────────────────────────────────────

    fn submit(&mut self) {
        // Stop any ongoing speech and clear TTS buffer
        if self.cfg.tts {
            self.speaker.stop();
            self.tts_buf.clear();
        }
        // Confirmation mode intercepts everything except slash commands.
        if self.pending_confirm.is_some() {
            let text = self.editor.take().unwrap_or_default();
            if text.starts_with('/') {
                // Allow slash commands (e.g. /yolo) during confirmation. Re-queue
                // the editor so the user can retry, then run the command.
                self.handle_command(&text);
                return;
            }
            let action = parse_confirm_input(&text);
            match action {
                Ok(a) => self.deliver_confirm(a),
                Err(msg) => {
                    self.entries.push(Entry::error(msg));
                    self.auto_scroll = true;
                }
            }
            return;
        }

        let text = match self.editor.take() {
            Some(t) => t,
            None => return,
        };

        // Commands run immediately regardless of mode
        if text.starts_with('/') {
            self.handle_command(&text);
            return;
        }

        // Queue if already generating
        if self.mode == Mode::Generating {
            self.queued = Some(text);
            self.entries.push(Entry::info("⏎ queued — will send when done".into()));
            return;
        }

        self.auto_scroll = true;
        self.mode = Mode::Generating;

        self.entries.push(Entry::user(text.clone()));
        self.history.push(Message {
            role: "user".to_string(),
            content: text,
            tool_calls: None,
        });

        // Fresh cancel flag for this generation
        self.cancel = Arc::new(AtomicBool::new(false));

        let (tx, rx) = mpsc::channel();
        self.rx = rx;
        self._tx = tx.clone();

        let cfg = self.cfg.clone();
        let client = self.client.clone();
        let history = self.history.clone();
        let show_thinking = cfg.show_thinking;
        let cancel = self.cancel.clone();

        std::thread::spawn(move || {
            run_worker(cfg, client, history, show_thinking, cancel, tx);
        });
    }

    fn handle_command(&mut self, cmd: &str) {
        match cmd {
            "/help" => self.entries.push(Entry::info(
                "/help  show help\n\
                 /clear  clear history\n\
                 /compact  summarize history to shrink context\n\
                 /tools  list tools\n\
                 /model  list available models\n\
                 /model <name>  change model\n\
                 /think  toggle thinking display\n\
                 /yolo  toggle yolo mode (auto-approve tools)\n\
                 /voice  toggle text-to-speech\n\
                 /lang <code>  set language for TTS (en, es, fr, de, it, pt)\n\
                 /exit or Ctrl+C  quit".into(),
            )),
            "/clear" | "/reset" => {
                self.entries.clear();
                self.history.truncate(1);
                self.entries.push(Entry::info("History cleared.".into()));
            }
            "/compact" => self.start_compact(),
            "/tools" => {
                let names: Vec<String> = tools::definitions()
                    .iter()
                    .filter_map(|t| {
                        t.get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(|n| n.as_str())
                            .map(|s| format!("  • {s}"))
                    })
                    .collect();
                self.entries.push(Entry::info(names.join("\n")));
            }
            "/think" => {
                self.cfg.show_thinking = !self.cfg.show_thinking;
                let state = if self.cfg.show_thinking { "on" } else { "off" };
                self.entries.push(Entry::info(format!("Thinking display: {state}")));
            }
            "/yolo" => {
                self.cfg.yolo = !self.cfg.yolo;
                let state = if self.cfg.yolo {
                    "on (tools run without prompting)"
                } else {
                    "off (prompt before each tool call)"
                };
                self.entries.push(Entry::info(format!("Yolo mode: {state}")));
            }
            "/voice" => {
                self.cfg.tts = !self.cfg.tts;
                let state = if self.cfg.tts {
                    format!("on  ({})", crate::tts::tts_cmd(&self.cfg.tts_lang))
                } else {
                    "off".to_string()
                };
                self.entries.push(Entry::info(format!("Voice: {state}")));
            }
            s if s.starts_with("/lang ") => {
                let lang = s[6..].trim().to_string();
                self.cfg.tts_lang = lang.clone();
                let cmd = crate::tts::tts_cmd(&lang);
                self.entries.push(Entry::info(format!("Language → {lang}  (voice: {cmd})")));
            }
            "/lang" => {
                self.entries.push(Entry::info(format!("Current language: {}  (voice: {})",
                    self.cfg.tts_lang, crate::tts::tts_cmd(&self.cfg.tts_lang))));
            }
            "/exit" | "/quit" => self.should_quit = true,
            "/model" | "/models" => self.list_models_entry(),
            s if s.starts_with("/model ") => {
                let model = s[7..].trim().to_string();
                self.cfg.model = model.clone();
                self.entries.push(Entry::info(format!("Model → {model}")));
            }
            _ => self.entries.push(Entry::error("Unknown command. /help for list.".to_string())),
        }
    }

    fn list_models_entry(&mut self) {
        let models = match self.client.list_models() {
            Ok(m) => m,
            Err(e) => {
                self.entries.push(Entry::error(format!("list models: {e}")));
                return;
            }
        };
        if models.is_empty() {
            self.entries.push(Entry::info(
                "No models installed. Try `ollama pull <model>`.".into(),
            ));
            return;
        }
        let caps: Vec<crate::ollama::ModelCaps> = models
            .iter()
            .map(|m| self.client.model_capabilities(&m.name))
            .collect();
        let rows = crate::ollama::format_model_listing(&models, &caps, &self.cfg.model);
        let mut text = String::from("");
        for (line, is_sel) in &rows {
            if *is_sel {
                text.push_str(&format!("{line}  ← current\n"));
            } else {
                text.push_str(&format!("{line}\n"));
            }
        }
        text.push_str(&format!("selected: {}", self.cfg.model));
        self.entries.push(Entry::info(text));
    }

    // ── /compact ──────────────────────────────────────────────────────────────

    fn start_compact(&mut self) {
        if self.mode == Mode::Generating {
            self.entries.push(Entry::info(
                "busy generating — try /compact after it finishes.".into(),
            ));
            return;
        }
        if self.history.len() <= 1 {
            self.entries.push(Entry::info("nothing to compact.".into()));
            return;
        }

        self.auto_scroll = true;
        self.mode = Mode::Generating;
        self.entries.push(Entry::info("Compacting conversation…".into()));

        self.cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        self.rx = rx;
        self._tx = tx.clone();

        let cfg = self.cfg.clone();
        let client = self.client.clone();
        let history = self.history.clone();
        let show_thinking = self.cfg.show_thinking;
        let cancel = self.cancel.clone();

        std::thread::spawn(move || {
            run_compact_worker(cfg, client, history, show_thinking, cancel, tx);
        });
    }

    // ── tool confirmation ─────────────────────────────────────────────────────

    fn deliver_confirm(&mut self, action: ConfirmAction) {
        let Some(p) = self.pending_confirm.take() else { return; };
        let label = match &action {
            ConfirmAction::Accept => "accepted".to_string(),
            ConfirmAction::Reject(r) if r.is_empty() => "rejected".to_string(),
            ConfirmAction::Reject(r) => format!("rejected: {r}"),
            ConfirmAction::Modify(_) => "args modified".to_string(),
            ConfirmAction::Comment(t) => format!("accepted + comment: {t}"),
        };
        self.entries.push(Entry::info(format!("→ {label}")));
        self.auto_scroll = true;
        if p.reply.send(action).is_err() {
            self.entries
                .push(Entry::error("worker gone — cannot deliver confirmation".into()));
        }
    }

    // ── worker events ─────────────────────────────────────────────────────────

    pub fn poll_worker(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.handle_worker_msg(msg);
        }
        // Poll STT transcription result
        if let Some(ref rx) = self.stt_rx {
            if let Ok(result) = rx.try_recv() {
                self.stt_rx = None;
                self.mode = Mode::Input;
                match result {
                    Ok(text) => {
                        self.editor.set(text);
                        self.entries.push(Entry::info("Transcription ready — press Enter to send or edit first.".into()));
                    }
                    Err(e) => self.entries.push(Entry::error(e)),
                }
            }
        }
    }

    fn toggle_recording(&mut self) {
        match self.mode {
            Mode::Recording => {
                // Stop recording and start transcription
                if let Some(child) = self.rec_child.take() {
                    self.mode = Mode::Transcribing;
                    self.entries.push(Entry::info("Transcribing…".into()));
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.stt_rx = Some(rx);
                    crate::stt::transcribe_async(child, self.cfg.stt_cmd.clone(), tx);
                }
            }
            Mode::Input => {
                match crate::stt::start_recording(&self.cfg.rec_cmd) {
                    Ok(child) => {
                        self.rec_child = Some(child);
                        self.mode = Mode::Recording;
                        self.entries.push(Entry::info("Recording… press Ctrl+R or Esc to stop.".into()));
                        self.auto_scroll = true;
                    }
                    Err(e) => self.entries.push(Entry::error(e)),
                }
            }
            _ => {}
        }
    }

    fn handle_worker_msg(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::ThinkToken(t) => {
                if self.cfg.show_thinking {
                    match self.entries.last_mut() {
                        Some(e) if e.role == Role::Think => e.text.push_str(&t),
                        _ => self.entries.push(Entry::think(t)),
                    }
                    self.auto_scroll = true;
                }
            }
            WorkerMsg::Token(t) => {
                match self.entries.last_mut() {
                    Some(e) if e.role == Role::Assistant => e.text.push_str(&t),
                    _ => self.entries.push(Entry::assistant(t.clone())),
                }
                self.auto_scroll = true;
                // Stream TTS sentence by sentence
                if self.cfg.tts {
                    self.tts_buf.push_str(&t);
                    for sentence in crate::tts::drain_sentences(&mut self.tts_buf) {
                        let clean = crate::tts::clean_for_speech(&sentence);
                        self.speaker.say(&clean, &self.cfg.tts_lang);
                    }
                }
            }
            WorkerMsg::ToolBegin { name, args } => {
                let arg_str = fmt_args(&args);
                self.entries.push(Entry::tool(name, arg_str));
                self.auto_scroll = true;
            }
            WorkerMsg::ToolEnd { result_preview } => {
                if let Some(e) = self.entries.last_mut() {
                    if e.role == Role::Tool && !result_preview.is_empty() {
                        e.text.push_str(&format!("\n→ {result_preview}"));
                    }
                }
            }
            WorkerMsg::AddMessage(msg) => {
                self.history.push(msg);
            }
            WorkerMsg::ConfirmRequest { name, args, reply } => {
                let arg_str = fmt_args(&args);
                self.entries.push(Entry::info(format!(
                    "confirm tool: {name}  ({arg_str})\n[Enter]/y accept  n reject  c <note> comment  m <json> modify  Esc reject"
                )));
                self.pending_confirm = Some(PendingConfirm { name, args, reply });
                self.auto_scroll = true;
            }
            WorkerMsg::CompactReady(summary) => {
                if summary.trim().is_empty() {
                    self.entries.push(Entry::error(
                        "compact produced empty summary — history unchanged.".into(),
                    ));
                } else {
                    let system = self.history.first().cloned().unwrap_or(Message {
                        role: "system".to_string(),
                        content: String::new(),
                        tool_calls: None,
                    });
                    self.history = vec![
                        system,
                        Message {
                            role: "user".to_string(),
                            content: "Summary of the prior conversation (context was compacted):"
                                .to_string(),
                            tool_calls: None,
                        },
                        Message {
                            role: "assistant".to_string(),
                            content: summary,
                            tool_calls: None,
                        },
                    ];
                    self.entries.clear();
                    self.entries
                        .push(Entry::info("Context compacted.".into()));
                }
                if !self.cfg.no_ctx { crate::context::save(&self.history); }
                self.mode = Mode::Input;
                if let Some(queued) = self.queued.take() {
                    self.editor.set(queued);
                    self.submit();
                }
            }
            WorkerMsg::Done => {
                if !self.cfg.no_ctx { crate::context::save(&self.history); }
                // Flush any remaining tail (sentence without ending punctuation)
                if self.cfg.tts && !self.tts_buf.is_empty() {
                    let tail = crate::tts::clean_for_speech(&self.tts_buf.clone());
                    self.speaker.say(&tail, &self.cfg.tts_lang);
                    self.tts_buf.clear();
                }
                self.mode = Mode::Input;
                if let Some(queued) = self.queued.take() {
                    self.editor.set(queued);
                    self.submit();
                }
            }
            WorkerMsg::Error(e) => {
                self.mode = Mode::Input;
                self.queued = None;
                self.entries.push(Entry::error(e));
                if let Some(last) = self.history.last() {
                    if last.role == "user" {
                        self.history.pop();
                    }
                }
            }
        }
    }

    // ── render ────────────────────────────────────────────────────────────────

    pub fn render(&mut self, f: &mut Frame) {
        let area = f.area();

        // Layout: title(1) + messages(fill) + input(3) + hints(1)
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

        self.render_title(f, chunks[0]);
        self.render_messages(f, chunks[1]);
        self.render_input(f, chunks[2]);
        self.render_hints(f, chunks[3]);

        // Cursor always visible in input box
        let cx = chunks[2].x + 1 + 2 + self.editor.cursor as u16;
        let cy = chunks[2].y + 1;
        if cx < chunks[2].x + chunks[2].width.saturating_sub(1) {
            f.set_cursor_position((cx, cy));
        }
    }

    fn render_title(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        const SPINNER: &[&str] = &["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"];
        let generating_indicator = match self.mode {
            Mode::Generating => {
                let frame = (self.tick / 3) as usize % SPINNER.len();
                Span::styled(format!(" {} thinking…", SPINNER[frame]), Style::default().fg(Color::Yellow))
            }
            Mode::Recording => {
                let dot = if (self.tick / 6) % 2 == 0 { "●" } else { "○" };
                Span::styled(format!(" {dot} recording…"), Style::default().fg(Color::Red))
            }
            Mode::Transcribing => Span::styled(" ◌ transcribing…", Style::default().fg(Color::Magenta)),
            Mode::Input => Span::raw(""),
        };

        let title_line = Line::from(vec![
            Span::styled(
                " offcode",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  model:{}", self.cfg.model),
                Style::default().fg(Color::DarkGray),
            ),
            generating_indicator,
        ]);

        f.render_widget(
            Paragraph::new(title_line).style(Style::default()),
            area,
        );
    }

    fn render_messages(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let width = area.width.saturating_sub(2) as usize; // padding
        let height = area.height as usize;

        let mut lines: Vec<Line<'static>> = vec![];

        // Mascot when empty
        if self.entries.is_empty() {
            lines.extend(mascot_lines());
        }

        for entry in &self.entries {
            lines.extend(entry_to_lines(entry, width));
            lines.push(Line::raw(""));
        }

        let total = lines.len();

        // Auto-scroll: pin to bottom
        if self.auto_scroll {
            self.scroll = total.saturating_sub(height) as u16;
        }

        // Clamp manual scroll
        let max_scroll = total.saturating_sub(height) as u16;
        if self.scroll >= max_scroll {
            self.scroll = max_scroll;
            // Re-enable auto-scroll when user scrolled back to bottom
            self.auto_scroll = true;
        }

        f.render_widget(
            Paragraph::new(lines).scroll((self.scroll, 0)),
            area,
        );
    }

    fn render_input(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let (border_style, label_color) = if self.pending_confirm.is_some() {
            (Style::default().fg(Color::Yellow), Color::Yellow)
        } else {
            (Style::default().fg(Color::Cyan), Color::Green)
        };

        let prompt = if self.pending_confirm.is_some() { "? " } else { "> " };

        let content = Line::from(vec![
            Span::styled(prompt, Style::default().fg(label_color).add_modifier(Modifier::BOLD)),
            Span::raw(self.editor.input.clone()),
        ]);

        f.render_widget(
            Paragraph::new(content)
                .block(Block::default().borders(Borders::ALL).border_style(border_style)),
            area,
        );
    }

    fn render_hints(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let hints = if self.pending_confirm.is_some() {
            Line::from(vec![
                Span::styled("Enter/y", Style::default().fg(Color::Yellow)),
                Span::styled(" accept  ", Style::default().fg(Color::DarkGray)),
                Span::styled("n", Style::default().fg(Color::Yellow)),
                Span::styled(" reject  ", Style::default().fg(Color::DarkGray)),
                Span::styled("c <note>", Style::default().fg(Color::Yellow)),
                Span::styled(" comment  ", Style::default().fg(Color::DarkGray)),
                Span::styled("m <json>", Style::default().fg(Color::Yellow)),
                Span::styled(" modify  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::styled(" reject", Style::default().fg(Color::DarkGray)),
            ])
        } else {
            Line::from(vec![
                Span::styled("Enter", Style::default().fg(Color::Cyan)),
                Span::styled(" send  ", Style::default().fg(Color::DarkGray)),
                Span::styled("↑↓", Style::default().fg(Color::Cyan)),
                Span::styled(" scroll  ", Style::default().fg(Color::DarkGray)),
                Span::styled("^P/^N", Style::default().fg(Color::Cyan)),
                Span::styled(" history  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::styled(" complete  ", Style::default().fg(Color::DarkGray)),
                Span::styled("/help", Style::default().fg(Color::Cyan)),
                Span::styled(" commands  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Ctrl+C", Style::default().fg(Color::Cyan)),
                Span::styled(" quit", Style::default().fg(Color::DarkGray)),
            ])
        };
        f.render_widget(Paragraph::new(hints), area);
    }
}

// ── entry → ratatui lines ─────────────────────────────────────────────────────

fn entry_to_lines(entry: &Entry, width: usize) -> Vec<Line<'static>> {
    let mut result = vec![];

    match entry.role {
        Role::User => {
            result.push(Line::from(vec![Span::styled(
                "  ▷ you",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )]));
            for l in word_wrap(&entry.text, width.saturating_sub(4)) {
                result.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(l, Style::default().fg(Color::White)),
                ]));
            }
        }
        Role::Assistant => {
            result.push(Line::from(vec![Span::styled(
                "  ◆ offcode",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]));
            for l in word_wrap(&entry.text, width.saturating_sub(4)) {
                result.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(l, Style::default().fg(Color::White)),
                ]));
            }
        }
        Role::Think => {
            result.push(Line::from(vec![Span::styled(
                "  ◇ thinking",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )]));
            for l in word_wrap(&entry.text, width.saturating_sub(4)) {
                result.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(l, Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
        Role::Tool => {
            result.push(Line::from(vec![
                Span::styled(
                    "  ⚙ ",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    entry.label.clone(),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ]));
            for l in word_wrap(&entry.text, width.saturating_sub(4)) {
                result.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(l, Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
        Role::Error => {
            result.push(Line::from(vec![Span::styled(
                "  ✗ error",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )]));
            for l in word_wrap(&entry.text, width.saturating_sub(4)) {
                result.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(l, Style::default().fg(Color::Red)),
                ]));
            }
        }
        Role::Info => {
            for l in word_wrap(&entry.text, width.saturating_sub(4)) {
                result.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(l, Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
    }

    result
}

// ── mascot ────────────────────────────────────────────────────────────────────

fn mascot_lines() -> Vec<Line<'static>> {
    // ╭──────────╮ = 12 chars (10 inside)
    // eyes:   ◉    ◉   = 2+1+4+1+2 = 10 ✓
    // smile:   ╰──╯    = 3+4+3     = 10 ✓
    let fr = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let ey = Style::default().fg(Color::White).add_modifier(Modifier::BOLD);
    let sm = Style::default().fg(Color::Green).add_modifier(Modifier::BOLD);
    let d  = Style::default().fg(Color::DarkGray);
    let br = Style::default().fg(Color::White).add_modifier(Modifier::BOLD);
    let ac = Style::default().fg(Color::Cyan);

    vec![
        Line::raw(""),
        //      ╭──────────╮
        Line::from(vec![Span::styled("      ╭──────────╮", fr)]),
        //      │  ◉    ◉  │   offcode
        Line::from(vec![
            Span::styled("      │  ", fr),
            Span::styled("◉", ey),
            Span::raw("    "),
            Span::styled("◉", ey),
            Span::styled("  │   ", fr),
            Span::styled("offcode", br),
        ]),
        //      │   ╰──╯   │   offline coding assistant
        Line::from(vec![
            Span::styled("      │   ", fr),
            Span::styled("╰──╯", sm),
            Span::styled("   │   ", fr),
            Span::styled("offline coding assistant", d),
        ]),
        //      ╰──────────╯   powered by ollama · type a prompt
        Line::from(vec![
            Span::styled("      ╰──────────╯   ", fr),
            Span::styled("powered by ollama · type a prompt to begin", d),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("      ", ac),
        ]),
    ]
}

// ── worker thread ─────────────────────────────────────────────────────────────

fn run_worker(
    cfg: Config,
    client: Client,
    mut history: Vec<Message>,
    show_thinking: bool,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<WorkerMsg>,
) {
    let tool_defs = tools::definitions();
    let max_iters = cfg.max_tool_iters;
    let mut iters = 0;

    loop {
        if iters >= max_iters {
            let _ = tx.send(WorkerMsg::Error(format!(
                "Max tool iterations ({max_iters}) reached."
            )));
            return;
        }
        iters += 1;

        let request = ChatRequest {
            model: cfg.model.clone(),
            messages: history.clone(),
            stream: true,
            tools: tool_defs.clone(),
            options: Options {
                temperature: cfg.temperature,
                num_ctx: cfg.num_ctx,
            },
        };

        let tx2 = tx.clone();
        let result = client.chat_stream(&request, show_thinking, cancel.clone(), move |token, is_think| {
            let msg = if is_think {
                WorkerMsg::ThinkToken(token.to_string())
            } else {
                WorkerMsg::Token(token.to_string())
            };
            let _ = tx2.send(msg);
        });

        match result {
            Ok((content, Some(mut calls))) => {
                // Resolve confirmations up-front so the assistant message we
                // store carries the final (possibly modified) arguments.
                let mut actions: Vec<ConfirmAction> = Vec::with_capacity(calls.len());
                for call in calls.iter_mut() {
                    let action = if cfg.is_auto_approved(&call.function.name) {
                        ConfirmAction::Accept
                    } else {
                        let (reply_tx, reply_rx) = mpsc::sync_channel::<ConfirmAction>(1);
                        if tx
                            .send(WorkerMsg::ConfirmRequest {
                                name: call.function.name.clone(),
                                args: call.function.arguments.clone(),
                                reply: reply_tx,
                            })
                            .is_err()
                        {
                            return;
                        }
                        match reply_rx.recv() {
                            Ok(a) => a,
                            Err(_) => ConfirmAction::Reject("ui closed".into()),
                        }
                    };
                    if let ConfirmAction::Modify(ref new_args) = action {
                        call.function.arguments = new_args.clone();
                    }
                    actions.push(action);
                }

                // Add assistant message with (final) tool calls to history
                let asst_msg = Message {
                    role: "assistant".to_string(),
                    content: content.clone(),
                    tool_calls: Some(calls.clone()),
                };
                history.push(asst_msg.clone());
                let _ = tx.send(WorkerMsg::AddMessage(asst_msg));

                for (call, action) in calls.iter().zip(actions) {
                    let name = &call.function.name;
                    let args = &call.function.arguments;

                    let _ = tx.send(WorkerMsg::ToolBegin {
                        name: name.clone(),
                        args: args.clone(),
                    });

                    let (result_str, extra_user) = match action {
                        ConfirmAction::Reject(reason) => {
                            let msg = if reason.is_empty() {
                                "Tool call rejected by user.".to_string()
                            } else {
                                format!("Tool call rejected by user: {reason}")
                            };
                            (msg, None)
                        }
                        ConfirmAction::Comment(text) => {
                            (tools::execute(name, args), Some(text))
                        }
                        ConfirmAction::Accept | ConfirmAction::Modify(_) => {
                            (tools::execute(name, args), None)
                        }
                    };

                    let preview: String = result_str
                        .lines()
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let _ = tx.send(WorkerMsg::ToolEnd {
                        result_preview: preview,
                    });

                    let tool_msg = Message {
                        role: "tool".to_string(),
                        content: result_str,
                        tool_calls: None,
                    };
                    history.push(tool_msg.clone());
                    let _ = tx.send(WorkerMsg::AddMessage(tool_msg));

                    if let Some(text) = extra_user {
                        let user_msg = Message {
                            role: "user".to_string(),
                            content: text,
                            tool_calls: None,
                        };
                        history.push(user_msg.clone());
                        let _ = tx.send(WorkerMsg::AddMessage(user_msg));
                    }
                }
                // Loop to get model's response after tool calls
            }

            Ok((content, None)) => {
                if !content.is_empty() {
                    let asst_msg = Message {
                        role: "assistant".to_string(),
                        content,
                        tool_calls: None,
                    };
                    history.push(asst_msg.clone());
                    let _ = tx.send(WorkerMsg::AddMessage(asst_msg));
                }
                let _ = tx.send(WorkerMsg::Done);
                return;
            }

            Err(e) if e == "__cancelled__" => {
                let _ = tx.send(WorkerMsg::Done);
                return;
            }
            Err(e) => {
                let _ = tx.send(WorkerMsg::Error(e));
                return;
            }
        }
    }
}

fn run_compact_worker(
    cfg: Config,
    client: Client,
    history: Vec<Message>,
    show_thinking: bool,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<WorkerMsg>,
) {
    let mut msgs = history;
    msgs.push(Message {
        role: "user".to_string(),
        content: cfg.compact_prompt.clone(),
        tool_calls: None,
    });

    let request = ChatRequest {
        model: cfg.model.clone(),
        messages: msgs,
        stream: true,
        tools: vec![],
        options: Options {
            temperature: cfg.temperature,
            num_ctx: cfg.num_ctx,
        },
    };

    let tx2 = tx.clone();
    let result = client.chat_stream(&request, show_thinking, cancel, move |token, is_think| {
        let msg = if is_think {
            WorkerMsg::ThinkToken(token.to_string())
        } else {
            WorkerMsg::Token(token.to_string())
        };
        let _ = tx2.send(msg);
    });

    match result {
        Ok((content, _)) => {
            let _ = tx.send(WorkerMsg::CompactReady(content));
        }
        Err(e) if e == "__cancelled__" => {
            let _ = tx.send(WorkerMsg::Done);
        }
        Err(e) => {
            let _ = tx.send(WorkerMsg::Error(e));
        }
    }
}

// ── public entry point ────────────────────────────────────────────────────────

pub fn run(cfg: Config, client: Client) -> std::io::Result<()> {
    // Set up panic handler to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        original_hook(info);
    }));

    let mut terminal = ratatui::init();
    execute!(std::io::stdout(), EnableBracketedPaste)?;
    let mut app = App::new(cfg, client);

    loop {
        // Increment tick for animations
        app.tick = app.tick.wrapping_add(1);

        // Draw
        terminal.draw(|f| app.render(f))?;

        // Drain worker events
        app.poll_worker();

        // Poll keyboard with 80ms timeout (gives ~12fps animation)
        if event::poll(std::time::Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    app.handle_key(key);
                }
                Event::Paste(text) => {
                    app.handle_paste(&text);
                }
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }
    }

    execute!(std::io::stdout(), DisableBracketedPaste)?;
    ratatui::restore();
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn word_wrap(text: &str, width: usize) -> Vec<String> {
    if width < 4 {
        return vec![text.to_string()];
    }
    let mut out = vec![];
    for raw_line in text.lines() {
        if raw_line.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            if current.is_empty() {
                if word.len() > width {
                    // Hard-break very long words
                    let mut remaining = word;
                    while remaining.len() > width {
                        out.push(remaining[..width].to_string());
                        remaining = &remaining[width..];
                    }
                    current = remaining.to_string();
                } else {
                    current = word.to_string();
                }
            } else if current.len() + 1 + word.len() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                out.push(current);
                current = word.to_string();
            }
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Parse a confirmation input line into a ConfirmAction.
/// Returns Err with a user-facing message on invalid input.
fn parse_confirm_input(line: &str) -> Result<ConfirmAction, String> {
    let t = line.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("y") || t.eq_ignore_ascii_case("yes") {
        return Ok(ConfirmAction::Accept);
    }
    if t.eq_ignore_ascii_case("n") || t.eq_ignore_ascii_case("no") {
        return Ok(ConfirmAction::Reject(String::new()));
    }
    let (head, rest) = match t.split_once(char::is_whitespace) {
        Some((h, r)) => (h, r.trim()),
        None => (t, ""),
    };
    match head {
        "r" | "reject" => Ok(ConfirmAction::Reject(rest.to_string())),
        "c" | "comment" => {
            if rest.is_empty() {
                Err("comment requires text (e.g. `c please also lint`)".into())
            } else {
                Ok(ConfirmAction::Comment(rest.to_string()))
            }
        }
        "m" | "modify" => {
            if rest.is_empty() {
                Err("modify requires JSON args (e.g. `m {\"path\":\"foo\"}`)".into())
            } else {
                serde_json::from_str::<Value>(rest)
                    .map(ConfirmAction::Modify)
                    .map_err(|e| format!("invalid JSON: {e}"))
            }
        }
        _ => Err("unknown confirmation input; use y / n / c <note> / m <json>".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_empty_is_accept() {
        assert!(matches!(parse_confirm_input(""), Ok(ConfirmAction::Accept)));
        assert!(matches!(parse_confirm_input("  "), Ok(ConfirmAction::Accept)));
        assert!(matches!(parse_confirm_input("y"), Ok(ConfirmAction::Accept)));
        assert!(matches!(parse_confirm_input("YES"), Ok(ConfirmAction::Accept)));
    }

    #[test]
    fn confirm_n_is_reject() {
        assert!(matches!(parse_confirm_input("n"), Ok(ConfirmAction::Reject(r)) if r.is_empty()));
        match parse_confirm_input("r unsafe path") {
            Ok(ConfirmAction::Reject(r)) => assert_eq!(r, "unsafe path"),
            _ => panic!("expected reject with reason"),
        }
    }

    #[test]
    fn confirm_comment_requires_text() {
        assert!(parse_confirm_input("c").is_err());
        match parse_confirm_input("c also lint afterwards") {
            Ok(ConfirmAction::Comment(t)) => assert_eq!(t, "also lint afterwards"),
            _ => panic!("expected comment"),
        }
    }

    #[test]
    fn confirm_modify_requires_valid_json() {
        assert!(parse_confirm_input("m").is_err());
        assert!(parse_confirm_input("m {not json}").is_err());
        match parse_confirm_input(r#"m {"path":"x"}"#) {
            Ok(ConfirmAction::Modify(v)) => {
                assert_eq!(v.get("path").and_then(|x| x.as_str()), Some("x"));
            }
            _ => panic!("expected modify"),
        }
    }

    #[test]
    fn confirm_unknown_is_error() {
        assert!(parse_confirm_input("garbage").is_err());
    }
}

fn fmt_args(args: &Value) -> String {
    match args.as_object() {
        Some(obj) => obj
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    Value::String(s) => {
                        let first: String = s.lines().next().unwrap_or("").chars().take(50).collect();
                        if s.lines().count() > 1 {
                            format!("{first}…")
                        } else {
                            first
                        }
                    }
                    other => other.to_string(),
                };
                format!("{k}={val}")
            })
            .collect::<Vec<_>>()
            .join("  "),
        None => args.to_string(),
    }
}
