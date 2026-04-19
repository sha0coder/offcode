use std::sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}};

use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
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

// ── worker ↔ app events ───────────────────────────────────────────────────────

#[derive(Debug)]
enum WorkerMsg {
    ThinkToken(String),
    Token(String),
    ToolBegin { name: String, args: Value },
    ToolEnd { result_preview: String },
    AddMessage(Message),
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

// ── app ───────────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Mode {
    Input,
    Generating,
}

pub struct App {
    cfg: Config,
    client: Client,
    history: Vec<Message>,
    entries: Vec<Entry>,
    input: String,
    cursor: usize,
    scroll: u16,
    auto_scroll: bool,
    mode: Mode,
    queued: Option<String>, // prompt typed while generating, sent when done
    cancel: Arc<AtomicBool>,
    rx: mpsc::Receiver<WorkerMsg>,
    _tx: mpsc::Sender<WorkerMsg>,
    pub should_quit: bool,
    tick: u64,
}

impl App {
    pub fn new(cfg: Config, client: Client) -> Self {
        let (tx, rx) = mpsc::channel();
        let history = vec![Message {
            role: "system".to_string(),
            content: super::build_system_prompt(&cfg),
            tool_calls: None,
        }];
        Self {
            cfg,
            client,
            history,
            entries: vec![],
            input: String::new(),
            cursor: 0,
            scroll: 0,
            auto_scroll: true,
            mode: Mode::Input,
            rx,
            _tx: tx,
            should_quit: false,
            tick: 0,
            queued: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    // ── key handling ──────────────────────────────────────────────────────────

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Global quit shortcuts
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }
        if key.code == KeyCode::Esc {
            match self.mode {
                Mode::Generating => {
                    // Cancel current generation, stay in app
                    self.cancel.store(true, Ordering::Relaxed);
                    self.queued = None;
                }
                Mode::Input => self.should_quit = true,
            }
            return;
        }

        // Allow typing and scrolling at all times
        self.handle_input_key(key);
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                self.submit();
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.input.remove(self.cursor);
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.input.len() {
                    self.input.remove(self.cursor);
                }
            }
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
            }
            KeyCode::Right => {
                if self.cursor < self.input.len() {
                    self.cursor += 1;
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.input.len(),
            KeyCode::Up => {
                self.auto_scroll = false;
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::Down => {
                self.scroll += 1;
                // auto_scroll resumes when user scrolls to bottom (handled in render)
            }
            KeyCode::PageUp => {
                self.auto_scroll = false;
                self.scroll = self.scroll.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.scroll += 10;
            }
            KeyCode::Char(c) => {
                self.input.insert(self.cursor, c);
                self.cursor += 1;
            }
            _ => {}
        }
    }

    // ── submission ────────────────────────────────────────────────────────────

    fn submit(&mut self) {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.input.clear();
        self.cursor = 0;

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
                 /tools  list tools\n\
                 /model  list available models\n\
                 /model <name>  change model\n\
                 /think  toggle thinking display\n\
                 /exit or Ctrl+C  quit".into(),
            )),
            "/clear" | "/reset" => {
                self.entries.clear();
                self.history.truncate(1);
                self.entries.push(Entry::info("History cleared.".into()));
            }
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
            "/exit" | "/quit" => self.should_quit = true,
            "/model" | "/models" => self.list_models_entry(),
            s if s.starts_with("/model ") => {
                let model = s[7..].trim().to_string();
                self.cfg.model = model.clone();
                self.entries.push(Entry::info(format!("Model → {model}")));
            }
            _ => self.entries.push(Entry::error(format!("Unknown command. /help for list."))),
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

    // ── worker events ─────────────────────────────────────────────────────────

    pub fn poll_worker(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.handle_worker_msg(msg);
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
                    _ => self.entries.push(Entry::assistant(t)),
                }
                self.auto_scroll = true;
            }
            WorkerMsg::ToolBegin { name, args } => {
                let arg_str = fmt_args(&args);
                self.entries.push(Entry::tool(name, arg_str));
                self.auto_scroll = true;
            }
            WorkerMsg::ToolEnd { result_preview } => {
                if let Some(e) = self.entries.last_mut() {
                    if e.role == Role::Tool {
                        if !result_preview.is_empty() {
                            e.text.push_str(&format!("\n→ {result_preview}"));
                        }
                    }
                }
            }
            WorkerMsg::AddMessage(msg) => {
                self.history.push(msg);
            }
            WorkerMsg::Done => {
                self.mode = Mode::Input;
                if let Some(queued) = self.queued.take() {
                    self.input = queued;
                    self.cursor = self.input.len();
                    self.submit();
                }
            }
            WorkerMsg::Error(e) => {
                self.mode = Mode::Input;
                self.queued = None; // drop queued on error
                self.entries.push(Entry::error(e));
                // Remove user message that caused error
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
        let cx = chunks[2].x + 1 + 2 + self.cursor as u16;
        let cy = chunks[2].y + 1;
        if cx < chunks[2].x + chunks[2].width.saturating_sub(1) {
            f.set_cursor_position((cx, cy));
        }
    }

    fn render_title(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        const SPINNER: &[&str] = &["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"];
        let generating_indicator = if self.mode == Mode::Generating {
            let frame = (self.tick / 3) as usize % SPINNER.len();
            Span::styled(
                format!(" {} thinking…", SPINNER[frame]),
                Style::default().fg(Color::Yellow),
            )
        } else {
            Span::raw("")
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
            Paragraph::new(title_line).style(Style::default().bg(Color::Black)),
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
        let (border_style, label_color) = (Style::default().fg(Color::Cyan), Color::Green);

        let content = Line::from(vec![
            Span::styled("> ", Style::default().fg(label_color).add_modifier(Modifier::BOLD)),
            Span::raw(self.input.clone()),
        ]);

        f.render_widget(
            Paragraph::new(content)
                .block(Block::default().borders(Borders::ALL).border_style(border_style)),
            area,
        );
    }

    fn render_hints(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let hints = Line::from(vec![
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::styled(" send  ", Style::default().fg(Color::DarkGray)),
            Span::styled("↑↓", Style::default().fg(Color::Cyan)),
            Span::styled(" scroll  ", Style::default().fg(Color::DarkGray)),
            Span::styled("/help", Style::default().fg(Color::Cyan)),
            Span::styled(" commands  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Ctrl+C", Style::default().fg(Color::Cyan)),
            Span::styled(" quit", Style::default().fg(Color::DarkGray)),
        ]);
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
            Ok((content, Some(calls))) => {
                // Add assistant message with tool calls to history
                let asst_msg = Message {
                    role: "assistant".to_string(),
                    content: content.clone(),
                    tool_calls: Some(calls.clone()),
                };
                history.push(asst_msg.clone());
                let _ = tx.send(WorkerMsg::AddMessage(asst_msg));

                for call in &calls {
                    let name = &call.function.name;
                    let args = &call.function.arguments;

                    let _ = tx.send(WorkerMsg::ToolBegin {
                        name: name.clone(),
                        args: args.clone(),
                    });

                    let result_str = tools::execute(name, args);

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

// ── public entry point ────────────────────────────────────────────────────────

pub fn run(cfg: Config, client: Client) -> std::io::Result<()> {
    // Set up panic handler to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = ratatui::restore();
        original_hook(info);
    }));

    let mut terminal = ratatui::init();
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
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }

        if app.should_quit {
            break;
        }
    }

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
