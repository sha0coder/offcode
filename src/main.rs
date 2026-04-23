use std::io::{self, BufRead, Write};

mod config;
mod context;
mod diff;
mod ollama;
mod tools;
mod stt;
mod tts;
mod tui;
mod ui;

use config::Config;
use ollama::{ChatRequest, Client, Message, Options};

pub enum ConfirmAction {
    Accept,
    Reject(String),
    Modify(serde_json::Value),
    Comment(String),
}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    let mut cfg = Config::load();

    let mut i = 1usize;
    let mut prompt_words: Vec<String> = vec![];
    let mut no_tui = false;

    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-v" | "--version" => {
                println!("offcode {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--config" => {
                let path = Config::config_path();
                println!("Config file: {}", path.display());
                println!();
                println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
                return;
            }
            "-m" | "--model" => {
                i += 1;
                if let Some(m) = raw_args.get(i) {
                    cfg.model = m.clone();
                }
            }
            "--url" => {
                i += 1;
                if let Some(u) = raw_args.get(i) {
                    cfg.ollama_url = u.clone();
                }
            }
            "--think" => cfg.show_thinking = true,
            "--no-tui" => no_tui = true,
            "--no-ctx" => cfg.no_ctx = true,
            _ => {
                prompt_words = raw_args[i..].to_vec();
                break;
            }
        }
        i += 1;
    }

    let client = Client::new(&cfg.ollama_url);
    if !client.is_healthy() {
        eprintln!(
            "{}{}Error:{} Cannot connect to Ollama at {}",
            ui::BOLD,
            ui::RED,
            ui::RESET,
            cfg.ollama_url
        );
        eprintln!(
            "{}Tip:{}   Run `ollama serve` or install Ollama.",
            ui::YELLOW,
            ui::RESET
        );
        std::process::exit(1);
    }

    // Single-shot mode (no TUI, just print to stdout)
    if !prompt_words.is_empty() {
        ui::print_mascot(&cfg.model);
        let system_msg = Message {
            role: "system".to_string(),
            content: build_system_prompt(&cfg),
            tool_calls: None,
        };
        let mut messages = if cfg.no_ctx {
            vec![system_msg]
        } else {
            context::load(&system_msg)
        };
        let prompt = prompt_words.join(" ");
        run_turn(&cfg, &client, &mut messages, &prompt);
        if !cfg.no_ctx { context::save(&messages); }
        return;
    }

    // Interactive: use TUI by default; fall back to plain REPL if not a real terminal
    use std::io::IsTerminal;
    let use_tui = !no_tui && std::io::stdout().is_terminal();

    if use_tui {
        if let Err(e) = tui::run(cfg, client) {
            eprintln!("TUI error: {e}");
            std::process::exit(1);
        }
    } else {
        run_repl(cfg, client);
    }
}

// ── plain REPL (--no-tui) ─────────────────────────────────────────────────────

fn run_repl(cfg: Config, client: Client) {
    let mut cfg = cfg;
    ui::print_mascot(&cfg.model);
    println!(
        "{}Connected {} model: {}{}{}",
        ui::DIM,
        ui::RESET,
        ui::CYAN,
        cfg.model,
        ui::RESET
    );
    println!("{}Type /help, /exit to quit.{}\n", ui::DIM, ui::RESET);

    let system_msg = Message {
        role: "system".to_string(),
        content: build_system_prompt(&cfg),
        tool_calls: None,
    };
    let mut messages = if cfg.no_ctx {
        vec![system_msg]
    } else {
        context::load(&system_msg)
    };
    if messages.len() > 1 {
        println!("{}Restored {} messages from previous session.{}",
            ui::DIM, messages.len() - 1, ui::RESET);
    }

    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut line = String::new();

    loop {
        print!("{}offcode>{} ", ui::BRIGHT_GREEN, ui::RESET);
        io::stdout().flush().ok();

        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) | Err(_) => {
                println!();
                break;
            }
            Ok(_) => {}
        }

        let input = line.trim().to_string();
        if input.is_empty() {
            continue;
        }

        match input.as_str() {
            "/exit" | "/quit" | "/q" => {
                println!("{}Goodbye!{}", ui::CYAN, ui::RESET);
                break;
            }
            "/help" => print_repl_help(),
            "/clear" | "/reset" => {
                messages.truncate(1);
                println!("{}History cleared.{}", ui::DIM, ui::RESET);
            }
            "/compact" => run_compact(&cfg, &client, &mut messages),
            "/tools" => tools::print_list(),
            "/yolo" => {
                cfg.yolo = !cfg.yolo;
                let state = if cfg.yolo { "on (tools run without prompting)" } else { "off (prompt before each tool call)" };
                println!("{}Yolo mode: {}{}", ui::DIM, state, ui::RESET);
            }
            "/config" => {
                println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
            }
            "/history" => print_history(&messages),
            "/model" | "/models" => print_model_list(&client, &cfg.model),
            s if s.starts_with("/model ") => {
                cfg.model = s[7..].trim().to_string();
                println!("{}Model → {}{}", ui::DIM, cfg.model, ui::RESET);
            }
            s if s.starts_with('/') => {
                println!("{}Unknown command. /help{}", ui::DIM, ui::RESET);
            }
            _ => {
                run_turn(&cfg, &client, &mut messages, &input);
                if !cfg.no_ctx { context::save(&messages); }
            }
        }
    }
}

// ── agentic turn (used by single-shot and --no-tui modes) ────────────────────

fn run_turn(cfg: &Config, client: &Client, messages: &mut Vec<Message>, input: &str) {
    messages.push(Message {
        role: "user".to_string(),
        content: input.to_string(),
        tool_calls: None,
    });

    let tool_defs = tools::definitions();
    let mut iters = 0u32;

    loop {
        if iters >= cfg.max_tool_iters {
            println!("\n{}Max tool iterations reached.{}", ui::YELLOW, ui::RESET);
            break;
        }
        iters += 1;

        let request = ChatRequest {
            model: cfg.model.clone(),
            messages: messages.clone(),
            stream: true,
            tools: tool_defs.clone(),
            options: Options {
                temperature: cfg.temperature,
                num_ctx: cfg.num_ctx,
            },
        };

        let mut first_token = true;

        let no_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = client.chat_stream(
            &request,
            cfg.show_thinking,
            no_cancel,
            |token: &str, is_thinking: bool| {
                if first_token && !is_thinking {
                    print!("{}", ui::WHITE);
                    first_token = false;
                }
                if is_thinking {
                    print!("{}{}{}", ui::DIM, token, ui::RESET);
                } else {
                    print!("{token}");
                }
                io::stdout().flush().ok();
            },
        );

        match result {
            Ok((content, Some(mut calls))) => {
                println!("{}", ui::RESET);

                // Per-call confirmation: may mutate args on Modify, or produce
                // a comment appended after the tool result.
                let mut actions: Vec<ConfirmAction> = Vec::with_capacity(calls.len());
                for call in calls.iter_mut() {
                    print_tool_call(&call.function.name, &call.function.arguments);
                    let action = if cfg.is_auto_approved(&call.function.name) {
                        ConfirmAction::Accept
                    } else {
                        prompt_confirm_stdin()
                    };
                    if let ConfirmAction::Modify(ref new_args) = action {
                        call.function.arguments = new_args.clone();
                        println!("{}  (args modified){}", ui::DIM, ui::RESET);
                    }
                    actions.push(action);
                }

                messages.push(Message {
                    role: "assistant".to_string(),
                    content: content.clone(),
                    tool_calls: Some(calls.clone()),
                });

                for (call, action) in calls.iter().zip(actions) {
                    let name = &call.function.name;
                    let args = &call.function.arguments;

                    let (tool_result, extra_user) = match action {
                        ConfirmAction::Reject(reason) => {
                            let msg = if reason.is_empty() {
                                "Tool call rejected by user.".to_string()
                            } else {
                                format!("Tool call rejected by user: {reason}")
                            };
                            println!("{}  ✗ rejected{}", ui::YELLOW, ui::RESET);
                            (msg, None)
                        }
                        ConfirmAction::Comment(text) => {
                            let r = tools::execute(name, args);
                            let preview: Vec<&str> = r.lines().take(4).collect();
                            if !preview.is_empty() {
                                println!("{}  → {}{}", ui::DIM, preview.join(" | "), ui::RESET);
                            }
                            (r, Some(text))
                        }
                        ConfirmAction::Accept | ConfirmAction::Modify(_) => {
                            let r = tools::execute(name, args);
                            let preview: Vec<&str> = r.lines().take(4).collect();
                            if !preview.is_empty() {
                                println!("{}  → {}{}", ui::DIM, preview.join(" | "), ui::RESET);
                            }
                            (r, None)
                        }
                    };

                    messages.push(Message {
                        role: "tool".to_string(),
                        content: tool_result,
                        tool_calls: None,
                    });

                    if let Some(text) = extra_user {
                        println!("{}  + user note: {}{}", ui::DIM, text, ui::RESET);
                        messages.push(Message {
                            role: "user".to_string(),
                            content: text,
                            tool_calls: None,
                        });
                    }
                }
                println!();
            }

            Ok((content, None)) => {
                println!("{}\n", ui::RESET);
                if !content.is_empty() {
                    messages.push(Message {
                        role: "assistant".to_string(),
                        content,
                        tool_calls: None,
                    });
                }
                break;
            }

            Err(e) => {
                println!("{}", ui::RESET);
                eprintln!("{}{}Error:{} {e}", ui::BOLD, ui::RED, ui::RESET);
                messages.pop();
                break;
            }
        }
    }
}

// ── /compact (REPL implementation; TUI has its own async worker) ─────────────

fn run_compact(cfg: &Config, client: &Client, messages: &mut Vec<Message>) {
    if messages.len() <= 1 {
        println!("{}Nothing to compact.{}", ui::DIM, ui::RESET);
        return;
    }
    let mut msgs = messages.clone();
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
    print!("{}", ui::DIM);
    io::stdout().flush().ok();
    let no_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = client.chat_stream(&request, false, no_cancel, |token, _is_think| {
        print!("{token}");
        io::stdout().flush().ok();
    });
    println!("{}", ui::RESET);
    match result {
        Ok((summary, _)) if !summary.trim().is_empty() => {
            let system = messages.first().cloned().expect("system prompt");
            *messages = vec![
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
            if !cfg.no_ctx { context::save(messages); }
            println!("{}Context compacted.{}", ui::DIM, ui::RESET);
        }
        Ok(_) => {
            println!("{}Compact produced empty summary; history unchanged.{}", ui::YELLOW, ui::RESET);
        }
        Err(e) => {
            println!("{}Compact error: {}{}", ui::RED, e, ui::RESET);
        }
    }
}

// ── shared helper (also used by tui.rs) ──────────────────────────────────────

pub const COMPACT_PROMPT: &str = "\
You are compressing the conversation above so work can continue in a smaller context.\n\
Produce ONE concise summary (plain prose + terse bullets, no preamble, no closing remarks).\n\
It must preserve, and ONLY preserve, what is needed to keep working:\n\
  • The user's current task and overall goal.\n\
  • Decisions made, constraints agreed on, and conclusions reached.\n\
  • Concrete artifacts: file paths, function/type names, commands, URLs, identifiers.\n\
  • Relevant contents already read from files (keep exact signatures, key code snippets).\n\
  • Outstanding TODOs, unresolved questions, and the next concrete step.\n\
  • User preferences or corrections given during the conversation.\n\
Drop tool-call mechanics, chit-chat, retries, dead ends, and anything already superseded.\n\
Do not ask questions. Do not address the user. Write the summary as notes for your future self.\n\
Output the summary only.";

pub fn build_system_prompt(cfg: &Config) -> String {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".to_string());

    let skill_section = tools::active_skill()
        .map(|s| format!("\n\n# Active skill\n\n{s}"))
        .unwrap_or_default();

    format!(
        "{}\n\nCurrent directory: {}\nOS: {}{}",
        cfg.system_prompt,
        cwd,
        std::env::consts::OS,
        skill_section,
    )
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn print_help() {
    let b = ui::BOLD;
    let r = ui::RESET;
    let c = ui::CYAN;
    let d = ui::DIM;
    println!(
        "{b}offcode{r} {} — offline AI coding assistant",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("{b}USAGE{r}");
    println!("  offcode [OPTIONS] [PROMPT]");
    println!();
    println!("{b}OPTIONS{r}");
    println!("  {c}-m, --model <MODEL>{r}   {d}Model to use (default: gemma4:e4b){r}");
    println!("  {c}    --url <URL>{r}       {d}Ollama base URL{r}");
    println!("  {c}    --think{r}           {d}Show thinking tokens{r}");
    println!("  {c}    --no-tui{r}          {d}Plain terminal mode (no TUI){r}");
    println!("  {c}    --config{r}          {d}Print configuration{r}");
    println!("  {c}-v, --version{r}         {d}Print version{r}");
    println!("  {c}-h, --help{r}            {d}Print help{r}");
}

fn print_repl_help() {
    let b = ui::BOLD;
    let r = ui::RESET;
    let c = ui::CYAN;
    let d = ui::DIM;
    println!("{b}Commands{r}");
    println!("  {c}/help{r}           {d}This help{r}");
    println!("  {c}/clear{r}          {d}Clear history{r}");
    println!("  {c}/compact{r}        {d}Summarize history to shrink context{r}");
    println!("  {c}/history{r}        {d}Show history{r}");
    println!("  {c}/tools{r}          {d}List tools{r}");
    println!("  {c}/model{r}          {d}List available models (with capabilities){r}");
    println!("  {c}/model <name>{r}   {d}Switch model{r}");
    println!("  {c}/config{r}         {d}Show config{r}");
    println!("  {c}/yolo{r}           {d}Toggle yolo mode (auto-approve tool calls){r}");
    println!("  {c}/exit{r}           {d}Quit{r}");
}

fn print_model_list(client: &Client, selected: &str) {
    let models = match client.list_models() {
        Ok(m) => m,
        Err(e) => {
            println!("{}Error listing models: {}{}", ui::RED, e, ui::RESET);
            return;
        }
    };
    if models.is_empty() {
        println!("{}No models installed. Try `ollama pull <model>`.{}", ui::DIM, ui::RESET);
        return;
    }
    let caps: Vec<ollama::ModelCaps> =
        models.iter().map(|m| client.model_capabilities(&m.name)).collect();
    let rows = ollama::format_model_listing(&models, &caps, selected);
    println!(
        "{}{}  tools🛠   thinking🧠   vision👁{}",
        ui::DIM,
        " ".repeat(2),
        ui::RESET
    );
    for (line, is_sel) in &rows {
        if *is_sel {
            println!("{}{}{}{}", ui::BOLD, ui::BRIGHT_CYAN, line, ui::RESET);
        } else {
            println!("{}", line);
        }
    }
    println!(
        "{}selected: {}{}{}",
        ui::DIM,
        ui::BRIGHT_CYAN,
        selected,
        ui::RESET
    );
}

fn print_tool_call(name: &str, args: &serde_json::Value) {
    println!(
        "\n{}{}⚙ {}{}{}{}",
        ui::BOLD,
        ui::BRIGHT_YELLOW,
        ui::RESET,
        ui::CYAN,
        name,
        ui::RESET
    );
    if let Some(obj) = args.as_object() {
        for (k, v) in obj {
            let val = match v {
                serde_json::Value::String(s) => {
                    let first: String =
                        s.lines().next().unwrap_or("").chars().take(80).collect();
                    if s.lines().count() > 1 {
                        format!("{first}…")
                    } else {
                        first
                    }
                }
                other => other.to_string(),
            };
            println!("  {}  {k}: {}{}", ui::DIM, val, ui::RESET);
        }
    }
}

fn prompt_confirm_stdin() -> ConfirmAction {
    use std::io::BufRead;
    let stdin = io::stdin();
    loop {
        print!(
            "{}[y]accept  [n]reject  [c <note>]comment  [m <json>]modify ? {}",
            ui::BRIGHT_GREEN,
            ui::RESET
        );
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            return ConfirmAction::Reject("stdin closed".into());
        }
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
            return ConfirmAction::Accept;
        }
        if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
            return ConfirmAction::Reject(String::new());
        }
        let (head, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((h, r)) => (h, r.trim()),
            None => (trimmed, ""),
        };
        match head {
            "r" | "reject" => return ConfirmAction::Reject(rest.to_string()),
            "c" | "comment" => {
                if rest.is_empty() {
                    println!("{}  (comment text required){}", ui::YELLOW, ui::RESET);
                    continue;
                }
                return ConfirmAction::Comment(rest.to_string());
            }
            "m" | "modify" => {
                if rest.is_empty() {
                    println!("{}  (json args required){}", ui::YELLOW, ui::RESET);
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(rest) {
                    Ok(v) => return ConfirmAction::Modify(v),
                    Err(e) => {
                        println!("{}  invalid JSON: {}{}", ui::YELLOW, e, ui::RESET);
                        continue;
                    }
                }
            }
            _ => {
                println!("{}  unknown response{}", ui::YELLOW, ui::RESET);
            }
        }
    }
}

fn print_history(messages: &[Message]) {
    for msg in messages.iter().skip(1) {
        let (color, label): (&str, &str) = match msg.role.as_str() {
            "user" => (ui::BRIGHT_GREEN, "you     "),
            "assistant" => (ui::CYAN, "offcode "),
            "tool" => (ui::BRIGHT_YELLOW, "tool    "),
            _ => (ui::DIM, "other   "),
        };
        let preview: String = msg.content.lines().take(2).collect::<Vec<_>>().join(" · ");
        let preview = if preview.len() > 100 {
            format!("{}…", &preview[..100])
        } else {
            preview
        };
        let rst = ui::RESET;
        let dim = ui::DIM;
        println!("{color}{label}{rst} {dim}{preview}{rst}");
    }
}
