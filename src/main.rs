use std::io::{self, BufRead, Write};

mod config;
mod context;
mod diff;
mod ollama;
mod tools;
mod tui;
mod ui;

use config::Config;
use ollama::{ChatRequest, Client, Message, Options};

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
        let mut messages = vec![Message {
            role: "system".to_string(),
            content: build_system_prompt(&cfg),
            tool_calls: None,
        }];
        let prompt = prompt_words.join(" ");
        run_turn(&cfg, &client, &mut messages, &prompt);
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

    let mut messages = vec![Message {
        role: "system".to_string(),
        content: build_system_prompt(&cfg),
        tool_calls: None,
    }];

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
            "/tools" => tools::print_list(),
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
            _ => run_turn(&cfg, &client, &mut messages, &input),
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
            Ok((content, Some(calls))) => {
                println!("{}", ui::RESET);
                messages.push(Message {
                    role: "assistant".to_string(),
                    content: content.clone(),
                    tool_calls: Some(calls.clone()),
                });

                for call in &calls {
                    let name = &call.function.name;
                    let args = &call.function.arguments;
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
                    let tool_result = tools::execute(name, args);
                    let preview: Vec<&str> = tool_result.lines().take(4).collect();
                    if !preview.is_empty() {
                        println!("{}  → {}{}", ui::DIM, preview.join(" | "), ui::RESET);
                    }
                    messages.push(Message {
                        role: "tool".to_string(),
                        content: tool_result,
                        tool_calls: None,
                    });
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

// ── shared helper (also used by tui.rs) ──────────────────────────────────────

pub fn build_system_prompt(cfg: &Config) -> String {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".to_string());

    let ctx_hint = if context::ctx_path().exists() {
        "\n\nA file named .offcode.ctx exists in the current directory. \
         It contains the conversation history from previous sessions in JSON format. \
         Read it with the read_file tool at the start to restore context."
    } else {
        ""
    };

    format!(
        "{}\n\nCurrent directory: {}\nOS: {}{}",
        cfg.system_prompt,
        cwd,
        std::env::consts::OS,
        ctx_hint,
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
    println!("  {c}/history{r}        {d}Show history{r}");
    println!("  {c}/tools{r}          {d}List tools{r}");
    println!("  {c}/model{r}          {d}List available models (with capabilities){r}");
    println!("  {c}/model <name>{r}   {d}Switch model{r}");
    println!("  {c}/config{r}         {d}Show config{r}");
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
