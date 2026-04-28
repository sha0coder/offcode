use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;

// ── SSH session state ─────────────────────────────────────────────────────────

struct SshState {
    host: String,
    user: String,
    socket: String,
}

static SSH: Mutex<Option<SshState>> = Mutex::new(None);

// ── radare2 built-in skill ────────────────────────────────────────────────────

const R2_SKILL: &str = "\
# Radare2 expert

You are an expert reverse engineer using radare2. Follow these guidelines:

## Session workflow
1. After r2_open, run `aaa` to analyze the binary (skip with no_analysis=true for raw hex work).
2. Use `afl` to list functions, `s <addr|name>` to seek, `pdf` to disassemble the current function.
3. Prefer JSON output (`-j` flag) when you need to parse structured data: `aflj`, `pdj`, etc.

## Essential commands
- `i` / `ii` / `il` — binary info / imports / libraries
- `afl` — list all functions
- `pdf` / `pdf @ sym.main` — disassemble function at current seek / at symbol
- `s addr` — seek to address or symbol name
- `px N` / `pxw N` — hex dump N bytes / words
- `ps @ addr` — print string at address
- `xrefs @ addr` — cross-references to address
- `afvd` — list local variables of current function
- `axt addr` — find references to address
- `iz` / `izz` — strings in data section / whole binary

## Patching (requires write=true)
- `wa <asm>` — write assembly at current seek, e.g. `wa nop`
- `wx <hex>` — write raw hex bytes, e.g. `wx 9090`
- `wv4 <val>` — write 4-byte value

## Tips
- Chain commands with `;`: `s main; pdf`
- Use `~pattern` to grep output: `afl~main`
- Radare2 addresses are in hex: `0x401000`
- Always close the session with r2_close when done.
";

// ── radare2 session ───────────────────────────────────────────────────────────

struct R2Session {
    child:  Child,
    stdin:  ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

static R2: Mutex<Option<R2Session>> = Mutex::new(None);

// ── IRC session ───────────────────────────────────────────────────────────────

enum IrcStream {
    Plain(std::net::TcpStream),
    Tls(Box<native_tls::TlsStream<std::net::TcpStream>>),
}

impl IrcStream {
    fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            IrcStream::Plain(s) => s.set_read_timeout(dur),
            IrcStream::Tls(s)   => s.get_ref().set_read_timeout(dur),
        }
    }
}

impl std::io::Read for IrcStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            IrcStream::Plain(s) => s.read(buf),
            IrcStream::Tls(s)   => s.read(buf),
        }
    }
}

impl std::io::Write for IrcStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            IrcStream::Plain(s) => s.write(buf),
            IrcStream::Tls(s)   => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            IrcStream::Plain(s) => s.flush(),
            IrcStream::Tls(s)   => s.flush(),
        }
    }
}

struct IrcSession {
    reader:  BufReader<IrcStream>,
    channel: String,
    nick:    String,
    host:    String,
}

static IRC: Mutex<Option<IrcSession>> = Mutex::new(None);

fn irc_send_line(stream: &mut IrcStream, line: &str) -> std::io::Result<()> {
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

// Drain any available lines without blocking. Auto-responds to PING.
// `budget_ms` is the total time we're willing to wait for output.
fn irc_drain(session: &mut IrcSession, budget_ms: u64) -> String {
    use std::io::ErrorKind;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
    let _ = session.reader.get_ref().set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let mut out = String::new();
    loop {
        let mut line = String::new();
        match session.reader.read_line(&mut line) {
            Ok(0) => { out.push_str("[irc: connection closed]\n"); break; }
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                if let Some(rest) = trimmed.strip_prefix("PING ") {
                    let pong = format!("PONG {rest}");
                    let _ = irc_send_line(session.reader.get_mut(), &pong);
                    continue;
                }
                out.push_str(&trimmed);
                out.push('\n');
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if std::time::Instant::now() >= deadline { break; }
            }
            Err(e) => { out.push_str(&format!("[read error: {e}]\n")); break; }
        }
    }
    out
}

// ── browser state ────────────────────────────────────────────────────────────

struct FormField {
    name:  String,
    ftype: String,
    value: String,
}

struct HtmlForm {
    action: String,
    method: String,
    fields: Vec<FormField>,
}

struct BrowserState {
    url:        String,
    cookie_jar: String,   // "name=val; name2=val2" ready to send
    forms:      Vec<HtmlForm>,
}

static BROWSER: Mutex<Option<BrowserState>> = Mutex::new(None);

// ── active skill ──────────────────────────────────────────────────────────────

static SKILL: Mutex<Option<String>> = Mutex::new(None);

pub fn active_skill() -> Option<String> {
    SKILL.lock().ok()?.clone()
}

// ── tool schema definitions ──────────────────────────────────────────────────

pub fn definitions() -> Vec<Value> {
    vec![
        json!({
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read the full contents of a file. Adds line numbers for code files.",
                "parameters": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string", "description": "File path to read" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write (or overwrite) a file with the given content. Creates parent dirs automatically. 'path' is REQUIRED — always supply a filename such as 'notes.md' or 'src/foo.rs'.",
                "parameters": {
                    "type": "object",
                    "required": ["path", "content"],
                    "properties": {
                        "path":    { "type": "string", "description": "Destination file path" },
                        "content": { "type": "string", "description": "Content to write" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "Execute a shell command (via sh -c). Returns exit code, stdout, and stderr.",
                "parameters": {
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to run" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List files and subdirectories at a path. Directories are marked with /.",
                "parameters": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string", "description": "Directory to list (use '.' for current)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "search_files",
                "description": "Recursively search for a text pattern inside files. Returns matching lines with paths and line numbers.",
                "parameters": {
                    "type": "object",
                    "required": ["pattern"],
                    "properties": {
                        "pattern":      { "type": "string", "description": "Text to search for (case-insensitive)" },
                        "path":         { "type": "string", "description": "Root directory to search (default: current dir)" },
                        "file_ext":     { "type": "string", "description": "Restrict to files with this extension, e.g. 'rs'" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "create_dir",
                "description": "Create a directory tree (like mkdir -p).",
                "parameters": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string", "description": "Directory path to create" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "delete_path",
                "description": "Delete a file or an empty directory.",
                "parameters": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string", "description": "Path to delete" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "change_dir",
                "description": "Change the current working directory. Use '..' to go up. All subsequent tool calls (read_file, run_command, etc.) will operate from the new directory.",
                "parameters": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string", "description": "Directory to change to, e.g. 'src', '..', '/tmp', '../other'" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "path_info",
                "description": "Get metadata about a file or directory (type, size, modified time).",
                "parameters": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string", "description": "Path to inspect" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "ssh_connect",
                "description": "Connect to a remote host via SSH. Subsequent ssh_exec calls run on that host.",
                "parameters": {
                    "type": "object",
                    "required": ["host", "user", "key"],
                    "properties": {
                        "host": { "type": "string", "description": "Hostname or IP address" },
                        "user": { "type": "string", "description": "SSH username" },
                        "key":  { "type": "string", "description": "Path to the private key file (-i)" },
                        "port": { "type": "integer", "description": "SSH port (default 22)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "ssh_exec",
                "description": "Execute a command on the currently connected remote SSH host.",
                "parameters": {
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to run on the remote host" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "r2_open",
                "description": "Open a radare2 session on a binary file. Must be called before r2_cmd. Opens an interactive r2 process that keeps state (seek position, analysis, flags) across commands.",
                "parameters": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file":        { "type": "string",  "description": "Path to the binary file to open" },
                        "write":       { "type": "boolean", "description": "Open in write mode (-w) for patching" },
                        "no_analysis": { "type": "boolean", "description": "Skip analysis (-n), useful for raw hex editing" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "r2_cmd",
                "description": "Send one or more radare2 commands to the open session and return the output. Separate multiple commands with semicolons or newlines.",
                "parameters": {
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": { "type": "string", "description": "r2 command(s) to execute, e.g. 'aaa' or 'pdf @ main' or 's 0x1234; pd 20'" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "r2_close",
                "description": "Close the current radare2 session.",
                "parameters": {
                    "type": "object",
                    "required": [],
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "irc_open",
                "description": "Connect to an IRC server over TLS (default port 6697) and join a channel. Persists for the session; use irc_say / irc_read / irc_close.",
                "parameters": {
                    "type": "object",
                    "required": ["host", "nick", "channel"],
                    "properties": {
                        "host":     { "type": "string", "description": "IRC server hostname, e.g. irc.libera.chat" },
                        "port":     { "type": "integer", "description": "TCP port (default 6697 with SSL, 6667 without)" },
                        "nick":     { "type": "string", "description": "Nickname to register with" },
                        "channel":  { "type": "string", "description": "Channel to join, e.g. #rust (will prepend '#' if missing)" },
                        "ssl":      { "type": "boolean", "description": "Use TLS (default true)" },
                        "password": { "type": "string", "description": "Optional server password (sent via PASS before NICK)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "irc_say",
                "description": "Send a PRIVMSG to the joined channel (or to 'target' if given — a user or another channel).",
                "parameters": {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "string", "description": "Message text" },
                        "target":  { "type": "string", "description": "Optional target (user or channel). Defaults to the joined channel." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "irc_read",
                "description": "Read pending lines from the IRC server (auto-responds to PING). Blocks up to timeout_ms collecting whatever arrives.",
                "parameters": {
                    "type": "object",
                    "required": [],
                    "properties": {
                        "timeout_ms": { "type": "integer", "description": "Total time budget to wait for output, in ms (default 3000)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "irc_raw",
                "description": "Send a raw IRC command line (without CRLF), e.g. 'JOIN #rust' or 'WHOIS alice'.",
                "parameters": {
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": { "type": "string", "description": "Raw IRC command" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "irc_close",
                "description": "Disconnect from the IRC server (sends QUIT).",
                "parameters": { "type": "object", "required": [], "properties": {} }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_navigate",
                "description": "Navigate to an HTTP/HTTPS URL. Maintains cookies across calls. Returns the page as plain text plus a summary of any HTML forms found (index, action, fields).",
                "parameters": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": { "type": "string", "description": "Full URL to navigate to" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_fill",
                "description": "Fill a field in the current page's form before submitting. Call once per field.",
                "parameters": {
                    "type": "object",
                    "required": ["field", "value"],
                    "properties": {
                        "field":      { "type": "string",  "description": "Field name (the 'name' attribute of the input)" },
                        "value":      { "type": "string",  "description": "Value to set" },
                        "form_index": { "type": "integer", "description": "Which form to target (0-based, default 0)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_submit",
                "description": "Submit the current form (GET or POST). Returns the resulting page as plain text plus any new forms.",
                "parameters": {
                    "type": "object",
                    "required": [],
                    "properties": {
                        "form_index": { "type": "integer", "description": "Which form to submit (0-based, default 0)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "load_skill",
                "description": "Load a skill from the skills/ folder. The skill's content is added to the system prompt for the rest of the session, giving you specialized instructions or knowledge. Use list_dir on 'skills/' to see what skills are available.",
                "parameters": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string", "description": "Skill name without extension, e.g. 'python' to load skills/python.md" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "Search the web using DuckDuckGo. Returns a summary and related results. Use for current events, documentation, news, or any information not in the local codebase.",
                "parameters": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query":   { "type": "string", "description": "Search query" },
                        "max_results": { "type": "integer", "description": "Max related results to return (default: 5)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fetch_url",
                "description": "Fetch the content of any HTTP or HTTPS URL. Returns plain text (HTML tags stripped). Use to read documentation, news articles, or any web page found via web_search.",
                "parameters": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": { "type": "string", "description": "Full URL to fetch (http:// or https://)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "ssh_disconnect",
                "description": "Close the current SSH connection.",
                "parameters": {
                    "type": "object",
                    "required": [],
                    "properties": {}
                }
            }
        }),
    ]
}

// ── tool execution ───────────────────────────────────────────────────────────

pub fn execute(name: &str, raw_args: &Value) -> String {
    let args = coerce_args(raw_args);

    match name {
        "read_file" => {
            let path = sarg(&args, "path");
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let content = String::from_utf8_lossy(&bytes).into_owned();
                    if is_code_ext(&path) {
                        content
                            .lines()
                            .enumerate()
                            .map(|(i, l)| format!("{:>4} | {l}", i + 1))
                            .collect::<Vec<_>>()
                            .join("\n")
                    } else {
                        content
                    }
                }
                Err(e) => format!("Error reading '{path}': {e}"),
            }
        }

        "write_file" => {
            let path = sarg(&args, "path");
            let content = sarg(&args, "content");
            if path.is_empty() {
                return "Error: 'path' argument is required and must not be empty. Provide a filename like 'notes.md' or 'src/foo.rs'.".to_string();
            }
            let old_content = std::fs::read_to_string(&path).unwrap_or_default();
            if let Some(parent) = Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            match std::fs::write(&path, &content) {
                Ok(_) => {
                    let diff = crate::diff::generate_diff(&old_content, &content);
                    format!("Wrote {} bytes to '{path}'\n{diff}", content.len())
                }
                Err(e) => format!("Error writing '{path}': {e}"),
            }
        }

        "run_command" => {
            let cmd = sarg(&args, "command");
            if let Err(reason) = check_command_paths(&cmd) {
                return format!("Blocked: {reason}");
            }
            match Command::new("sh").arg("-c").arg(&cmd).output() {
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
                    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
                    let mut result = format!("exit: {code}\n");
                    if !stdout.is_empty() {
                        result.push_str("stdout:\n");
                        result.push_str(&stdout);
                    }
                    if !stderr.is_empty() {
                        result.push_str("stderr:\n");
                        result.push_str(&stderr);
                    }
                    if stdout.is_empty() && stderr.is_empty() {
                        result.push_str("(no output)");
                    }
                    result
                }
                Err(e) => format!("Failed to run command: {e}"),
            }
        }

        "change_dir" => {
            let path = sarg(&args, "path");
            if path.is_empty() { return "Error: 'path' is required".to_string(); }
            match std::env::set_current_dir(&path) {
                Ok(_) => {
                    let cwd = std::env::current_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| path.clone());
                    format!("Changed directory to: {cwd}")
                }
                Err(e) => format!("Error: {e}"),
            }
        }

        "list_dir" => {
            let path = sarg(&args, "path");
            let path = if path.is_empty() { ".".to_string() } else { path };
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    let mut items: Vec<String> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                            if is_dir { format!("{name}/") } else { name }
                        })
                        .collect();
                    items.sort();
                    if items.is_empty() {
                        "(empty directory)".to_string()
                    } else {
                        items.join("\n")
                    }
                }
                Err(e) => format!("Error listing '{path}': {e}"),
            }
        }

        "search_files" => {
            let pattern = sarg(&args, "pattern");
            let root = args
                .get("path")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(".");
            let ext = args
                .get("file_ext")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());

            if pattern.is_empty() {
                return "Error: pattern is required".to_string();
            }

            let mut results = Vec::new();
            search_recursive(root, &pattern.to_lowercase(), ext, 0, &mut results);

            if results.is_empty() {
                format!("No matches for '{pattern}'")
            } else {
                results.join("\n")
            }
        }

        "create_dir" => {
            let path = sarg(&args, "path");
            match std::fs::create_dir_all(&path) {
                Ok(_) => format!("Created '{path}'"),
                Err(e) => format!("Error: {e}"),
            }
        }

        "delete_path" => {
            let path = sarg(&args, "path");
            let p = Path::new(&path);
            let result = if p.is_dir() {
                std::fs::remove_dir(&path)
            } else {
                std::fs::remove_file(&path)
            };
            match result {
                Ok(_) => format!("Deleted '{path}'"),
                Err(e) => format!("Error: {e}"),
            }
        }

        "path_info" => {
            let path = sarg(&args, "path");
            match std::fs::metadata(&path) {
                Ok(m) => {
                    let kind = if m.is_dir() { "directory" } else { "file" };
                    let size = m.len();
                    let modified = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    format!("path: {path}\ntype: {kind}\nsize: {size} bytes\nmodified (unix): {modified}")
                }
                Err(e) => format!("Error: {e}"),
            }
        }

        "ssh_connect" => {
            let host = sarg(&args, "host");
            let user = sarg(&args, "user");
            let key  = sarg(&args, "key");
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(22);
            let socket = format!("/tmp/offcode-ssh-{}", std::process::id());

            // Disconnect any existing session first
            if let Ok(mut g) = SSH.lock() {
                if let Some(old) = g.take() {
                    let _ = Command::new("ssh")
                        .args(["-S", &old.socket, "-O", "exit",
                               &format!("{}@{}", old.user, old.host)])
                        .output();
                }
            }

            let status = Command::new("ssh")
                .args([
                    "-i", &key,
                    "-p", &port.to_string(),
                    "-M", "-S", &socket,
                    "-fN",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "ConnectTimeout=10",
                    "-o", "LogLevel=QUIET",
                    "-o", "PermitLocalCommand=no",
                    &format!("{user}@{host}"),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            match status {
                Ok(s) if s.success() => {
                    if let Ok(mut g) = SSH.lock() {
                        *g = Some(SshState { host: host.clone(), user: user.clone(), socket: socket.clone() });
                    }
                    // Fetch MOTD as plain text so it appears safely in the TUI
                    let motd = Command::new("ssh")
                        .args(["-S", &socket, &format!("{user}@{host}"),
                               "cat /etc/motd /run/motd.dynamic 2>/dev/null; true"])
                        .output()
                        .map(|o| strip_ansi(&String::from_utf8_lossy(&o.stdout)))
                        .unwrap_or_default();
                    let motd = motd.trim();
                    if motd.is_empty() {
                        format!("Connected to {user}@{host}:{port}")
                    } else {
                        format!("Connected to {user}@{host}:{port}\n\n{motd}")
                    }
                }
                Ok(s) => format!("SSH connect failed (exit {})", s.code().unwrap_or(-1)),
                Err(e) => format!("SSH error: {e}"),
            }
        }

        "ssh_exec" => {
            let cmd = sarg(&args, "command");
            let guard = SSH.lock().unwrap();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return "Not connected to any SSH host. Use ssh_connect first.".to_string(),
            };
            let out = Command::new("ssh")
                .args(["-S", &state.socket, &format!("{}@{}", state.user, state.host), &cmd])
                .output();
            match out {
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
                    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
                    let mut result = format!("exit: {code}\n");
                    if !stdout.is_empty() { result.push_str(&format!("stdout:\n{stdout}")); }
                    if !stderr.is_empty()  { result.push_str(&format!("stderr:\n{stderr}")); }
                    if stdout.is_empty() && stderr.is_empty() { result.push_str("(no output)"); }
                    result
                }
                Err(e) => format!("SSH exec error: {e}"),
            }
        }

        "ssh_disconnect" => {
            let mut guard = SSH.lock().unwrap();
            match guard.take() {
                Some(state) => {
                    let _ = Command::new("ssh")
                        .args(["-S", &state.socket, "-O", "exit",
                               &format!("{}@{}", state.user, state.host)])
                        .output();
                    format!("Disconnected from {}@{}", state.user, state.host)
                }
                None => "Not connected to any SSH host.".to_string(),
            }
        }

        "load_skill" => {
            let name = sarg(&args, "name");
            if name.is_empty() {
                return "Error: 'name' is required".to_string();
            }
            let name = name.trim_end_matches(".md");
            let path = format!("skills/{name}.md");
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if let Ok(mut g) = SKILL.lock() {
                        *g = Some(content.clone());
                    }
                    format!("Skill '{name}' loaded. Its instructions are now active in your system prompt.")
                }
                Err(e) => format!("Could not load skill '{name}' from '{path}': {e}"),
            }
        }

        "r2_open" => {
            let file        = sarg(&args, "file");
            let write       = args.get("write").and_then(|v| v.as_bool()).unwrap_or(false);
            let no_analysis = args.get("no_analysis").and_then(|v| v.as_bool()).unwrap_or(false);

            if file.is_empty() { return "Error: 'file' is required".to_string(); }

            // Close any existing session first
            if let Ok(mut g) = R2.lock() {
                if let Some(mut old) = g.take() {
                    let _ = old.stdin.write_all(b"q\n");
                    let _ = old.child.wait();
                }
            }

            let mut cmd = Command::new("r2");
            if write       { cmd.arg("-w"); }
            if no_analysis { cmd.arg("-n"); }
            cmd.arg("-q0").arg(&file)   // -q0: quiet + no banner, still interactive
               .stdin(Stdio::piped())
               .stdout(Stdio::piped())
               .stderr(Stdio::null());

            match cmd.spawn() {
                Err(e) => format!("Failed to launch r2: {e}"),
                Ok(mut child) => {
                    let stdin  = child.stdin.take().unwrap();
                    let stdout = BufReader::new(child.stdout.take().unwrap());
                    let mut session = R2Session { child, stdin, stdout };
                    // Drain the initial prompt/banner
                    r2_drain(&mut session.stdout);
                    let mode = match (write, no_analysis) {
                        (true, true)  => " [-w -n]",
                        (true, false) => " [-w]",
                        (false, true) => " [-n]",
                        _             => "",
                    };
                    if let Ok(mut g) = R2.lock() { *g = Some(session); }

                    // Auto-load r2 skill: prefer skills/radare2.md, fall back to built-in
                    let skill_content = std::fs::read_to_string("skills/radare2.md")
                        .unwrap_or_else(|_| R2_SKILL.to_string());
                    if let Ok(mut g) = SKILL.lock() { *g = Some(skill_content); }

                    format!("r2 session opened on '{file}'{mode}. Use r2_cmd to run commands.")
                }
            }
        }

        "r2_cmd" => {
            let command = sarg(&args, "command");
            if command.is_empty() { return "Error: 'command' is required".to_string(); }
            match R2.lock() {
                Ok(mut g) => match g.as_mut() {
                    None => "No r2 session open. Use r2_open first.".to_string(),
                    Some(session) => {
                        // Send command(s) followed by sentinel
                        let payload = format!("{command}\n?e --OFFCODE--\n");
                        if let Err(e) = session.stdin.write_all(payload.as_bytes()) {
                            return format!("r2 write error: {e}");
                        }
                        let _ = session.stdin.flush();
                        // Read lines until sentinel
                        let mut out = String::new();
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match session.stdout.read_line(&mut line) {
                                Ok(0) => { out.push_str("[r2 process ended]"); break; }
                                Ok(_) => {
                                    if line.trim() == "--OFFCODE--" { break; }
                                    out.push_str(&line);
                                }
                                Err(e) => { out.push_str(&format!("[read error: {e}]")); break; }
                            }
                        }
                        if out.is_empty() { "(no output)".to_string() } else { out }
                    }
                },
                Err(_) => "r2 lock error".to_string(),
            }
        }

        "r2_close" => {
            match R2.lock() {
                Ok(mut g) => match g.take() {
                    None => "No r2 session open.".to_string(),
                    Some(mut session) => {
                        let _ = session.stdin.write_all(b"q\n");
                        let _ = session.child.wait();
                        "r2 session closed.".to_string()
                    }
                },
                Err(_) => "r2 lock error".to_string(),
            }
        }

        "irc_open" => {
            let host     = sarg(&args, "host");
            let nick     = sarg(&args, "nick");
            let mut chan = sarg(&args, "channel");
            let password = sarg(&args, "password");
            let ssl      = args.get("ssl").and_then(|v| v.as_bool()).unwrap_or(true);
            let port     = args.get("port").and_then(|v| v.as_u64())
                .unwrap_or(if ssl { 6697 } else { 6667 }) as u16;

            if host.is_empty() { return "Error: 'host' is required".to_string(); }
            if nick.is_empty() { return "Error: 'nick' is required".to_string(); }
            if chan.is_empty() { return "Error: 'channel' is required".to_string(); }
            if !chan.starts_with('#') && !chan.starts_with('&') { chan = format!("#{chan}"); }

            // Close any existing session first
            if let Ok(mut g) = IRC.lock() {
                if let Some(mut old) = g.take() {
                    let _ = irc_send_line(old.reader.get_mut(), "QUIT :bye");
                }
            }

            let tcp = match std::net::TcpStream::connect((host.as_str(), port)) {
                Ok(s) => s,
                Err(e) => return format!("Connect failed: {e}"),
            };
            if let Err(e) = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))) {
                return format!("socket setup error: {e}");
            }

            let mut stream = if ssl {
                let connector = match native_tls::TlsConnector::new() {
                    Ok(c) => c,
                    Err(e) => return format!("TLS init: {e}"),
                };
                match connector.connect(&host, tcp) {
                    Ok(s)  => IrcStream::Tls(Box::new(s)),
                    Err(e) => return format!("TLS handshake: {e}"),
                }
            } else {
                IrcStream::Plain(tcp)
            };

            if !password.is_empty() {
                if let Err(e) = irc_send_line(&mut stream, &format!("PASS {password}")) {
                    return format!("PASS write error: {e}");
                }
            }
            if let Err(e) = irc_send_line(&mut stream, &format!("NICK {nick}")) {
                return format!("NICK write error: {e}");
            }
            if let Err(e) = irc_send_line(&mut stream, &format!("USER {nick} 0 * :{nick}")) {
                return format!("USER write error: {e}");
            }
            if let Err(e) = irc_send_line(&mut stream, &format!("JOIN {chan}")) {
                return format!("JOIN write error: {e}");
            }

            let mut session = IrcSession {
                reader: BufReader::new(stream),
                channel: chan.clone(),
                nick: nick.clone(),
                host: host.clone(),
            };

            // Collect welcome + MOTD + join confirmation, up to ~8s or until 366 arrives
            use std::io::ErrorKind;
            let _ = session.reader.get_ref().set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            let mut welcome = String::new();
            let mut joined  = false;
            let mut fatal: Option<String> = None;
            while std::time::Instant::now() < deadline {
                let mut line = String::new();
                match session.reader.read_line(&mut line) {
                    Ok(0) => { fatal = Some("connection closed during handshake".into()); break; }
                    Ok(_) => {
                        let l = line.trim_end_matches(['\r', '\n']).to_string();
                        if let Some(rest) = l.strip_prefix("PING ") {
                            let _ = irc_send_line(session.reader.get_mut(), &format!("PONG {rest}"));
                            continue;
                        }
                        welcome.push_str(&l);
                        welcome.push('\n');
                        // 366 = End of /NAMES list → joined successfully
                        if l.contains(" 366 ") && l.contains(&chan) { joined = true; break; }
                        // Error replies: nick in use / banned
                        if l.contains(" 433 ") || l.contains(" 432 ") || l.contains(" 465 ") || l.contains(" 474 ") {
                            fatal = Some(l);
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => continue,
                    Err(e) => { fatal = Some(format!("read error: {e}")); break; }
                }
            }

            if let Some(err) = fatal {
                return format!("IRC connect failed: {err}\n--- partial log ---\n{welcome}");
            }

            if let Ok(mut g) = IRC.lock() { *g = Some(session); }
            let status = if joined { "joined" } else { "connected (no 366 seen yet)" };
            format!(
                "IRC {status} to {host}:{port} as {nick} in {chan}. \
                 Use irc_say to talk, irc_read to poll messages, irc_close to disconnect.\n\
                 --- server greeting ---\n{welcome}"
            )
        }

        "irc_say" => {
            let message = sarg(&args, "message");
            let target  = sarg(&args, "target");
            if message.is_empty() { return "Error: 'message' is required".to_string(); }
            match IRC.lock() {
                Ok(mut g) => match g.as_mut() {
                    None => "No IRC session open. Use irc_open first.".to_string(),
                    Some(session) => {
                        let dest = if target.is_empty() { session.channel.clone() } else { target };
                        // Split multi-line messages into separate PRIVMSGs
                        let mut sent = 0;
                        for line in message.lines() {
                            if line.is_empty() { continue; }
                            let payload = format!("PRIVMSG {dest} :{line}");
                            if let Err(e) = irc_send_line(session.reader.get_mut(), &payload) {
                                return format!("write error after {sent} line(s): {e}");
                            }
                            sent += 1;
                        }
                        format!("Sent {sent} line(s) to {dest}.")
                    }
                },
                Err(_) => "irc lock error".to_string(),
            }
        }

        "irc_read" => {
            let budget = args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(3000);
            match IRC.lock() {
                Ok(mut g) => match g.as_mut() {
                    None => "No IRC session open. Use irc_open first.".to_string(),
                    Some(session) => {
                        let out = irc_drain(session, budget);
                        if out.is_empty() { "(no new messages)".to_string() } else { out }
                    }
                },
                Err(_) => "irc lock error".to_string(),
            }
        }

        "irc_raw" => {
            let command = sarg(&args, "command");
            if command.is_empty() { return "Error: 'command' is required".to_string(); }
            match IRC.lock() {
                Ok(mut g) => match g.as_mut() {
                    None => "No IRC session open. Use irc_open first.".to_string(),
                    Some(session) => {
                        if let Err(e) = irc_send_line(session.reader.get_mut(), &command) {
                            return format!("write error: {e}");
                        }
                        format!("Sent: {command}")
                    }
                },
                Err(_) => "irc lock error".to_string(),
            }
        }

        "irc_close" => {
            match IRC.lock() {
                Ok(mut g) => match g.take() {
                    None => "No IRC session open.".to_string(),
                    Some(mut session) => {
                        let _ = irc_send_line(session.reader.get_mut(), "QUIT :bye");
                        format!("IRC session closed ({}@{}).", session.nick, session.host)
                    }
                },
                Err(_) => "irc lock error".to_string(),
            }
        }

        "browser_navigate" => {
            let url = sarg(&args, "url");
            if url.is_empty() { return "Error: 'url' is required".to_string(); }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return "Error: URL must start with http:// or https://".to_string();
            }
            let cookie_jar = BROWSER.lock().ok()
                .and_then(|g| g.as_ref().map(|b| b.cookie_jar.clone()))
                .unwrap_or_default();
            match browser_get(&url, &cookie_jar) {
                Ok((body, new_cookies, _)) => {
                    let content = strip_html(&body);
                    let forms   = parse_forms(&body);
                    let summary = forms_summary(&forms);
                    let jar     = merge_cookies(&cookie_jar, &new_cookies);
                    if let Ok(mut g) = BROWSER.lock() {
                        *g = Some(BrowserState { url, cookie_jar: jar, forms });
                    }
                    format!("{content}\n\n{summary}")
                }
                Err(e) => format!("Navigation failed: {e}"),
            }
        }

        "browser_fill" => {
            let field      = sarg(&args, "field");
            let value      = sarg(&args, "value");
            let form_index = args.get("form_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            if field.is_empty() { return "Error: 'field' is required".to_string(); }
            match BROWSER.lock() {
                Ok(mut g) => match g.as_mut() {
                    None => "No page loaded. Use browser_navigate first.".to_string(),
                    Some(state) => match state.forms.get_mut(form_index) {
                        None => format!("No form at index {form_index}."),
                        Some(form) => {
                            if let Some(f) = form.fields.iter_mut().find(|f| f.name == field) {
                                f.value = value.clone();
                                format!("Set '{field}' = '{value}'")
                            } else {
                                // Field not present yet — add it (some forms generate fields dynamically)
                                form.fields.push(FormField { name: field.clone(), ftype: "text".to_string(), value: value.clone() });
                                format!("Added '{field}' = '{value}'")
                            }
                        }
                    },
                },
                Err(_) => "Browser state lock error".to_string(),
            }
        }

        "browser_submit" => {
            let form_index = args.get("form_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let (base_url, cookie_jar, action, method, body_pairs) = {
                match BROWSER.lock() {
                    Ok(g) => match g.as_ref() {
                        None => return "No page loaded. Use browser_navigate first.".to_string(),
                        Some(state) => match state.forms.get(form_index) {
                            None => return format!("No form at index {form_index}."),
                            Some(form) => {
                                let pairs: Vec<(String, String)> = form.fields.iter()
                                    .filter(|f| f.ftype != "submit")
                                    .map(|f| (f.name.clone(), f.value.clone()))
                                    .collect();
                                (state.url.clone(), state.cookie_jar.clone(), form.action.clone(), form.method.clone(), pairs)
                            }
                        },
                    },
                    Err(_) => return "Browser state lock error".to_string(),
                }
            };

            let action_url = resolve_url(&base_url, &action);
            let encoded = body_pairs.iter()
                .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            let result = if method == "post" {
                browser_post(&action_url, &cookie_jar, &encoded)
            } else {
                let url = if encoded.is_empty() { action_url.clone() }
                          else { format!("{action_url}?{encoded}") };
                browser_get(&url, &cookie_jar)
            };

            match result {
                Ok((body, new_cookies, final_url)) => {
                    let content = strip_html(&body);
                    let forms   = parse_forms(&body);
                    let summary = forms_summary(&forms);
                    let jar     = merge_cookies(&cookie_jar, &new_cookies);
                    if let Ok(mut g) = BROWSER.lock() {
                        *g = Some(BrowserState { url: final_url, cookie_jar: jar, forms });
                    }
                    format!("{content}\n\n{summary}")
                }
                Err(e) => format!("Submit failed: {e}"),
            }
        }

        "fetch_url" => {
            let url = sarg(&args, "url");
            if url.is_empty() {
                return "Error: 'url' is required".to_string();
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return "Error: URL must start with http:// or https://".to_string();
            }
            match ureq::get(&url).call() {
                Ok(resp) => match resp.into_string() {
                    Ok(body) => strip_html(&body),
                    Err(e) => format!("Failed to read response: {e}"),
                },
                Err(e) => format!("Failed to fetch URL: {e}"),
            }
        }

        "web_search" => {
            let query = sarg(&args, "query");
            if query.is_empty() {
                return "Error: 'query' is required".to_string();
            }
            let max = args.get("max_results").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            let encoded: String = query
                .chars()
                .map(|c| if c == ' ' { '+' } else { c })
                .collect();
            let url = format!("https://html.duckduckgo.com/html/?q={encoded}");
            match ureq::get(&url)
                .set("User-Agent", "Mozilla/5.0 (compatible; offcode/1.0)")
                .call()
            {
                Ok(resp) => match resp.into_string() {
                    Ok(body) => parse_ddg_html(&body, max),
                    Err(e) => format!("Failed to read response: {e}"),
                },
                Err(e) => format!("Search request failed: {e}"),
            }
        }

        _ => format!("Unknown tool '{name}'"),
    }
}

/// Close any open SSH / radare2 / IRC sessions. Safe to call multiple times.
/// Returns a list of human-readable lines describing what was closed (empty if nothing).
pub fn cleanup_all() -> Vec<String> {
    let mut closed = Vec::new();

    if let Ok(mut g) = IRC.lock() {
        if let Some(mut s) = g.take() {
            let _ = irc_send_line(s.reader.get_mut(), "QUIT :offcode exiting");
            closed.push(format!("IRC: closed {}@{}", s.nick, s.host));
        }
    }

    if let Ok(mut g) = R2.lock() {
        if let Some(mut s) = g.take() {
            let _ = s.stdin.write_all(b"q\n");
            let _ = s.child.wait();
            closed.push("r2: session closed".into());
        }
    }

    if let Ok(mut g) = SSH.lock() {
        if let Some(s) = g.take() {
            let _ = Command::new("ssh")
                .args(["-S", &s.socket, "-O", "exit",
                       &format!("{}@{}", s.user, s.host)])
                .output();
            closed.push(format!("SSH: disconnected from {}@{}", s.user, s.host));
        }
    }

    closed
}

pub fn print_list() {
    use crate::ui::*;
    let tools = [
        ("read_file",    "Read file contents with line numbers"),
        ("write_file",   "Write/overwrite a file"),
        ("run_command",  "Run a shell command"),
        ("list_dir",     "List directory contents"),
        ("search_files", "Search pattern in files recursively"),
        ("create_dir",   "Create directories (mkdir -p)"),
        ("delete_path",     "Delete a file or empty directory"),
        ("path_info",       "File/directory metadata"),
        ("change_dir",      "Change current working directory (cd)"),
        ("ssh_connect",     "Connect to a remote host via SSH"),
        ("ssh_exec",        "Run a command on the connected SSH host"),
        ("ssh_disconnect",  "Disconnect from the current SSH host"),
        ("r2_open",          "Open a radare2 session on a binary (-w write, -n no-analysis)"),
        ("r2_cmd",           "Send command(s) to the open r2 session"),
        ("r2_close",         "Close the current r2 session"),
        ("irc_open",         "Connect to IRC (TLS by default) and join a channel"),
        ("irc_say",          "Send a PRIVMSG to the joined channel (or another target)"),
        ("irc_read",         "Poll incoming IRC lines (auto-responds to PING)"),
        ("irc_raw",          "Send a raw IRC command"),
        ("irc_close",        "Disconnect from IRC"),
        ("browser_navigate", "Navigate to a URL, get page text + forms"),
        ("browser_fill",    "Fill a form field on the current page"),
        ("browser_submit",  "Submit the current form (GET or POST)"),
        ("load_skill",      "Load a skill from skills/<name>.md into the system prompt"),
        ("web_search",      "Search the web via DuckDuckGo (no API key needed)"),
        ("fetch_url",       "Fetch and read any HTTP/HTTPS URL as plain text"),
    ];
    println!("{BOLD}Available tools:{RESET}");
    for (name, desc) in &tools {
        println!("  {CYAN}{name:<16}{RESET} {DIM}{desc}{RESET}");
    }
}

// ── command sandbox ───────────────────────────────────────────────────────────

fn check_command_paths(cmd: &str) -> Result<(), String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let cwd_str = cwd.to_string_lossy();

    // Directories that system binaries may live in — not treated as data paths
    const SYSTEM_BIN_PREFIXES: &[&str] = &[
        "/usr/", "/bin/", "/sbin/", "/opt/homebrew/", "/opt/local/",
        "/nix/", "/snap/", "/proc/", "/dev/null",
    ];

    // Split on common shell delimiters so we inspect each token
    for token in cmd.split(|c: char| c.is_whitespace() || matches!(c, '|' | ';' | '&' | '>' | '<' | '(' | ')')) {
        let token = token.trim_matches(|c| c == '\'' || c == '"');
        if token.is_empty() || token.starts_with('-') {
            continue;
        }

        // Block any directory traversal
        if token.contains("..") {
            return Err(format!("'{}' contains '..' (directory traversal)", token));
        }

        // Check absolute paths
        if token.starts_with('/') {
            if SYSTEM_BIN_PREFIXES.iter().any(|p| token.starts_with(p)) {
                continue;
            }
            if !token.starts_with(cwd_str.as_ref()) {
                return Err(format!("'{}' is outside the current directory", token));
            }
        }

        // Block home-dir references
        if token.starts_with('~') {
            return Err(format!("'{}' references the home directory", token));
        }
    }

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Strip ANSI/VT escape sequences so remote output doesn't corrupt the TUI.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some('[') => {
                    chars.next(); // consume '['
                    // consume until a byte in 0x40–0x7E (the final byte)
                    for ch in chars.by_ref() {
                        if ch.is_ascii_alphabetic() || matches!(ch, '~' | '@') {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    // OSC: consume until BEL or ST
                    for ch in chars.by_ref() {
                        if ch == '\x07' || ch == '\u{9C}' { break; }
                        if ch == '\x1b' {
                            if chars.peek() == Some(&'\\') { chars.next(); }
                            break;
                        }
                    }
                }
                _ => { chars.next(); } // other ESC sequences: skip next char
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ── radare2 helpers ───────────────────────────────────────────────────────────

// Drain any initial output (banner/prompt) with a short timeout via non-blocking read
fn r2_drain(stdout: &mut BufReader<std::process::ChildStdout>) {
    // r2 -q0 prints a null byte as prompt; consume everything available briefly
    let mut line = String::new();
    // Read until the null-byte prompt line or first empty read
    for _ in 0..32 {
        line.clear();
        match stdout.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) if line.contains('\0') => break,
            _ => {}
        }
    }
}

// ── browser helpers ───────────────────────────────────────────────────────────

fn browser_get(url: &str, cookies: &str) -> Result<(String, Vec<String>, String), String> {
    let mut req = ureq::get(url).set("User-Agent", "Mozilla/5.0 (compatible; offcode/1.0)");
    if !cookies.is_empty() { req = req.set("Cookie", cookies); }
    req.call()
        .map_err(|e| e.to_string())
        .and_then(|resp| {
            let cookie = resp.header("set-cookie").unwrap_or("").to_string();
            let final_url = resp.get_url().to_string();
            resp.into_string()
                .map(|body| (body, if cookie.is_empty() { vec![] } else { vec![cookie] }, final_url))
                .map_err(|e| e.to_string())
        })
}

fn browser_post(url: &str, cookies: &str, body: &str) -> Result<(String, Vec<String>, String), String> {
    let mut req = ureq::post(url)
        .set("User-Agent", "Mozilla/5.0 (compatible; offcode/1.0)")
        .set("Content-Type", "application/x-www-form-urlencoded");
    if !cookies.is_empty() { req = req.set("Cookie", cookies); }
    req.send_string(body)
        .map_err(|e| e.to_string())
        .and_then(|resp| {
            let cookie = resp.header("set-cookie").unwrap_or("").to_string();
            let final_url = resp.get_url().to_string();
            resp.into_string()
                .map(|b| (b, if cookie.is_empty() { vec![] } else { vec![cookie] }, final_url))
                .map_err(|e| e.to_string())
        })
}

fn merge_cookies(jar: &str, new: &[String]) -> String {
    let mut pairs: Vec<(String, String)> = jar.split("; ")
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let mut it = s.splitn(2, '=');
            Some((it.next()?.trim().to_string(), it.next().unwrap_or("").to_string()))
        })
        .collect();

    for set_cookie in new {
        let pair = set_cookie.split(';').next().unwrap_or("").trim();
        if pair.is_empty() { continue; }
        let mut it = pair.splitn(2, '=');
        let name  = it.next().unwrap_or("").trim().to_string();
        let value = it.next().unwrap_or("").to_string();
        if let Some(existing) = pairs.iter_mut().find(|(n, _)| n == &name) {
            existing.1 = value;
        } else {
            pairs.push((name, value));
        }
    }

    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
}

fn resolve_url(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    if href.starts_with("//") {
        let scheme = if base.starts_with("https") { "https" } else { "http" };
        return format!("{scheme}:{href}");
    }
    // Extract origin from base
    if let Some((_, after_scheme)) = base.split_once("://") {
        let origin_end = after_scheme.find('/').map(|i| i + base.find("://").unwrap_or(0) + 3).unwrap_or(base.len());
        let origin = &base[..origin_end];
        if href.starts_with('/') {
            return format!("{origin}{href}");
        }
        // relative path: join with base directory
        let base_dir = base.rfind('/').map(|i| &base[..=i]).unwrap_or(base);
        return format!("{base_dir}{href}");
    }
    href.to_string()
}

fn parse_forms(html: &str) -> Vec<HtmlForm> {
    let mut forms = Vec::new();
    let lower = html.to_lowercase();
    let mut pos = 0;

    while let Some(rel) = lower[pos..].find("<form") {
        let start = pos + rel;
        let tag_end = html[start..].find('>').map(|i| start + i + 1).unwrap_or(html.len());
        let tag = &html[start..tag_end];
        let action = extract_attr(tag, "action").unwrap_or_default();
        let method = extract_attr(tag, "method").unwrap_or_else(|| "get".to_string()).to_lowercase();

        let form_end = lower[tag_end..].find("</form>").map(|i| tag_end + i).unwrap_or(html.len());
        let body = &html[tag_end..form_end];
        let fields = parse_inputs(body);

        forms.push(HtmlForm { action, method, fields });
        pos = form_end + 7;
        if pos >= html.len() { break; }
    }
    forms
}

fn parse_inputs(html: &str) -> Vec<FormField> {
    let mut fields = Vec::new();
    let lower = html.to_lowercase();
    let mut pos = 0;

    // <input ...>
    while let Some(rel) = lower[pos..].find("<input") {
        let start = pos + rel;
        let end = html[start..].find('>').map(|i| start + i + 1).unwrap_or(html.len());
        let tag = &html[start..end];
        let name  = extract_attr(tag, "name").unwrap_or_default();
        let ftype = extract_attr(tag, "type").unwrap_or_else(|| "text".to_string()).to_lowercase();
        let value = extract_attr(tag, "value").unwrap_or_default();
        if !name.is_empty() {
            fields.push(FormField { name, ftype, value });
        }
        pos = end;
        if pos >= html.len() { break; }
    }

    // <textarea name="...">content</textarea>
    let mut pos2 = 0;
    while let Some(rel) = lower[pos2..].find("<textarea") {
        let start = pos2 + rel;
        let gt = html[start..].find('>').map(|i| start + i + 1).unwrap_or(html.len());
        let tag = &html[start..gt];
        let name = extract_attr(tag, "name").unwrap_or_default();
        let end  = lower[gt..].find("</textarea>").map(|i| gt + i).unwrap_or(gt);
        let value = html_text(&html[gt..end]);
        if !name.is_empty() {
            fields.push(FormField { name, ftype: "textarea".to_string(), value });
        }
        pos2 = end + 11;
        if pos2 >= html.len() { break; }
    }

    fields
}

fn forms_summary(forms: &[HtmlForm]) -> String {
    if forms.is_empty() { return String::new(); }
    let mut out = String::from("── Forms ──\n");
    for (i, form) in forms.iter().enumerate() {
        out.push_str(&format!("[{i}] {} {} {}\n", form.method.to_uppercase(), form.action, ""));
        for f in &form.fields {
            if f.ftype == "hidden" { continue; }
            let val = if f.value.is_empty() { String::new() } else { format!(" = \"{}\"", f.value) };
            out.push_str(&format!("    {} ({}){}\n", f.name, f.ftype, val));
        }
    }
    out.trim_end().to_string()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_ddg_html(html: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut pos = 0;

    while count < max && pos < html.len() {
        // Find next result title anchor
        let Some(rel) = html[pos..].find("class=\"result__a\"") else { break };
        let chunk = &html[pos + rel..];

        // Extract href from the tag (search backwards from class= to opening <a)
        let tag_start = chunk[..17].rfind('<').unwrap_or(0);
        let tag = &chunk[tag_start..];
        let href = extract_attr(tag, "href").unwrap_or_default();

        // Extract title text (between > and </a>)
        let title = if let Some(gt) = tag.find('>') {
            let after = &tag[gt + 1..];
            if let Some(end) = after.find("</a>") {
                html_text(&after[..end])
            } else { String::new() }
        } else { String::new() };

        // Advance past this anchor
        let end_a = chunk.find("</a>").map(|i| i + 4).unwrap_or(17);
        pos += rel + end_a;

        // Look for snippet right after (within next 2000 chars)
        let window = html.get(pos..pos + 2000).unwrap_or("");
        let snippet = if let Some(snip_pos) = window.find("result__snippet") {
            let snip = &window[snip_pos..];
            if let Some(gt) = snip.find('>') {
                let after = &snip[gt + 1..];
                if let Some(end) = after.find("</a>") {
                    html_text(&after[..end])
                } else { String::new() }
            } else { String::new() }
        } else { String::new() };

        if title.is_empty() { continue; }

        out.push_str(&format!("{title}\n"));
        if !href.is_empty() { out.push_str(&format!("{href}\n")); }
        if !snippet.is_empty() { out.push_str(&format!("{snippet}\n")); }
        out.push('\n');
        count += 1;
    }

    if out.is_empty() { "No results found.".to_string() } else { out.trim_end().to_string() }
}

// Extract an HTML attribute value (e.g. href="...") from a tag string.
// Resolves DDG redirect URLs (?uddg=...) to the real destination.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')?;
    let raw = html_text(&tag[start..start + end]);

    // DDG wraps real URLs in //duckduckgo.com/l/?uddg=<percent-encoded-url>&rut=...
    if raw.contains("duckduckgo.com/l/") {
        if let Some(uddg_start) = raw.find("uddg=") {
            let encoded = raw[uddg_start + 5..].split('&').next().unwrap_or("");
            return Some(percent_decode(encoded));
        }
    }

    // Promote protocol-relative URLs
    if raw.starts_with("//") {
        return Some(format!("https:{raw}"));
    }

    Some(raw)
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            if let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                out.push(byte as char);
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

// Strip any remaining tags and decode entities from a short string
fn html_text(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            '&' if !in_tag => {
                let mut entity = String::new();
                for ec in chars.by_ref() {
                    if ec == ';' { break; }
                    entity.push(ec);
                }
                out.push_str(match entity.as_str() {
                    "amp" => "&", "lt" => "<", "gt" => ">",
                    "quot" => "\"", "apos" => "'", "nbsp" => " ",
                    _ => { out.push('&'); out.push_str(&entity); out.push(';'); continue; }
                });
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_script = false;
    let mut buf = String::new();

    let mut chars = html.chars().peekable();
    while let Some(c) = chars.next() {
        if in_tag {
            buf.push(c);
            if c == '>' {
                let tag = buf.to_lowercase();
                in_script = tag.starts_with("<script") || tag.starts_with("<style");
                if tag.starts_with("</script") || tag.starts_with("</style") {
                    in_script = false;
                }
                // add newline after block-level closing tags
                if tag.starts_with("</p") || tag.starts_with("</div")
                    || tag.starts_with("</li") || tag.starts_with("<br")
                    || tag.starts_with("</h")
                {
                    out.push('\n');
                }
                buf.clear();
                in_tag = false;
            }
        } else if c == '<' {
            in_tag = true;
            buf.push(c);
        } else if !in_script {
            // decode basic HTML entities
            if c == '&' {
                let mut entity = String::new();
                for ec in chars.by_ref() {
                    if ec == ';' { break; }
                    entity.push(ec);
                }
                let decoded = match entity.as_str() {
                    "amp"  => "&",
                    "lt"   => "<",
                    "gt"   => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    "nbsp" => " ",
                    _      => { out.push('&'); out.push_str(&entity); out.push(';'); continue; }
                };
                out.push_str(decoded);
            } else {
                out.push(c);
            }
        }
    }

    // collapse runs of blank lines
    let mut result = String::new();
    let mut blank_run = 0u32;
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank_run += 1;
            if blank_run <= 1 { result.push('\n'); }
        } else {
            blank_run = 0;
            result.push_str(trimmed);
            result.push('\n');
        }
    }
    result
}

fn sarg(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn coerce_args(v: &Value) -> Value {
    if let Some(s) = v.as_str() {
        serde_json::from_str(s).unwrap_or_else(|_| v.clone())
    } else {
        v.clone()
    }
}

fn is_code_ext(path: &str) -> bool {
    const EXTS: &[&str] = &[
        "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "c", "cpp",
        "h", "hpp", "cs", "rb", "php", "swift", "kt", "scala", "sh", "bash",
        "zsh", "fish", "ps1", "toml", "yaml", "yml", "json", "xml", "html",
        "css", "scss", "sql", "md", "lua", "r", "ex", "exs", "hs",
    ];
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| EXTS.contains(&e))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sandbox_blocks_traversal() {
        assert!(check_command_paths("cat ../../etc/passwd").is_err());
    }

    #[test]
    fn sandbox_blocks_absolute_outside_cwd() {
        assert!(check_command_paths("cat /etc/passwd").is_err());
    }

    #[test]
    fn sandbox_blocks_home_dir() {
        assert!(check_command_paths("ls ~/secret").is_err());
    }

    #[test]
    fn sandbox_allows_system_binaries() {
        assert!(check_command_paths("/usr/bin/grep -r pattern .").is_ok());
    }

    #[test]
    fn sandbox_allows_relative_paths() {
        assert!(check_command_paths("ls -la src/").is_ok());
        assert!(check_command_paths("cargo build").is_ok());
    }

    #[test]
    fn read_file_returns_correct_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, "line one\nline two\nline three").unwrap();

        let result = execute("read_file", &json!({ "path": file.to_str().unwrap() }));

        assert_eq!(result.trim(), "line one\nline two\nline three");
    }
}

fn search_recursive(
    dir: &str,
    pattern: &str,
    ext_filter: Option<&str>,
    depth: usize,
    results: &mut Vec<String>,
) {
    if depth > 6 || results.len() > 500 {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip common noise
        if name.starts_with('.') || matches!(name.as_str(), "target" | "node_modules" | ".git") {
            continue;
        }

        if path.is_dir() {
            search_recursive(
                &path.to_string_lossy(),
                pattern,
                ext_filter,
                depth + 1,
                results,
            );
        } else {
            if let Some(ext) = ext_filter {
                let file_ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                if file_ext != ext {
                    continue;
                }
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                for (lineno, line) in content.lines().enumerate() {
                    if line.to_lowercase().contains(pattern) {
                        results.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            lineno + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
}
