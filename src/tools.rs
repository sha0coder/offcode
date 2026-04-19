use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

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
                "description": "Write (or overwrite) a file with the given content. Creates parent dirs automatically.",
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
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
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

        _ => format!("Unknown tool '{name}'"),
    }
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
        ("delete_path",  "Delete a file or empty directory"),
        ("path_info",    "File/directory metadata"),
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
