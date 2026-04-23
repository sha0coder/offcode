use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub model: String,
    pub ollama_url: String,
    pub system_prompt: String,
    pub compact_prompt: String,
    pub temperature: f64,
    pub num_ctx: u32,
    pub show_thinking: bool,
    pub max_tool_iters: u32,
    #[serde(default = "default_yolo")]
    pub yolo: bool,
    #[serde(default = "default_auto_approve")]
    pub auto_approve_tools: Vec<String>,
    #[serde(default = "default_tts")]
    pub tts: bool,
    #[serde(default = "default_tts_lang")]
    pub tts_lang: String,
    #[serde(default = "default_stt")]
    pub stt: bool,
    #[serde(default = "default_stt_cmd")]
    pub stt_cmd: String,
    #[serde(default = "default_rec_cmd")]
    pub rec_cmd: String,
    #[serde(skip)]
    pub no_ctx: bool,
}

fn default_yolo() -> bool { false }
fn default_tts() -> bool { false }
fn default_tts_lang() -> String { "es".to_string() }
fn default_stt() -> bool { false }
fn default_stt_cmd() -> String { String::new() }  // user must configure model path
fn default_rec_cmd() -> String {
    if cfg!(target_os = "macos") {
        "sox rec -r 16000 -c 1 -b 16 -e signed-integer".to_string()
    } else {
        "arecord -r 16000 -c 1 -f S16_LE".to_string()
    }
}

fn default_auto_approve() -> Vec<String> {
    vec!["read_file".into(), "list_dir".into(), "search_files".into(), "path_info".into()]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            model: "gemma4:e4b".to_string(),
            ollama_url: "http://localhost:11434".to_string(),
            system_prompt: concat!(
                "You are offcode, an offline AI coding assistant running locally via Ollama. ",
                "Help the user with software development: reading code, writing files, running commands, ",
                "debugging, refactoring, and implementing features. ",
                "You have FULL access to the user's current directory via tools: use read_file to read any file, ",
                "list_dir to explore the project, search_files to find code, and write_file to make changes. ",
                "NEVER ask the user to paste code or file contents — always read them yourself with the tools. ",
                "Use the provided tools whenever you need to interact with the filesystem or shell. ",
                "Be concise, accurate, and practical. ",
                "At the start of every session, always run list_dir on '.' first to understand the project structure."
            ).to_string(),
            compact_prompt: crate::COMPACT_PROMPT.to_string(),
            temperature: 0.6,
            num_ctx: 16384,
            show_thinking: false,
            max_tool_iters: 30,
            yolo: false,
            auto_approve_tools: default_auto_approve(),
            tts: false,
            tts_lang: default_tts_lang(),
            stt: false,
            stt_cmd: default_stt_cmd(),
            rec_cmd: default_rec_cmd(),
            no_ctx: false,
        }
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("offcode")
            .join("config.toml")
    }

    pub fn is_auto_approved(&self, tool_name: &str) -> bool {
        self.yolo || self.auto_approve_tools.iter().any(|t| t == tool_name)
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            match toml::from_str::<Config>(&content) {
                Ok(c) => return c,
                Err(e) => eprintln!("Warning: config parse error ({e}), using defaults"),
            }
        }
        let cfg = Self::default();
        cfg.save();
        cfg
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(s) = toml::to_string_pretty(self) {
            let _ = std::fs::write(&path, s);
        }
    }
}
