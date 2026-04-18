use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub model: String,
    pub ollama_url: String,
    pub system_prompt: String,
    pub temperature: f64,
    pub num_ctx: u32,
    pub show_thinking: bool,
    pub max_tool_iters: u32,
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
                "Use the provided tools whenever you need to interact with the filesystem or shell. ",
                "Be concise, accurate, and practical."
            ).to_string(),
            temperature: 0.6,
            num_ctx: 16384,
            show_thinking: false,
            max_tool_iters: 30,
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
