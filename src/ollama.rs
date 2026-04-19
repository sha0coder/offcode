use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

// ── public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    #[serde(default)]
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    #[serde(default)]
    pub id: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: Value,
    // Ollama may include an "index" field; accept but ignore it
    #[allow(dead_code)]
    #[serde(default, skip_serializing)]
    pub index: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
    pub options: Options,
}

#[derive(Debug, Clone, Serialize)]
pub struct Options {
    pub temperature: f64,
    pub num_ctx: u32,
}

// ── model listing (/api/tags, /api/show) ─────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<ModelInfo>,
}

#[derive(Debug, Deserialize)]
struct ShowResponse {
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ModelCaps {
    pub tools: bool,
    pub thinking: bool,
    pub vision: bool,
}

// ── internal deserialization ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawChunk {
    message: RawMessage,
    #[serde(default)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    // Actual response text
    #[serde(default)]
    content: String,
    // Qwen3 / Ollama native thinking field (separate from content)
    #[serde(default)]
    thinking: Option<String>,
    // Tool call requests from the model (come in a done=false chunk)
    #[serde(default)]
    tool_calls: Option<Vec<ToolCall>>,
}

// ── Ollama client ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base_url: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(600))
            .build();
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            agent,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.agent
            .get(&format!("{}/api/tags", self.base))
            .call()
            .is_ok()
    }

    /// Fetch the list of locally available models via /api/tags.
    pub fn list_models(&self) -> Result<Vec<ModelInfo>, String> {
        let url = format!("{}/api/tags", self.base);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| format!("Failed to fetch models: {e}"))?;
        let body: TagsResponse = resp
            .into_json()
            .map_err(|e| format!("Failed to parse models: {e}"))?;
        Ok(body.models)
    }

    /// Query /api/show for a model and extract the capability flags we care about.
    pub fn model_capabilities(&self, name: &str) -> ModelCaps {
        let url = format!("{}/api/show", self.base);
        let req = serde_json::json!({ "name": name });
        let resp = match self.agent.post(&url).send_json(&req) {
            Ok(r) => r,
            Err(_) => return ModelCaps::default(),
        };
        let show: ShowResponse = match resp.into_json() {
            Ok(s) => s,
            Err(_) => return ModelCaps::default(),
        };
        let mut caps = ModelCaps::default();
        for c in &show.capabilities {
            match c.as_str() {
                "tools" => caps.tools = true,
                "thinking" => caps.thinking = true,
                "vision" => caps.vision = true,
                _ => {}
            }
        }
        caps
    }
}

/// Format a size in bytes as a human-readable string.
pub fn format_size(bytes: u64) -> String {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.0} MB", b / MB)
    } else {
        format!("{bytes} B")
    }
}

/// Build a human-readable listing of models, one row per line.
/// The selected model is marked with `●` and bolded by the caller.
pub fn format_model_listing(
    models: &[ModelInfo],
    caps: &[ModelCaps],
    selected: &str,
) -> Vec<(String, bool)> {
    let name_w = models.iter().map(|m| m.name.len()).max().unwrap_or(20).max(20);
    let mut out = Vec::with_capacity(models.len());
    for (m, c) in models.iter().zip(caps.iter()) {
        let is_sel = m.name == selected;
        let mark = if is_sel { "●" } else { " " };
        let t = if c.tools { "🛠 " } else { "  " };
        let k = if c.thinking { "🧠" } else { "  " };
        let v = if c.vision { "👁 " } else { "  " };
        let size = format_size(m.size);
        let line = format!(
            "{mark} {name:<nw$}  {size:>10}  {t} {k} {v}",
            mark = mark,
            name = m.name,
            size = size,
            t = t,
            k = k,
            v = v,
            nw = name_w,
        );
        out.push((line, is_sel));
    }
    out
}

impl Client {
    /// Stream a chat response.
    ///
    /// `show_thinking` – if true, thinking tokens are also forwarded to `on_token`
    /// (displayed dim in the caller).
    ///
    /// Returns `(content, tool_calls)`:
    /// - `content`    – accumulated visible text (may be empty when tool calls fired)
    /// - `tool_calls` – Some(...) when the model wants to invoke tools
    pub fn chat_stream<F>(
        &self,
        request: &ChatRequest,
        show_thinking: bool,
        cancel: Arc<AtomicBool>,
        mut on_token: F,
    ) -> Result<(String, Option<Vec<ToolCall>>), String>
    where
        F: FnMut(&str, bool), // (token, is_thinking)
    {
        let mut req = request.clone();
        req.stream = true;

        let url = format!("{}/api/chat", self.base);
        let resp = match self.agent.post(&url).send_json(&req) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                return Err(format!("Ollama {code}: {body}"));
            }
            Err(e) => return Err(format!("Connection error: {e}")),
        };

        let reader = BufReader::new(resp.into_reader());
        let mut content = String::new();
        let mut tool_calls: Option<Vec<ToolCall>> = None;

        for line in reader.lines() {
            if cancel.load(Ordering::Relaxed) {
                return Err("__cancelled__".into());
            }

            let line = line.map_err(|e| format!("Stream read error: {e}"))?;
            if line.is_empty() {
                continue;
            }

            let chunk: RawChunk = serde_json::from_str(&line)
                .map_err(|e| format!("Stream parse error: {e}"))?;

            // Thinking tokens (Ollama native thinking field, e.g. Qwen3)
            if show_thinking {
                if let Some(ref t) = chunk.message.thinking {
                    if !t.is_empty() {
                        on_token(t, true);
                    }
                }
            }

            // Response content tokens
            if !chunk.message.content.is_empty() {
                on_token(&chunk.message.content.clone(), false);
                content.push_str(&chunk.message.content);
            }

            // Tool calls arrive in a pre-done chunk (done=false)
            if let Some(tc) = chunk.message.tool_calls {
                if !tc.is_empty() {
                    tool_calls = Some(tc);
                }
            }

            if chunk.done {
                break;
            }
        }

        Ok((content, tool_calls))
    }
}
