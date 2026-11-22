//! AI Provider 抽象（可替换：离线 / OpenAI 兼容 / 本地服务）。

use serde_json::json;

/// 聊天 Provider trait。
pub trait ChatProvider: Send {
    fn chat(&self, system: &str, user: &str) -> Result<String, String>;
    fn name(&self) -> String;
}

/// 离线 Provider：不调用任何模型，仅对检索到的证据做确定性重组。
/// 明确声明"离线模式"，不编造任何超出证据的结论。
pub struct OfflineProvider;

impl ChatProvider for OfflineProvider {
    fn chat(&self, _system: &str, user: &str) -> Result<String, String> {
        // user 消息即"问题 + 检索到的证据 JSON"——离线模式做结构化摘要
        Ok(format!(
            "【离线证据模式】未配置语言模型，以下为按规则检索到的结构化证据摘要（不含模型推断）。\n\n\
             {user}\n\n\
             提示：如需自然语言根因分析，请在 Settings 中配置 AI Provider \
             （支持 OpenAI 兼容 API 与本地模型如 Ollama）。所有回答均仅基于上述证据；\
             证据不足的部分无法确定。\n\
             （NetScope 不会通过 AI 自动修改任何网络配置。）"
        ))
    }

    fn name(&self) -> String {
        "offline(证据摘要)".into()
    }
}

/// OpenAI 兼容 Provider（含本地模型服务）。
pub struct OpenAiProvider {
    base_url: String,
    api_key: Option<String>,
    model: String,
}

impl OpenAiProvider {
    pub fn new(base_url: String, api_key: Option<String>, model: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            model,
        }
    }

    /// 解析 chat/completions 响应中的回答文本。
    pub fn parse_response(body: &str) -> Option<String> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        let content = v
            .get("choices")?
            .get(0)?
            .get("message")?
            .get("content")?
            .as_str()?
            .to_string();
        Some(content)
    }
}

impl ChatProvider for OpenAiProvider {
    fn chat(&self, system: &str, user: &str) -> Result<String, String> {
        if self.base_url.is_empty() {
            return Err("未配置 AI base_url（Settings 中设置 OpenAI 兼容端点）".into());
        }
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};

        let body = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
            "temperature": 0.2,
        })
        .to_string();

        let tmp = std::env::temp_dir().join(format!("ns_ai_{}.json", std::process::id()));
        std::fs::write(&tmp, body).map_err(|e| format!("写请求体失败: {e}"))?;

        let mut cmd = Command::new("curl.exe");
        let mut args = vec![
            "-s".to_string(),
            "--max-time".to_string(),
            "90".to_string(),
            "-X".to_string(),
            "POST".to_string(),
            "-H".to_string(),
            "Content-Type: application/json".to_string(),
            "--data-binary".to_string(),
            format!("@{}", tmp.display()),
            "-o".to_string(),
            "-".to_string(),
            format!("{}/chat/completions", self.base_url),
        ];
        if let Some(key) = &self.api_key {
            args.push("-H".to_string());
            args.push(format!("Authorization: Bearer {key}"));
        }
        cmd.args(&args)
            .creation_flags(0x0800_0000)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let out = cmd.output().map_err(|e| format!("curl 执行失败: {e}"))?;
        let _ = std::fs::remove_file(&tmp);

        let body = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            return Err(format!(
                "AI 端点请求失败（curl 退出码 {}，响应 {:.120}）",
                out.status.code().unwrap_or(-1),
                body
            ));
        }
        Self::parse_response(&body).ok_or_else(|| {
            format!("AI 响应格式无法解析（{:.160}）", body)
        })
    }

    fn name(&self) -> String {
        format!("openai-compatible({})", self.model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_provider_states_honestly() {
        let p = OfflineProvider;
        let answer = p.chat("s", "证据：...").unwrap();
        assert!(answer.contains("离线"));
        assert!(answer.contains("无法确定") || answer.contains("仅基于上述证据"));
        assert!(answer.contains("不会通过 AI 自动修改"));
    }

    #[test]
    fn parse_response_extracts_content() {
        let body = r#"{"choices":[{"message":{"content":"分析结果"}}]}"#;
        assert_eq!(OpenAiProvider::parse_response(body).unwrap(), "分析结果");
        assert!(OpenAiProvider::parse_response("{\"bad\":1}").is_none());
    }
}
