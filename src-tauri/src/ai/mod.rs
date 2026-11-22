//! AI 网络助手（第三轮）。
//!
//! 硬性规则（写入 system prompt，且由检索层强制）：
//! 1. 先检索证据，再分析原因；
//! 2. 引用事件时间与数据来源；
//! 3. 明确区分事实与推测；
//! 4. 证据不足时必须说明"无法确定"；
//! 5. 不得自动修改网络配置；任何修复操作都需要用户明确确认。
//!
//! Provider 可替换：离线模式（默认，仅证据摘要，不调用任何模型）、
//! OpenAI 兼容 API（含本地 Ollama / LM Studio 等，经系统 curl 调用）。

pub mod assistant;
pub mod provider;

use crate::models::session::AiConfig;

pub use provider::{ChatProvider, OfflineProvider, OpenAiProvider};
pub use assistant::ask;

/// 按配置构造 Provider。
pub fn from_config(cfg: &AiConfig) -> Box<dyn ChatProvider> {
    match cfg.kind {
        crate::models::session::AiProviderKind::OpenAiCompatible => {
            Box::new(OpenAiProvider::new(
                cfg.base_url.clone().unwrap_or_default(),
                cfg.api_key.clone(),
                cfg.model.clone().unwrap_or_else(|| "gpt-4o-mini".into()),
            ))
        }
        crate::models::session::AiProviderKind::Offline => Box::new(OfflineProvider),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_yields_offline_provider() {
        let p = from_config(&AiConfig::default());
        assert!(p.name().contains("offline") || p.name().contains("离线"));
    }

    #[test]
    fn openai_provider_requires_base_url() {
        let p = OpenAiProvider::new(String::new(), None, "m".into());
        assert!(p.chat("s", "u").is_err(), "无 base_url 必须报错而非编造回答");
    }
}
