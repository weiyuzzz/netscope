//! 第三轮：网络历史 / 会话录制 / 诊断 / 基准测试 / AI 模型。
//!
//! 准确性约定：
//! - 历史回放必须基于当时保存的事件重建，不得用当前连接状态冒充历史状态；
//! - 诊断结论必须引用证据（时间 + 来源），单指标不得得出确定性根因；
//! - AI 只能访问已采集的结构化数据，证据不足时必须明说，不得编造。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::proxy::Confidence;

// ---------------------------------------------------------------------------
// 会话录制
// ---------------------------------------------------------------------------

/// 会话范围（录制时的过滤条件）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum SessionScope {
    /// 全部网络活动。
    All,
    /// 指定进程（按进程名，如 "chrome.exe"）。
    Process { name: String },
    /// 指定域名（及其解析 IP 的连接）。
    Domain { domain: String },
}

impl SessionScope {
    /// 判断某事件载荷是否命中范围（载荷为序列化后的 JSON 对象）。
    pub fn matches(&self, payload: &serde_json::Value) -> bool {
        match self {
            SessionScope::All => true,
            SessionScope::Process { name } => payload
                .get("processName")
                .and_then(|v| v.as_str())
                .map(|p| p.eq_ignore_ascii_case(name))
                .unwrap_or(false),
            SessionScope::Domain { domain } => payload
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|d| d.to_lowercase().contains(&domain.to_lowercase()))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Recording,
    Completed,
    Cancelled,
}

/// 一次网络测试录制任务。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingSession {
    pub id: String,
    pub name: String,
    pub scope: SessionScope,
    pub started_at: DateTime<Utc>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub status: SessionStatus,
    /// 录制的事件数（停止时统计）。
    pub event_count: u64,
    /// 任务类型（browser / vpn / download / network_switch / custom）。
    pub test_kind: String,
}

/// 会话内的一条事件（统一时间线事件的会话级副本）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEvent {
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub kind: String,
    pub summary: String,
    pub payload: serde_json::Value,
}

// ---------------------------------------------------------------------------
// 统一时间线 + 拓扑历史
// ---------------------------------------------------------------------------

/// 全局网络事件时间线条目（History & Replay 数据源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub kind: String,
    /// 人类可读摘要（时间线直接展示）。
    pub summary: String,
    /// 结构化载荷（回放重建用）。
    pub payload: serde_json::Value,
}

/// 拓扑历史快照（周期性落库，回放的基底）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyHistorySnapshot {
    pub timestamp: DateTime<Utc>,
    pub nodes: Vec<crate::models::topology::TopologyNode>,
    pub edges: Vec<crate::models::topology::TopologyEdge>,
}

// ---------------------------------------------------------------------------
// 诊断规则引擎
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// 证据引用（诊断结论的最小支撑单元）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRef {
    /// 证据来源（如 "timeline:dns_new" / "capture:retransmit" / "probe:ping"）。
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

/// 一条诊断结论。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub detected_at: DateTime<Utc>,
    pub impact_processes: Vec<String>,
    pub impact_domains: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
    pub possible_causes: Vec<String>,
    pub verification: Vec<String>,
}

/// 诊断规则元数据（存储层注册，供 UI 开关）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticRuleMeta {
    pub rule_id: String,
    pub category: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// 根因分析
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PossibleCause {
    pub description: String,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RcaReport {
    pub id: String,
    pub created_at: DateTime<Utc>,
    /// 分析对象（域名 / 进程 / 描述）。
    pub subject: String,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub symptom: String,
    pub observations: Vec<EvidenceRef>,
    pub causes: Vec<PossibleCause>,
    pub suggestions: Vec<String>,
    /// 引用的诊断 findings。
    pub finding_rule_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// 基准测试
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkKind {
    Ping,
    Dns,
    TcpConnect,
    Http,
    Download,
    Upload,
}

/// 一次基准测试记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkResult {
    pub id: String,
    pub kind: BenchmarkKind,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// 出口网卡（可获取时）。
    pub interface: Option<String>,
    /// 代理模式提示（可获取时）。
    pub proxy_mode: Option<String>,
    pub egress_ip: Option<String>,
    pub dns_server: Option<String>,
    /// 指标（按 kind 不同：延迟统计 / 成功率 / 速度 / HTTP 分段耗时）。
    pub metrics: serde_json::Value,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// AI 助手
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    /// 离线模式：不调用任何模型，仅输出检索到的证据摘要（默认）。
    Offline,
    /// OpenAI 兼容 API（含本地 Ollama / LM Studio 等）。
    OpenAiCompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfig {
    pub kind: AiProviderKind,
    /// OpenAI 兼容端点（如 http://127.0.0.1:11434/v1）。
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            kind: AiProviderKind::Offline,
            base_url: None,
            api_key: None,
            model: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConversation {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub provider: String,
    pub question: String,
    pub answer: String,
    /// 检索到的证据（时间线/诊断/质量）摘要。
    pub evidence_used: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matching() {
        let payload = serde_json::json!({ "processName": "chrome.exe", "domain": "google.com" });
        assert!(SessionScope::All.matches(&payload));
        assert!(SessionScope::Process { name: "Chrome.exe".into() }.matches(&payload));
        assert!(SessionScope::Domain { domain: "google".into() }.matches(&payload));
        assert!(!SessionScope::Process { name: "firefox.exe".into() }.matches(&payload));
        assert!(!SessionScope::Domain { domain: "bing.com".into() }.matches(&payload));
    }

    #[test]
    fn scope_tagged_serialization() {
        let s = serde_json::to_string(&SessionScope::Domain { domain: "a.com".into() }).unwrap();
        assert!(s.contains("\"mode\":\"domain\""));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    #[test]
    fn ai_config_default_is_offline() {
        let c = AiConfig::default();
        assert_eq!(c.kind, AiProviderKind::Offline);
        assert!(c.base_url.is_none());
    }
}
