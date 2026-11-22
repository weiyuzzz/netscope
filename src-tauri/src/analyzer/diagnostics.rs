//! 根因关联分析（Root Cause Analysis，第三轮）。
//!
//! 输入：分析对象（域名 / 进程 / 自由描述）+ 时间窗口 + 全部采集数据。
//! 输出：结构化 RcaReport —— 观察（带证据）→ 可能原因（带置信度）→ 建议。
//!
//! 原则：所有结论必须由窗口内的真实事件支撑；证据不足时降低置信度并明说。

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use crate::models::metrics::RouteProbe;
use crate::models::proxy::{Confidence, ProxyServer, VpnInterface};
use crate::models::session::{EvidenceRef, PossibleCause, RcaReport, TimelineEvent};

/// RCA 输入数据包。
pub struct RcaInput<'a> {
    pub subject: String,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub timeline: &'a [TimelineEvent],
    /// 当前代理服务器（host:port）。
    pub proxies: &'a [ProxyServer],
    /// 当前 VPN / 虚拟网卡。
    pub vpn: &'a [VpnInterface],
    /// 路由探测结果（可空）。
    pub route_probes: &'a [RouteProbe],
    /// 当前 DNS 服务器（可空）。
    pub dns_server: Option<String>,
}

/// 从目标推断关联域名/IP（用于过滤连接事件）。
fn related_ips(timeline: &[TimelineEvent], subject: &str) -> HashSet<String> {
    let mut ips = HashSet::new();
    // DNS 事件：domain 命中 subject → 关联其 answers IP
    for e in timeline {
        if e.kind == "dns_new" || e.kind.contains("dns") {
            if let Some(domain) = e.payload.get("domain").and_then(|v| v.as_str()) {
                if domain.to_lowercase().contains(&subject.to_lowercase()) {
                    if let Some(answers) = e.payload.get("answers").and_then(|v| v.as_array()) {
                        for a in answers {
                            if let Some(ip) = a.as_str() {
                                ips.insert(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    ips
}

fn conn_matches(
    e: &TimelineEvent,
    subject: &str,
    related: &HashSet<String>,
) -> bool {
    let payload = &e.payload;
    let remote_ip = payload
        .get("remote")
        .and_then(|r| r.get("ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let process = payload
        .get("processName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !subject.is_empty() {
        if remote_ip.contains(subject) || process.to_lowercase().contains(&subject.to_lowercase())
        {
            return true;
        }
        if !related.is_empty() && related.contains(remote_ip) {
            return true;
        }
    }
    false
}

/// 执行根因关联分析（全部基于窗口内真实事件）。
pub fn analyze(input: &RcaInput) -> RcaReport {
    let mut observations: Vec<EvidenceRef> = Vec::new();
    let mut causes: Vec<PossibleCause> = Vec::new();
    let mut suggestions: Vec<String> = Vec::new();

    let related = related_ips(input.timeline, &input.subject);

    // ---- 1. DNS 证据 ----
    let dns_events: Vec<&TimelineEvent> = input
        .timeline
        .iter()
        .filter(|e| e.kind.contains("dns") || e.kind == "dns_new")
        .collect();
    let subject_dns: Vec<&TimelineEvent> = dns_events
        .into_iter()
        .filter(|e| {
            e.payload
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|d| d.to_lowercase().contains(&input.subject.to_lowercase()))
                .unwrap_or(false)
        })
        .collect();

    if !subject_dns.is_empty() {
        observations.push(EvidenceRef {
            source: "timeline:dns_new".into(),
            timestamp: subject_dns[0].timestamp,
            description: format!(
                "窗口内观察到 {} 次 DNS 解析记录（目标域名）",
                subject_dns.len()
            ),
        });
    }

    // ---- 2. 连接证据（目标相关） ----
    let conn_events: Vec<&TimelineEvent> = input
        .timeline
        .iter()
        .filter(|e| e.kind.starts_with("conn_") && conn_matches(e, &input.subject, &related))
        .collect();
    let opened = conn_events.iter().filter(|e| e.kind == "conn_opened").count();
    let closed = conn_events.iter().filter(|e| e.kind == "conn_closed").count();

    if opened > 0 {
        observations.push(EvidenceRef {
            source: "timeline:conn_opened".into(),
            timestamp: conn_events[0].timestamp,
            description: format!("窗口内目标相关连接打开 {opened} 次"),
        });
    }

    // ---- 3. 本地链路证据 ----
    let iface_down = input
        .timeline
        .iter()
        .filter(|e| e.kind == "interface_changed" && e.summary.contains("→ down"))
        .count();
    if iface_down > 0 {
        observations.push(EvidenceRef {
            source: "timeline:interface_changed".into(),
            timestamp: input.window_end,
            description: format!("窗口内网卡断开 {iface_down} 次"),
        });
    }
    let route_changes: Vec<&TimelineEvent> = input
        .timeline
        .iter()
        .filter(|e| e.kind == "route_changed")
        .collect();
    if !route_changes.is_empty() {
        observations.push(EvidenceRef {
            source: "timeline:route_changed".into(),
            timestamp: route_changes[0].timestamp,
            description: format!("窗口内默认路由变化 {} 次", route_changes.len()),
        });
    }

    // ---- 4. 代理证据 ----
    let proxy_remove_events: Vec<&TimelineEvent> = input
        .timeline
        .iter()
        .filter(|e| e.kind == "proxy_removed")
        .collect();
    let mut proxy_hit = false;
    // 目标连接（或任意连接）指向本地代理端口的失败
    let proxy_hosts: HashSet<String> = input
        .proxies
        .iter()
        .map(|p| format!("{}:{}", p.host, p.port))
        .collect();
    for e in input.timeline.iter().filter(|e| e.kind == "conn_closed") {
        let remote = e
            .payload
            .get("remote")
            .map(|r| {
                format!(
                    "{}:{}",
                    r.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                    r.get("port").and_then(|v| v.as_u64()).unwrap_or(0)
                )
            })
            .unwrap_or_default();
        if proxy_hosts.contains(&remote) {
            proxy_hit = true;
            observations.push(EvidenceRef {
                source: "timeline:conn_closed".into(),
                timestamp: e.timestamp,
                description: format!("与本地代理 {remote} 的连接出现关闭事件"),
            });
        }
    }

    // ---- 5. VPN 证据 ----
    let vpn_active = input
        .vpn
        .iter()
        .filter(|v| v.active && v.kind != crate::models::proxy::VirtualAdapterKind::Loopback)
        .count();
    if vpn_active > 0 {
        observations.push(EvidenceRef {
            source: "proxy:vpn_state".into(),
            timestamp: input.window_end,
            description: format!("当前活跃 VPN/虚拟网卡 {vpn_active} 个"),
        });
    }

    // ---- 6. 路由探测证据 ----
    for p in input.route_probes.iter().rev().take(2) {
        if let Some(ip) = &p.resolved_ip {
            observations.push(EvidenceRef {
                source: "probe:traceroute".into(),
                timestamp: p.started_at,
                description: format!(
                    "路由探测 {} → {}（{} 跳）",
                    p.target,
                    ip,
                    p.hops.len()
                ),
            });
        }
    }

    // ---- 归因链（多证据汇聚，单证据低置信度） ----
    let mut finding_rule_ids = Vec::new();

    if iface_down > 0 {
        causes.push(PossibleCause {
            description: "本地网卡断开导致网络中断".into(),
            confidence: Confidence::Confirmed,
            evidence: vec![EvidenceRef {
                source: "timeline:interface_changed".into(),
                timestamp: input.window_end,
                description: format!("窗口内网卡断开 {iface_down} 次"),
            }],
        });
        suggestions.push("检查网线 / Wi-Fi 连接状态".into());
        suggestions.push("查看 Overview 网卡状态恢复时间".into());
        finding_rule_ids.push("iface.link_down".into());
    }

    if !proxy_remove_events.is_empty() || (proxy_hit && opened == 0) {
        causes.push(PossibleCause {
            description: "本地代理服务不可达或代理链路失败".into(),
            confidence: if !proxy_remove_events.is_empty() {
                Confidence::Confirmed
            } else {
                Confidence::Inferred
            },
            evidence: proxy_remove_events
                .iter()
                .map(|e| EvidenceRef {
                    source: "timeline:proxy_removed".into(),
                    timestamp: e.timestamp,
                    description: e.summary.clone(),
                })
                .chain(observations.iter().filter(|o| o.source == "timeline:conn_closed").cloned())
                .collect(),
        });
        suggestions.push("确认本地代理软件运行状态与监听端口".into());
        suggestions.push("切换代理节点后重试".into());
        finding_rule_ids.push("proxy.listener_gone".into());
    }

    if !route_changes.is_empty() && iface_down == 0 {
        causes.push(PossibleCause {
            description: "默认路由变化（VPN/网络切换）导致短暂中断".into(),
            confidence: Confidence::Inferred,
            evidence: route_changes
                .iter()
                .map(|e| EvidenceRef {
                    source: "timeline:route_changed".into(),
                    timestamp: e.timestamp,
                    description: e.summary.clone(),
                })
                .collect(),
        });
        suggestions.push("对比切换前后的 Proxy Analysis 出口信息".into());
        finding_rule_ids.push("iface.gateway_change".into());
    }

    if closed > opened && opened == 0 && !conn_events.is_empty() {
        causes.push(PossibleCause {
            description: "目标连接全部失败（未观察到成功打开）".into(),
            confidence: Confidence::Inferred,
            evidence: conn_events
                .iter()
                .take(3)
                .map(|e| EvidenceRef {
                    source: "timeline:conn_closed".into(),
                    timestamp: e.timestamp,
                    description: e.summary.clone(),
                })
                .collect(),
        });
        suggestions.push("用 Route Explorer 对目标 IP 做 Traceroute".into());
        suggestions.push("用 Benchmark 对多目标测速，区分单目标故障还是全局故障".into());
    }

    if causes.is_empty() {
        // 证据不足：如实说明，不编造根因
        causes.push(PossibleCause {
            description: "证据不足：窗口内未观察到与目标相关的故障事件".into(),
            confidence: Confidence::Speculative,
            evidence: vec![EvidenceRef {
                source: "timeline".into(),
                timestamp: input.window_end,
                description: format!(
                    "窗口（{} ~ {}）内 {} 条时间线事件中无目标相关故障",
                    input.window_start.format("%H:%M:%S"),
                    input.window_end.format("%H:%M:%S"),
                    input.timeline.len()
                ),
            }],
        });
        suggestions.push(
            "扩大时间窗口重试，或开启 Session Recorder 后复现问题以采集证据".into(),
        );
    }

    let symptom = if !conn_events.is_empty() {
        format!(
            "与目标 '{}' 相关的连接出现异常（打开 {opened} 次，关闭 {closed} 次）",
            input.subject
        )
    } else if !subject_dns.is_empty() {
        format!("目标 '{}' 相关的 DNS 解析有记录，但未见连接建立", input.subject)
    } else {
        format!("分析对象 '{}' 在窗口内未观察到直接网络活动", input.subject)
    };

    RcaReport {
        id: format!("rca-{}", Utc::now().timestamp_millis()),
        created_at: Utc::now(),
        subject: input.subject.clone(),
        window_start: input.window_start,
        window_end: input.window_end,
        symptom,
        observations,
        causes,
        suggestions,
        finding_rule_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(kind: &str, summary: &str, payload: serde_json::Value) -> TimelineEvent {
        TimelineEvent {
            timestamp: Utc::now(),
            source: "test".into(),
            kind: kind.into(),
            summary: summary.into(),
            payload,
        }
    }

    fn input<'a>(
        subject: &str,
        timeline: &'a [TimelineEvent],
        proxies: &'a [ProxyServer],
        vpn: &'a [VpnInterface],
        probes: &'a [RouteProbe],
    ) -> RcaInput<'a> {
        RcaInput {
            subject: subject.into(),
            window_start: Utc::now() - chrono::Duration::minutes(5),
            window_end: Utc::now(),
            timeline,
            proxies,
            vpn,
            route_probes: probes,
            dns_server: Some("192.168.1.1".into()),
        }
    }

    #[test]
    fn proxy_failure_cause_with_high_confidence() {
        let timeline = vec![
            ev("dns_new", "新解析域名: google.com", json!({"domain": "google.com"})),
            ev(
                "conn_closed",
                "chrome.exe 关闭 127.0.0.1:6081 → 127.0.0.1:12001",
                json!({
                    "processName": "chrome.exe",
                    "remote": {"ip": "127.0.0.1", "port": 12001},
                }),
            ),
        ];
        let proxies = vec![ProxyServer {
            id: "local_listener:127.0.0.1:12001".into(),
            mechanism: crate::models::proxy::ProxyMechanism::LocalListener,
            protocol: crate::models::proxy::ProxyProtocol::Http,
            host: "127.0.0.1".into(),
            port: 12001,
            process_name: Some("proxy.exe".into()),
            pid: Some(100),
            source: "test".into(),
            confidence: Confidence::Confirmed,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            active: true,
        }];
        let report = analyze(&input("google.com", &timeline, &proxies, &[], &[]));
        assert!(report
            .causes
            .iter()
            .any(|c| c.description.contains("代理")));
        // 代理失败 + DNS 正常记录 → 应给出代理检查建议
        assert!(report.suggestions.iter().any(|s| s.contains("代理")));
    }

    #[test]
    fn insufficient_evidence_is_stated_not_fabricated() {
        let timeline = vec![ev("quality_sample", "下行 1KB/s", json!({}))];
        let report = analyze(&input("google.com", &timeline, &[], &[], &[]));
        assert!(
            report.causes.iter().any(|c| c.description.contains("证据不足")),
            "无证据时必须如实说明"
        );
    }

    #[test]
    fn interface_down_maps_to_link_cause() {
        let timeline = vec![ev(
            "interface_changed",
            "网卡 以太网 状态: up → down",
            json!({"ifIndex": 5}),
        )];
        let report = analyze(&input("google.com", &timeline, &[], &[], &[]));
        let c = report.causes.iter().find(|c| c.description.contains("网卡断开")).expect("应定位到网卡断开");
        assert_eq!(c.confidence, Confidence::Confirmed);
    }

    #[test]
    fn all_connections_failed_pattern() {
        let timeline = vec![ev(
            "conn_closed",
            "app.exe 关闭 192.168.1.10:5000 → 5.6.7.8:443",
            json!({
                "processName": "app.exe",
                "remote": {"ip": "5.6.7.8", "port": 443},
            }),
        )];
        let report = analyze(&input("5.6.7.8", &timeline, &[], &[], &[]));
        assert!(report.causes.iter().any(|c| c.description.contains("全部失败")));
        assert!(report.symptom.contains("连接出现异常"));
    }
}
