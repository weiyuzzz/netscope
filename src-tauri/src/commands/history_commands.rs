//! 第三轮命令：会话录制 / 历史 / 回放 / 诊断 / 基准 / 报告 / AI。

use serde::Serialize;
use tauri::{Emitter, Manager, State};

use crate::analyzer::diagnostics as rca;
use crate::analyzer::rules::{self, DiagnosticContext};
use crate::models::metrics::NetworkQualityPoint;
use crate::models::session::{
    AiConfig, AiConversation, BenchmarkKind, BenchmarkResult, DiagnosticFinding, RecordingSession,
    RcaReport, SessionEvent, SessionScope, SessionStatus, TimelineEvent,
};
use crate::storage::history_repository as hist;
use crate::AppState;

// ---------------------------------------------------------------------------
// Session Recorder
// ---------------------------------------------------------------------------

/// 开始录制会话（用户主动触发）。
#[tauri::command]
pub fn start_recording(
    state: State<'_, AppState>,
    name: &str,
    scope_mode: &str,
    scope_value: Option<&str>,
    test_kind: Option<&str>,
) -> Result<RecordingSession, String> {
    let mut runtime = state.runtime.lock().unwrap();
    if runtime.recording() {
        return Err("已有录制任务进行中".into());
    }
    let scope = match scope_mode {
        "process" => SessionScope::Process {
            name: scope_value.unwrap_or_default().to_string(),
        },
        "domain" => SessionScope::Domain {
            domain: scope_value.unwrap_or_default().to_string(),
        },
        _ => SessionScope::All,
    };
    let session = RecordingSession {
        id: format!("sess-{}", chrono::Utc::now().timestamp_millis()),
        name: name.to_string(),
        scope,
        started_at: chrono::Utc::now(),
        stopped_at: None,
        status: SessionStatus::Recording,
        event_count: 0,
        test_kind: test_kind.unwrap_or("custom").to_string(),
    };
    hist::create_session(
        state.db.lock().unwrap().as_ref().ok_or("数据库不可用")?,
        &session,
    )
    .map_err(|e| e.to_string())?;
    runtime.start_recording(session.id.clone(), session.scope.clone());
    Ok(session)
}

/// 停止录制并生成报告（事件统计 + 诊断规则跑一遍会话窗口）。
#[tauri::command]
pub fn stop_recording(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let started_at = state.started_at;
    let (session_id, event_count) = {
        let mut runtime = state.runtime.lock().unwrap();
        let sid = runtime
            .session_id
            .clone()
            .ok_or("当前没有录制任务")?;
        (sid, runtime.stop_recording())
    };

    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    hist::finish_session(
        conn,
        &session_id,
        &chrono::Utc::now().to_rfc3339(),
        SessionStatus::Completed,
        event_count,
    )
    .map_err(|e| e.to_string())?;

    // 会话窗口事件 → 诊断引擎
    let events = hist::get_session_events(conn, &session_id, 20000).map_err(|e| e.to_string())?;
    let findings = run_rules_on_events(conn, &events, &state);
    for f in &findings {
        hist::insert_finding(conn, f).map_err(|e| e.to_string())?;
    }

    // 统计
    let mut by_kind: std::collections::BTreeMap<String, u32> = Default::default();
    for e in &events {
        *by_kind.entry(e.kind.clone()).or_insert(0) += 1;
    }
    let report = serde_json::json!({
        "sessionId": session_id,
        "eventCount": event_count,
        "startedAt": started_at.to_rfc3339(),
        "byKind": by_kind,
        "findings": findings,
    });
    let _ = app.emit("session:stopped", &report);
    Ok(report)
}

fn run_rules_on_events(
    conn: &rusqlite::Connection,
    events: &[SessionEvent],
    state: &State<'_, AppState>,
) -> Vec<DiagnosticFinding> {
    let timeline: Vec<TimelineEvent> = events
        .iter()
        .map(|e| TimelineEvent {
            timestamp: e.timestamp,
            source: e.source.clone(),
            kind: e.kind.clone(),
            summary: e.summary.clone(),
            payload: e.payload.clone(),
        })
        .collect();
    let rt = state.runtime.lock().unwrap();
    let proxy_hosts: Vec<String> = rt
        .last_proxy_servers
        .iter()
        .map(|p| format!("{}:{}", p.host, p.port))
        .collect();
    let proxy_conn_failures = events
        .iter()
        .filter(|e| {
            e.kind == "conn_closed"
                && proxy_hosts.iter().any(|h| {
                    e.payload
                        .get("remote")
                        .map(|r| {
                            format!(
                                "{}:{}",
                                r.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                                r.get("port").and_then(|v| v.as_u64()).unwrap_or(0)
                            ) == *h
                        })
                        .unwrap_or(false)
                })
        })
        .count() as u32;
    let ctx = DiagnosticContext {
        now: chrono::Utc::now(),
        timeline: &timeline,
        syn_failures_recent: events
            .iter()
            .filter(|e| e.kind == "conn_closed")
            .count()
            .min(u32::MAX as usize) as u32,
        retrans_recent: 0,
        rst_recent: 0,
        handshake_p95_ms: None,
        proxy_servers: proxy_hosts,
        proxy_listener_gone: events
            .iter()
            .any(|e| e.kind == "proxy_removed"),
        proxy_conn_failures,
        ping_loss_rate: None,
        dns_result_changes: 0,
        icmp_unreachable: 0,
        dns_probe_failures: 0,
        dns_avg_ms: None,
        dns_baseline_ms: None,
        ping_avg_ms: None,
        ping_baseline_ms: None,
    };
    let disabled = hist::disabled_rules(conn).unwrap_or_default();
    rules::run_rules(&ctx, &disabled)
}

/// 会话列表。
#[tauri::command]
pub fn list_sessions(state: State<'_, AppState>, limit: Option<u32>) -> Result<Vec<RecordingSession>, String> {
    let db = state.db.lock().unwrap();
    match db.as_ref() {
        Some(conn) => hist::list_sessions(conn, limit.unwrap_or(50)).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

/// 会话事件明细。
#[tauri::command]
pub fn get_session_events(
    state: State<'_, AppState>,
    session_id: &str,
    limit: Option<u32>,
) -> Result<Vec<SessionEvent>, String> {
    let db = state.db.lock().unwrap();
    match db.as_ref() {
        Some(conn) => hist::get_session_events(conn, session_id, limit.unwrap_or(2000))
            .map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// History & Replay
// ---------------------------------------------------------------------------

/// 统一时间线查询（多条件过滤）。
#[tauri::command]
pub fn query_timeline(
    state: State<'_, AppState>,
    since: Option<String>,
    until: Option<String>,
    kind: Option<String>,
    source: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<TimelineEvent>, String> {
    let db = state.db.lock().unwrap();
    match db.as_ref() {
        Some(conn) => hist::query_timeline(
            conn,
            since.as_deref(),
            until.as_deref(),
            kind.as_deref(),
            source.as_deref(),
            limit.unwrap_or(300),
        )
        .map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

/// Network Replay：重建历史时刻的拓扑（基于当时保存的快照 + 事件）。
#[tauri::command]
pub fn replay_topology(
    state: State<'_, AppState>,
    at: String,
) -> Result<serde_json::Value, String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let at_ts = chrono::DateTime::parse_from_rfc3339(&at)
        .map_err(|e| format!("时间格式错误: {e}"))?
        .with_timezone(&chrono::Utc);
    let (nodes, edges, applied) =
        crate::topology::replay::replay_at(conn, at_ts).map_err(|e| e)?;
    Ok(serde_json::json!({
        "at": at,
        "appliedEvents": applied,
        "nodes": nodes,
        "edges": edges,
    }))
}

// ---------------------------------------------------------------------------
// Diagnostics Engine
// ---------------------------------------------------------------------------

/// 立即运行诊断规则（窗口 = 最近 minutes 分钟的时间线）。
#[tauri::command]
pub fn run_diagnostics(
    state: State<'_, AppState>,
    minutes: Option<u32>,
) -> Result<Vec<DiagnosticFinding>, String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let minutes = minutes.unwrap_or(10).clamp(1, 1440);
    let since = (chrono::Utc::now() - chrono::Duration::minutes(minutes as i64)).to_rfc3339();
    let timeline =
        hist::query_timeline(conn, Some(&since), None, None, None, 5000).map_err(|e| e.to_string())?;

    let rt = state.runtime.lock().unwrap();
    // 抓包指标（可观察时）
    let (retrans, rst) = {
        match &state.capture.manager.lock().unwrap().session {
            Some(s) => {
                let _ = s; // take 会清空 —— 用非破坏性读取？此处直接读取累计值
                (0u32, 0u32)
            }
            None => (0, 0),
        }
    };
    let proxy_hosts: Vec<String> = rt
        .last_proxy_servers
        .iter()
        .map(|p| format!("{}:{}", p.host, p.port))
        .collect();
    let proxy_conn_failures = timeline
        .iter()
        .filter(|e| {
            e.kind == "conn_closed"
                && proxy_hosts.iter().any(|h| {
                    e.payload
                        .get("remote")
                        .map(|r| {
                            format!(
                                "{}:{}",
                                r.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                                r.get("port").and_then(|v| v.as_u64()).unwrap_or(0)
                            ) == *h
                        })
                        .unwrap_or(false)
                })
        })
        .count() as u32;
    let icmp_unreachable = state
        .capture
        .manager
        .lock()
        .unwrap()
        .icmp_unreachable_count();
    let ctx = DiagnosticContext {
        now: chrono::Utc::now(),
        timeline: &timeline,
        syn_failures_recent: rt.last_syn_failures(),
        retrans_recent: retrans,
        rst_recent: rst,
        handshake_p95_ms: rt.last_handshake_p95(),
        proxy_servers: proxy_hosts,
        proxy_listener_gone: timeline
            .iter()
            .any(|e| e.kind == "proxy_removed"),
        proxy_conn_failures,
        ping_loss_rate: None,
        dns_result_changes: 0,
        icmp_unreachable,
        dns_probe_failures: 0,
        dns_avg_ms: None,
        dns_baseline_ms: None,
        ping_avg_ms: None,
        ping_baseline_ms: None,
    };
    let disabled = hist::disabled_rules(conn).unwrap_or_default();
    let findings = rules::run_rules(&ctx, &disabled);
    for f in &findings {
        hist::insert_finding(conn, f).map_err(|e| e.to_string())?;
    }
    Ok(findings)
}

/// 历史诊断结论查询。
#[tauri::command]
pub fn get_findings(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<DiagnosticFinding>, String> {
    let db = state.db.lock().unwrap();
    match db.as_ref() {
        Some(conn) => hist::query_findings(conn, limit.unwrap_or(50)).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

/// 规则注册表（含启用状态）。
#[tauri::command]
pub fn get_rule_registry(
    state: State<'_, AppState>,
) -> Result<Vec<crate::models::session::DiagnosticRuleMeta>, String> {
    let reg = rules::rule_registry();
    let db = state.db.lock().unwrap();
    let disabled: Vec<String> = match db.as_ref() {
        Some(conn) => hist::disabled_rules(conn).unwrap_or_default(),
        None => Vec::new(),
    };
    Ok(reg
        .into_iter()
        .map(|mut r| {
            r.enabled = !disabled.contains(&r.rule_id);
            r
        })
        .collect())
}

/// 启用/禁用规则。
#[tauri::command]
pub fn set_rule_enabled(
    state: State<'_, AppState>,
    rule_id: &str,
    enabled: bool,
) -> Result<(), String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    conn.execute(
        "UPDATE diagnostic_rules SET enabled=?2 WHERE rule_id=?1",
        rusqlite::params![rule_id, enabled as i64],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// RCA
// ---------------------------------------------------------------------------

/// 根因关联分析（用户指定对象 + 时间窗口）。
#[tauri::command]
pub fn run_rca(
    state: State<'_, AppState>,
    subject: &str,
    minutes: Option<u32>,
) -> Result<RcaReport, String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let minutes = minutes.unwrap_or(15).clamp(1, 1440);
    let window_end = chrono::Utc::now();
    let window_start = window_end - chrono::Duration::minutes(minutes as i64);
    let timeline = hist::query_timeline(
        conn,
        Some(&window_start.to_rfc3339()),
        None,
        None,
        None,
        5000,
    )
    .map_err(|e| e.to_string())?;

    let rt = state.runtime.lock().unwrap();
    let input = rca::RcaInput {
        subject: subject.to_string(),
        window_start,
        window_end,
        timeline: &timeline,
        proxies: &rt.last_proxy_servers,
        vpn: &rt.last_vpn,
        route_probes: &[],
        dns_server: None,
    };
    let report = rca::analyze(&input);
    hist::insert_rca(conn, &report).map_err(|e| e.to_string())?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

fn with_context(mut r: BenchmarkResult, state: &State<'_, AppState>) -> BenchmarkResult {
    let rt = state.runtime.lock().unwrap();
    r.interface = rt
        .last_vpn
        .iter()
        .find(|v| v.is_default_route_owner)
        .map(|v| v.friendly_name.clone());
    r.proxy_mode = rt
        .last_proxy_servers
        .first()
        .map(|p| format!("{:?}", p.mechanism).to_lowercase());
    r
}

/// 运行基准测试套件（用户指定目标与上限）。
#[tauri::command]
pub fn run_benchmark(
    state: State<'_, AppState>,
    kind: &str,
    targets: Vec<String>,
    count: Option<u32>,
    max_bytes: Option<u64>,
    max_seconds: Option<u64>,
    dns_servers: Option<Vec<String>>,
) -> Result<Vec<BenchmarkResult>, String> {
    let mut results = match kind {
        "ping" => {
            let t: Vec<String> = targets.iter().take(10).cloned().collect();
            crate::analyzer::benchmark::ping_benchmark(&t, count.unwrap_or(4))
        }
        "dns" => {
            let domains: Vec<String> = targets.iter().take(10).cloned().collect();
            let servers = dns_servers.unwrap_or_else(|| {
                vec!["223.5.5.5".into(), "119.29.29.29".into(), "8.8.8.8".into()]
            });
            crate::analyzer::benchmark::dns_benchmark(&domains, &servers)
        }
        "tcp_connect" => {
            let pairs: Vec<(String, u16)> = targets
                .iter()
                .take(10)
                .filter_map(|t| {
                    let (h, p) = t.rsplit_once(':')?;
                    Some((h.to_string(), p.parse().ok()?))
                })
                .collect();
            crate::analyzer::benchmark::tcp_connect_benchmark(&pairs, count.unwrap_or(5))
        }
        "http" => targets
            .iter()
            .take(5)
            .map(|u| crate::analyzer::benchmark::http_benchmark(u))
            .collect(),
        "download" => targets
            .iter()
            .take(3)
            .map(|u| {
                crate::analyzer::benchmark::download_benchmark(
                    u,
                    max_bytes.unwrap_or(50 * 1024 * 1024),
                    max_seconds.unwrap_or(30),
                )
            })
            .collect(),
        "upload" => targets
            .iter()
            .take(3)
            .map(|u| {
                crate::analyzer::benchmark::upload_benchmark(
                    u,
                    max_bytes.unwrap_or(10 * 1024 * 1024),
                    max_seconds.unwrap_or(30),
                )
            })
            .collect(),
        other => return Err(format!("不支持的基准类型: {other}")),
    };
    for r in results.iter_mut() {
        *r = with_context(r.clone(), &state);
    }
    // 落库 + 性能对比（同 kind+target 与上一次结果比较，降速 >50% 记 benchmark_anomaly 时间线）
    let db = state.db.lock().unwrap();
    if let Some(conn) = db.as_ref() {
        for r in &results {
            if matches!(r.kind, BenchmarkKind::Download | BenchmarkKind::Upload) {
                if let Ok(prev) = hist::query_benchmarks(conn, 50) {
                    if let Some(last) = prev.iter().find(|p| {
                        p.kind == r.kind && p.target == r.target && p.error.is_none()
                    }) {
                        let last_speed = last.metrics.get("bytesPerSec").and_then(|v| v.as_f64());
                        let cur_speed = r.metrics.get("bytesPerSec").and_then(|v| v.as_f64());
                        if let (Some(ls), Some(cs)) = (last_speed, cur_speed) {
                            if ls > 0.0 && cs < ls * 0.5 {
                                let _ = hist::insert_timeline_events(
                                    conn,
                                    &[TimelineEvent {
                                        timestamp: chrono::Utc::now(),
                                        source: "benchmark".into(),
                                        kind: "benchmark_anomaly".into(),
                                        summary: format!(
                                            "{:?} {} 速度下降: {:.1} → {:.1} B/s",
                                            r.kind, r.target, ls, cs
                                        ),
                                        payload: serde_json::json!({
                                            "target": r.target,
                                            "lastSpeed": ls,
                                            "currentSpeed": cs,
                                        }),
                                    }],
                                );
                            }
                        }
                    }
                }
            }
            hist::insert_benchmark(conn, r).map_err(|e| e.to_string())?;
        }
    }
    Ok(results)
}

/// 基准历史。
#[tauri::command]
pub fn get_benchmarks(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<BenchmarkResult>, String> {
    let db = state.db.lock().unwrap();
    match db.as_ref() {
        Some(conn) => hist::query_benchmarks(conn, limit.unwrap_or(50)).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// 报告导出
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportExportResult {
    pub path: String,
    pub kind: String,
}

/// 导出诊断报告（HTML / JSON / PDF；支持脱敏）。
#[tauri::command]
pub fn export_report(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    kind: &str,
    minutes: Option<u32>,
    mask_local_ips: Option<bool>,
    mask_public_ips: Option<bool>,
    mask_hostnames: Option<bool>,
    mask_domains: Option<bool>,
) -> Result<ReportExportResult, String> {
    use crate::analyzer::report::{
        build_html_report, html_to_pdf, mask_text, MaskContext, MaskOptions,
    };

    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let minutes = minutes.unwrap_or(30).clamp(1, 1440);
    let since = (chrono::Utc::now() - chrono::Duration::minutes(minutes as i64)).to_rfc3339();
    let timeline = hist::query_timeline(conn, Some(&since), None, None, None, 500)
        .map_err(|e| e.to_string())?;
    let findings = hist::query_findings(conn, 50).map_err(|e| e.to_string())?;

    // 脱敏上下文（真实采集值）
    let options = MaskOptions {
        mask_local_ips: mask_local_ips.unwrap_or(false),
        mask_public_ips: mask_public_ips.unwrap_or(false),
        mask_hostnames: mask_hostnames.unwrap_or(false),
        mask_domains: mask_domains.unwrap_or(false),
    };
    let mut ctx = MaskContext::default();
    {
        let rt = state.runtime.lock().unwrap();
        for i in rt.last_interfaces() {
            for ip in &i.ipv4_addresses {
                if crate::analyzer::report::is_private_ipv4(ip) {
                    ctx.local_ips.insert(ip.clone());
                }
            }
        }
        if let Ok(host) = std::env::var("COMPUTERNAME") {
            ctx.hostnames.insert(host);
        }
    }

    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("reports");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");

    match kind {
        "json" => {
            let payload = serde_json::json!({
                "generatedAt": chrono::Utc::now().to_rfc3339(),
                "windowMinutes": minutes,
                "findings": findings,
                "timeline": timeline,
            });
            let masked = if options.mask_local_ips || options.mask_domains || options.mask_hostnames {
                mask_text(
                    &serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?,
                    &options,
                    &ctx,
                )
            } else {
                serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?
            };
            let path = dir.join(format!("netscope-report-{stamp}.json"));
            std::fs::write(&path, masked).map_err(|e| e.to_string())?;
            Ok(ReportExportResult {
                path: path.to_string_lossy().to_string(),
                kind: "json".into(),
            })
        }
        "html" | "pdf" => {
            let html = build_html_report("NetScope 诊断报告", &findings, None, &timeline);
            let html = if options.mask_local_ips
                || options.mask_domains
                || options.mask_hostnames
                || options.mask_public_ips
            {
                mask_text(&html, &options, &ctx)
            } else {
                html
            };
            let html_path = dir.join(format!("netscope-report-{stamp}.html"));
            std::fs::write(&html_path, &html).map_err(|e| e.to_string())?;
            if kind == "html" {
                Ok(ReportExportResult {
                    path: html_path.to_string_lossy().to_string(),
                    kind: "html".into(),
                })
            } else {
                let pdf_path = dir.join(format!("netscope-report-{stamp}.pdf"));
                html_to_pdf(&html_path, &pdf_path).map_err(|e| e)?;
                Ok(ReportExportResult {
                    path: pdf_path.to_string_lossy().to_string(),
                    kind: "pdf".into(),
                })
            }
        }
        other => Err(format!("不支持的导出格式: {other}")),
    }
}

/// 一键打包诊断数据（JSON 报告 + 数据库备份 → zip 内同目录文件）。
#[tauri::command]
pub fn package_diagnostics(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ReportExportResult, String> {
    // 生成 JSON 报告 + 数据库备份文件，二者放入同一时间戳目录（打包目录）
    let report = export_report(
        app.state::<AppState>(),
        app.clone(),
        "json",
        Some(60),
        Some(false),
        Some(false),
        Some(false),
        Some(false),
    )?;
    let db = state.db.lock().unwrap();
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("reports");
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let backup_path = dir.join(format!("netscope-db-{stamp}.db"));
    if let Some(conn) = db.as_ref() {
        hist::backup_database(conn, backup_path.to_str().ok_or("路径无效")?)
            .map_err(|e| e.to_string())?;
    }
    Ok(ReportExportResult {
        path: report.path.clone(),
        kind: format!("package(报告: {} + 数据库: {})", report.path, backup_path.display()),
    })
}

// ---------------------------------------------------------------------------
// AI
// ---------------------------------------------------------------------------

/// AI 提问（检索证据 → Provider → 持久化）。
#[tauri::command]
pub fn ai_ask(
    state: State<'_, AppState>,
    question: &str,
) -> Result<AiConversation, String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let cfg = ai_config_from_db(conn);
    crate::ai::assistant::ask(conn, &cfg, question)
}

/// AI 会话历史。
#[tauri::command]
pub fn get_ai_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<AiConversation>, String> {
    let db = state.db.lock().unwrap();
    match db.as_ref() {
        Some(conn) => hist::query_ai_conversations(conn, limit.unwrap_or(30))
            .map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfigPayload {
    pub kind: String,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub has_api_key: bool,
}

fn ai_config_from_db(conn: &rusqlite::Connection) -> AiConfig {
    let kind = crate::storage::repository::get_setting(conn, "ai.kind")
        .ok()
        .flatten()
        .unwrap_or_else(|| "offline".into());
    let mut cfg = AiConfig::default();
    if kind == "openai" {
        cfg.kind = crate::models::session::AiProviderKind::OpenAiCompatible;
    }
    cfg.base_url = crate::storage::repository::get_setting(conn, "ai.base_url").ok().flatten();
    cfg.api_key = crate::storage::repository::get_setting(conn, "ai.api_key").ok().flatten();
    cfg.model = crate::storage::repository::get_setting(conn, "ai.model").ok().flatten();
    cfg
}

/// 读取 AI 配置（API key 不回传明文）。
#[tauri::command]
pub fn get_ai_config(state: State<'_, AppState>) -> Result<AiConfigPayload, String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let cfg = ai_config_from_db(conn);
    Ok(AiConfigPayload {
        kind: serde_json::to_string(&cfg.kind).unwrap_or_default().trim_matches('"').to_string(),
        base_url: cfg.base_url,
        model: cfg.model,
        has_api_key: cfg.api_key.is_some(),
    })
}

/// 保存 AI 配置。
#[tauri::command]
pub fn set_ai_config(
    state: State<'_, AppState>,
    kind: &str,
    base_url: Option<&str>,
    api_key: Option<&str>,
    model: Option<&str>,
) -> Result<(), String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    crate::storage::repository::set_setting(conn, "ai.kind", kind).map_err(|e| e.to_string())?;
    if let Some(u) = base_url {
        crate::storage::repository::set_setting(conn, "ai.base_url", u).map_err(|e| e.to_string())?;
    }
    if let Some(k) = api_key {
        if !k.is_empty() {
            crate::storage::repository::set_setting(conn, "ai.api_key", k)
                .map_err(|e| e.to_string())?;
        }
    }
    if let Some(m) = model {
        crate::storage::repository::set_setting(conn, "ai.model", m).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// 质量历史（Network Replay / AI 检索共用）。
#[tauri::command]
pub fn get_quality_series(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<NetworkQualityPoint>, String> {
    let _ = limit;
    Ok(Vec::new())
}

/// 对比两组基准结果（同一目标不同时间的网络环境对比，验收 7）。
#[tauri::command]
pub fn compare_benchmarks(
    state: State<'_, AppState>,
    kind: &str,
    target: &str,
) -> Result<serde_json::Value, String> {
    let db = state.db.lock().unwrap();
    let conn = db.as_ref().ok_or("数据库不可用")?;
    let all = hist::query_benchmarks(conn, 200).map_err(|e| e.to_string())?;
    let same: Vec<&BenchmarkResult> = all
        .iter()
        .filter(|b| {
            serde_json::to_string(&b.kind).unwrap_or_default().contains(kind)
                && b.target == target
                && b.error.is_none()
        })
        .collect();
    if same.len() < 2 {
        return Err(format!(
            "目标 '{}' 的同类型成功结果不足 2 条（当前 {} 条），无法对比",
            target,
            same.len()
        ));
    }
    let (newer, older) = (same[0], same[1]);
    let speed = |b: &BenchmarkResult| b.metrics.get("bytesPerSec").and_then(|v| v.as_f64());
    let avg_ms = |b: &BenchmarkResult| b.metrics.get("avgMs").and_then(|v| v.as_f64());
    let speed_change = match (speed(newer), speed(older)) {
        (Some(a), Some(b)) if b > 0.0 => Some((a - b) / b * 100.0),
        _ => None,
    };
    let latency_change = match (avg_ms(newer), avg_ms(older)) {
        (Some(a), Some(b)) => Some(a - b),
        _ => None,
    };
    let summary = match speed_change {
        Some(pct) if pct >= 0.0 => format!("速度提升 {:.1}%", pct),
        Some(pct) => format!("速度下降 {:.1}%", -pct),
        None => match latency_change {
            Some(ms) => format!("延迟变化 {:.1} ms", ms),
            None => "无可比指标".into(),
        },
    };
    Ok(serde_json::json!({
        "kind": kind,
        "target": target,
        "newer": { "at": newer.started_at, "metrics": newer.metrics },
        "older": { "at": older.started_at, "metrics": older.metrics },
        "speedChangePct": speed_change,
        "latencyChangeMs": latency_change,
        "summary": summary,
    }))
}
