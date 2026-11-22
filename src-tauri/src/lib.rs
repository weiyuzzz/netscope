//! NetScope 后端入口。
//!
//! 架构分层（详见 ARCHITECTURE.md）：
//! - `collector`  Windows 网络数据采集（含 Proxy Intelligence / 运行时）
//! - `correlator` 进程 / DNS / 连接关联
//! - `topology`   拓扑图数据构建（纯 Rust，不依赖 UI）
//! - `probe`      Ping / Traceroute / DNS 主动探测
//! - `analyzer`   诊断与 TCP 质量分析
//! - `storage`    SQLite 持久化（迁移 + 保留策略）
//! - `models`     统一数据模型与前后端通信契约
//! - `commands`   Tauri 命令层（前后端唯一通信入口）

pub mod ai;
pub mod analyzer;
pub mod collector;
pub mod commands;
pub mod correlator;
pub mod models;
pub mod probe;
pub mod storage;
pub mod topology;

use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tauri::{Emitter, Manager};

use collector::runtime::CollectorRuntime;

/// 全局应用状态（Tauri managed state）。
pub struct AppState {
    /// 应用启动时间（UTC，统一时间戳基准）。
    pub started_at: DateTime<Utc>,
    /// 后台采集运行时。
    pub runtime: Mutex<CollectorRuntime>,
    /// SQLite 连接（setup 时打开；失败则历史数据不可用，运行时功能不受影响）。
    pub db: Mutex<Option<rusqlite::Connection>>,
    /// 抓包管理器（Npcap 可选模块，用户主动启用）。
    pub capture: commands::capture_commands::CaptureHandle,
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("NetScope 后端启动");

    tauri::Builder::default()
        .manage(AppState {
            started_at: Utc::now(),
            runtime: Mutex::new(CollectorRuntime::new()),
            db: Mutex::new(None),
            capture: commands::capture_commands::CaptureHandle::default(),
        })
        .setup(|app| {
            // ---- SQLite 打开（失败不阻断运行）----
            match app.path().app_data_dir() {
                Ok(dir) => {
                    if let Err(e) = std::fs::create_dir_all(&dir) {
                        tracing::warn!("数据目录创建失败: {e}");
                    }
                    match storage::database::open(&dir.join("netscope.db")) {
                        Ok(conn) => {
                            tracing::info!("数据库已打开: {}", dir.join("netscope.db").display());
                            *app.state::<AppState>().db.lock().unwrap() = Some(conn);
                        }
                        Err(e) => tracing::warn!("数据库打开失败（历史数据不可用）: {e}"),
                    }
                }
                Err(e) => tracing::warn!("无法获取数据目录: {e}"),
            }

            // ---- 后台采集循环（不阻塞 UI）----
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(1));
                let mut ticks: u64 = 0;
                loop {
                    ticker.tick().await;
                    ticks += 1;

                    let out = {
                        let state = handle.state::<AppState>();
                        let mut rt = state.runtime.lock().unwrap();
                        let interval = rt.interval_secs.max(1);
                        // 首次立即执行；之后按设置间隔（秒）
                        if ticks > 1 && ticks % interval != 0 {
                            continue;
                        }
                        rt.tick()
                    };

                    for e in &out.errors {
                        tracing::warn!("采集错误: {e}");
                    }

                    // 拓扑增量推送
                    if !out.graph_diff.is_empty() {
                        let _ = handle.emit("topology:diff", &out.graph_diff);
                    }

                    // 指标推送（速率 / 质量 / 计数 / 代理 / VPN）
                    let metrics = serde_json::json!({
                        "interfaceRates": out.interface_rates,
                        "quality": out.quality,
                        "proxyServers": out.proxy_servers,
                        "proxyLinks": out.proxy_links,
                        "vpnInterfaces": out.vpn_interfaces,
                        "proxyEvents": out.proxy_events,
                        "activeProcesses": out.active_processes,
                        "connectionCount": out.connections.len(),
                        "tickCount": out.tick_count,
                        "errors": out.errors,
                    });
                    let _ = handle.emit("metrics:tick", &metrics);

                    // 生命周期事件推送（Connections 页增量更新）
                    for ev in &out.lifecycle {
                        let payload = serde_json::json!({
                            "kind": match ev {
                                correlator::connection_correlation::LifecycleEvent::Opened(_) => "opened",
                                correlator::connection_correlation::LifecycleEvent::Updated(_) => "updated",
                                correlator::connection_correlation::LifecycleEvent::Closed(_) => "closed",
                            },
                            "connection": correlator::connection_correlation::event_connection(ev),
                        });
                        let _ = handle.emit("connection:event", &payload);
                    }

                    // 持久化（质量点每 5 tick ≈ 10s 落库；DNS 新域名落库）
                    let state = handle.state::<AppState>();
                    let db_guard = state.db.lock();
                    if let Ok(db) = db_guard {
                        if let Some(conn) = db.as_ref() {
                            let _ = storage::repository::insert_network_events(conn, &out.events);
                            let _ = storage::repository::upsert_connections(conn, &out.connections);
                            for pe in &out.proxy_events {
                                let _ = storage::repository::insert_proxy_event(
                                    conn,
                                    &pe.timestamp.to_rfc3339(),
                                    &serde_json::to_string(&pe.kind).unwrap_or_default().trim_matches('"').to_string(),
                                    &serde_json::to_string(&pe.mechanism).unwrap_or_default().trim_matches('"').to_string(),
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    Some("runtime"),
                                    &pe.detail,
                                );
                            }
                            if out.tick_count % 5 == 0 {
                                if let Some(q) = &out.quality {
                                    let _ = storage::repository::insert_network_quality(conn, q);
                                }
                            }
                            for d in &out.dns_new_domains {
                                let _ = storage::repository::insert_dns_event(
                                    conn,
                                    &Utc::now().to_rfc3339(),
                                    "dns_cache",
                                    "cache_seen",
                                    d,
                                    0,
                                    Some("dns_only"),
                                    None,
                                    &serde_json::json!({}),
                                );
                            }
                            // 统一时间线（第三轮）
                            if !out.timeline.is_empty() {
                                let _ = storage::history_repository::insert_timeline_events(conn, &out.timeline);
                            }
                            // 会话录制事件
                            if !out.session_events.is_empty() {
                                let _ = storage::history_repository::insert_session_events(conn, &out.session_events);
                            }
                            // 拓扑历史快照
                            if let Some(snap) = &out.topology_snapshot {
                                let _ = storage::history_repository::insert_topology_snapshot(conn, snap);
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::network_commands::get_app_info,
            commands::network_commands::get_network_snapshot,
            commands::network_commands::get_dns_cache,
            commands::monitor_commands::get_connections,
            commands::monitor_commands::get_topology_graph,
            commands::monitor_commands::get_proxy_status,
            commands::monitor_commands::get_interface_rates,
            commands::monitor_commands::get_latest_quality,
            commands::monitor_commands::get_quality_history,
            commands::monitor_commands::get_proxy_event_history,
            commands::monitor_commands::probe_egress_ip,
            commands::monitor_commands::set_collection_enabled,
            commands::monitor_commands::set_collect_interval,
            commands::monitor_commands::get_collection_settings,
            commands::monitor_commands::clear_history,
            commands::capture_commands::npcap_status,
            commands::capture_commands::list_capture_devices,
            commands::capture_commands::start_capture,
            commands::capture_commands::stop_capture,
            commands::capture_commands::get_capture_status,
            commands::capture_commands::get_capture_packets,
            commands::capture_commands::get_capture_flows,
            commands::capture_commands::take_capture_metrics,
            commands::capture_commands::take_capture_handshakes,
            commands::diagnostic_commands::run_ping,
            commands::diagnostic_commands::run_traceroute,
            commands::diagnostic_commands::asn_lookup,
            commands::history_commands::start_recording,
            commands::history_commands::stop_recording,
            commands::history_commands::list_sessions,
            commands::history_commands::get_session_events,
            commands::history_commands::query_timeline,
            commands::history_commands::replay_topology,
            commands::history_commands::run_diagnostics,
            commands::history_commands::get_findings,
            commands::history_commands::get_rule_registry,
            commands::history_commands::set_rule_enabled,
            commands::history_commands::run_rca,
            commands::history_commands::run_benchmark,
            commands::history_commands::get_benchmarks,
            commands::history_commands::export_report,
            commands::history_commands::package_diagnostics,
            commands::history_commands::ai_ask,
            commands::history_commands::get_ai_history,
            commands::history_commands::get_ai_config,
            commands::history_commands::set_ai_config,
            commands::history_commands::get_quality_series,
            commands::history_commands::compare_benchmarks,
        ])
        .run(tauri::generate_context!())
        .expect("NetScope 应用启动失败");
}
