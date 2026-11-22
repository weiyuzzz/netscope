//! 监控相关 Tauri 命令（二轮新增）。
//!
//! 供前端查询运行时缓存 / 历史数据，以及用户主动触发的出口探测。
//! 均只读运行时或执行显式动作，不包含业务逻辑。

use serde::Serialize;
use tauri::State;


use crate::collector::proxy;
use crate::models::connection::Connection;
use crate::models::metrics::{InterfaceRate, NetworkQualityPoint};
use crate::models::proxy::{EgressInfo, ProxyEvent, ProxyLink, ProxyServer, VpnInterface};
use crate::models::topology::{TopologyEdge, TopologyNode};
use crate::AppState;

/// 全量拓扑（前端初次加载）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphPayload {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

/// 代理状态总览（Proxy Analysis 页数据源）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatusPayload {
    pub servers: Vec<ProxyServer>,
    pub links: Vec<ProxyLink>,
    pub vpn_interfaces: Vec<VpnInterface>,
    /// 近期代理事件（切换历史）。
    pub recent_events: Vec<ProxyEvent>,
}

#[tauri::command]
pub fn get_connections(state: State<'_, AppState>) -> Vec<Connection> {
    state.runtime.lock().unwrap().tracker_active()
}

#[tauri::command]
pub fn get_topology_graph(state: State<'_, AppState>) -> GraphPayload {
    let (nodes, edges) = state.runtime.lock().unwrap().graph_snapshot();
    GraphPayload { nodes, edges }
}
#[tauri::command]
pub fn get_proxy_status(state: State<'_, AppState>) -> ProxyStatusPayload {
    let rt = state.runtime.lock().unwrap();
    ProxyStatusPayload {
        servers: rt.last_proxy_servers.clone(),
        links: rt.last_proxy_links.clone(),
        vpn_interfaces: rt.last_vpn.clone(),
        recent_events: Vec::new(), // 近期事件由 db 查询填充（见 get_proxy_event_history）
    }
}

#[tauri::command]
pub fn get_interface_rates(state: State<'_, AppState>) -> Vec<InterfaceRate> {
    state.runtime.lock().unwrap().last_rates.clone()
}

#[tauri::command]
pub fn get_latest_quality(state: State<'_, AppState>) -> Option<NetworkQualityPoint> {
    state.runtime.lock().unwrap().last_quality.clone()
}

/// 历史质量曲线（network_quality 表）。
#[tauri::command]
pub fn get_quality_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<NetworkQualityPoint>, String> {
    let db = state.db.lock().unwrap();
    let Some(conn) = db.as_ref() else { return Ok(Vec::new()) };
    let limit = limit.unwrap_or(300).min(2000);
    let mut stmt = conn
        .prepare(
            "SELECT timestamp, rx_bps, tx_bps, tcp_total, tcp_established, udp_endpoints, \
             retransmits_recent, rst_recent, syn_failures_recent \
             FROM network_quality ORDER BY timestamp DESC LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([limit], |r| {
            let ts: String = r.get(0)?;
            Ok(NetworkQualityPoint {
                timestamp: chrono::DateTime::parse_from_rfc3339(&ts)
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                rx_bps: r.get(1)?,
                tx_bps: r.get(2)?,
                tcp_total: r.get(3)?,
                tcp_established: r.get(4)?,
                udp_endpoints: r.get(5)?,
                retransmits_recent: r.get(6)?,
                rst_recent: r.get(7)?,
                syn_failures_recent: r.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    out.reverse(); // 时间正序
    Ok(out)
}

/// 代理切换历史（proxy_events 表）。
#[tauri::command]
pub fn get_proxy_event_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<crate::storage::repository::PersistedEvent>, String> {
    let db = state.db.lock().unwrap();
    let Some(conn) = db.as_ref() else { return Ok(Vec::new()) };
    let limit = limit.unwrap_or(100).min(1000);
    let mut stmt = conn
        .prepare(
            "SELECT timestamp, 'proxy', event_kind, detail FROM proxy_events \
             ORDER BY timestamp DESC LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([limit], |r| {
            Ok(crate::storage::repository::PersistedEvent {
                timestamp: r.get(0)?,
                source: r.get(1)?,
                kind: r.get(2)?,
                payload: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// 公网出口探测（用户主动触发；不会在后台自动执行）。
#[tauri::command]
pub fn probe_egress_ip() -> EgressInfo {
    proxy::probe_egress_ip()
}

/// 采集开关（Settings 页）。
#[tauri::command]
pub fn set_collection_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.runtime.lock().unwrap().enabled = enabled;
    if let Ok(db) = state.db.lock() {
        if let Some(conn) = db.as_ref() {
            let _ = crate::storage::repository::set_setting(
                conn,
                "collection.enabled",
                if enabled { "1" } else { "0" },
            );
        }
    }
    Ok(())
}

/// 采集间隔（秒）。
#[tauri::command]
pub fn set_collect_interval(state: State<'_, AppState>, secs: u64) -> Result<(), String> {
    let secs = secs.clamp(1, 60);
    state.runtime.lock().unwrap().interval_secs = secs;
    if let Ok(db) = state.db.lock() {
        if let Some(conn) = db.as_ref() {
            let _ = crate::storage::repository::set_setting(
                conn,
                "collection.interval_secs",
                &secs.to_string(),
            );
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSettings {
    pub enabled: bool,
    pub interval_secs: u64,
}

#[tauri::command]
pub fn get_collection_settings(state: State<'_, AppState>) -> CollectionSettings {
    let rt = state.runtime.lock().unwrap();
    CollectionSettings {
        enabled: rt.enabled,
        interval_secs: rt.interval_secs,
    }
}

/// 清除本地历史数据（保留活跃状态；默认保留 7 天内数据）。
#[tauri::command]
pub fn clear_history(state: State<'_, AppState>, keep_days: Option<i64>) -> Result<(), String> {
    let db = state.db.lock().unwrap();
    if let Some(conn) = db.as_ref() {
        crate::storage::repository::apply_retention(conn, keep_days.unwrap_or(7))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
