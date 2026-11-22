//! 诊断相关 Tauri 命令：Ping / Traceroute / ASN 查询。
//!
//! 全部为用户主动触发的真实探测；结果推入拓扑（RouteHop 节点）并落库。

use serde::Serialize;
use tauri::{Emitter, State};

use crate::collector::capture;
use crate::models::metrics::RouteProbe;
use crate::probe::ping;
use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingPayload {
    pub result: ping::PingResult,
}

/// ICMP Ping（用户触发）。
#[tauri::command]
pub fn run_ping(target: &str, count: Option<u32>, timeout_ms: Option<u32>) -> Result<PingPayload, String> {
    let result = ping::ping(
        target,
        count.unwrap_or(4),
        timeout_ms.unwrap_or(2000),
    )?;
    Ok(PingPayload { result })
}

/// Traceroute（用户触发）。
/// ICMP 模式免管理员；UDP/TCP 模式需要 Npcap + 管理员（未满足时如实报错）。
#[tauri::command]
pub fn run_traceroute(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    target: &str,
    protocol: Option<&str>,
    max_hops: Option<u8>,
    probes_per_hop: Option<u8>,
    with_asn: Option<bool>,
) -> Result<RouteProbe, String> {
    let proto = protocol.unwrap_or("icmp").to_lowercase();
    let max_hops = max_hops.unwrap_or(15);
    let probes = probes_per_hop.unwrap_or(3);

    let mut probe = match proto.as_str() {
        "icmp" => ping::icmp_traceroute(target, max_hops, probes, 2000)?,
        "udp" | "tcp" => {
            // UDP/TCP 模式需要原始发包（Npcap）+ 管理员权限：如实拒绝而非伪造
            let status = capture::npcap_status();
            if !status.installed {
                return Err(
                    "UDP/TCP Traceroute 需要 Npcap（未安装）。请安装 Npcap 后重试，\
                     或使用 ICMP 模式（免管理员，默认可用）。"
                        .into(),
                );
            }
            return Err(
                "UDP/TCP Traceroute 需要 Npcap 发包 + 管理员权限运行 NetScope。\
                 当前进程无管理员权限，已拒绝执行（不伪造探测结果）。"
                    .into(),
            );
        }
        other => return Err(format!("不支持的协议模式: {other}")),
    };

    // ASN 查询（可选，走 cymru DNS TXT）
    if with_asn.unwrap_or(true) {
        for hop in probe.hops.iter_mut() {
            if let Some(ip) = &hop.ip {
                if let Some(asn) = crate::probe::dns_probe::asn_for_ip(ip) {
                    hop.asn = Some(asn);
                }
            }
        }
    }

    // 拓扑联动：RouteHop 节点推入拓扑图（增量事件）
    {
        let mut rt = state.runtime.lock().unwrap();
        let mut diff = crate::topology::graph::GraphDiff::default();
        rt.apply_route_probe(&mut probe, &mut diff);
        if !diff.is_empty() {
            let _ = app.emit("topology:diff", &diff);
        }
    }

    // 落库（route_probes + route_hops）
    if let Ok(db) = state.db.lock() {
        if let Some(conn) = db.as_ref() {
            let _ = crate::storage::repository::insert_route_probe(conn, &probe);
        }
    }

    Ok(probe)
}

/// 单个 IP 的 ASN 查询（cymru DNS，用户触发）。
#[tauri::command]
pub fn asn_lookup(ip: &str) -> Option<String> {
    crate::probe::dns_probe::asn_for_ip(ip)
}
