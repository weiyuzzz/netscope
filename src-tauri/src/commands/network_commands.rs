//! 网络相关 Tauri 命令。
//!
//! - `get_app_info`：真实应用信息；
//! - `get_network_snapshot`：完整网络快照（网卡 + TCP 连接 + UDP 端点），
//!   结构化 JSON（camelCase）输出，Phase 3 前端轮询消费。

use serde::Serialize;
use tauri::State;

use crate::collector::NetworkSnapshot;
use crate::AppState;

/// 前端 `types/app.ts::AppInfo` 对应的后端结构（camelCase 序列化）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub started_at: String,
}

/// 返回真实应用与系统信息（无模拟数据）。
#[tauri::command]
pub fn get_app_info(state: State<'_, AppState>, app: tauri::AppHandle) -> AppInfo {
    let package = app.package_info();
    AppInfo {
        name: package.name.clone(),
        version: package.version.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()),
        started_at: state.started_at.to_rfc3339(),
    }
}

/// 采集一次完整网络快照。失败时返回错误字符串（前端如实展示，不降级为模拟数据）。
#[tauri::command]
pub fn get_network_snapshot() -> Result<NetworkSnapshot, String> {
    crate::collector::collect_snapshot().map_err(|e| e.to_string())
}

/// 读取当前系统 DNS 缓存（真实解析结果，普通权限可读）。
#[tauri::command]
pub fn get_dns_cache() -> Result<Vec<crate::collector::dns::DnsCacheEntry>, String> {
    crate::collector::dns::read_dns_cache().map_err(|e| e.to_string())
}
