//! 数据包捕获 Tauri 命令（Npcap 可选模块）。
//!
//! 约束：抓包仅在用户主动启用时运行；状态/限制如实上报；
//! 同时最多一个会话；停止时确保采集线程干净退出。

use serde::Serialize;
use std::sync::Arc;
use tauri::{Emitter, Manager, State};

use crate::collector::capture::{
    CaptureDevice, CaptureManager, CaptureSession, CaptureStatus, NpcapLib, NpcapStatus,
};
use crate::models::capture::{FlowSummary, PacketInfo};
use crate::AppState;

/// 抓包会话句柄（AppState 持有）。
pub struct CaptureHandle {
    pub manager: std::sync::Mutex<CaptureManager>,
}

impl Default for CaptureHandle {
    fn default() -> Self {
        Self {
            manager: std::sync::Mutex::new(CaptureManager::default()),
        }
    }
}

/// Npcap 安装状态（含安装指引）。
#[tauri::command]
pub fn npcap_status() -> NpcapStatus {
    crate::collector::capture::npcap_status()
}

/// 枚举可抓包网卡（需 Npcap；未安装时返回明确错误）。
#[tauri::command]
pub fn list_capture_devices() -> Result<Vec<CaptureDevice>, String> {
    crate::collector::capture::list_capture_devices()
}

/// 启动抓包会话（用户主动触发；PCAP 导出路径可空）。
#[tauri::command]
pub fn start_capture(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    config: crate::models::capture::CaptureConfig,
    export_path: Option<String>,
) -> Result<CaptureStatus, String> {
    let status = state.capture.manager.lock().unwrap().status();
    if status.state == crate::models::capture::CaptureState::Running {
        return Err("已有抓包会话在运行，请先停止".into());
    }

    let lib = Arc::new(NpcapLib::load().map_err(|e| {
        format!("Npcap 加载失败：{e}（未安装或路径不含 wpcap.dll）")
    })?);

    // 导出路径：相对路径放到应用数据目录
    let export = export_path.map(|p| {
        let path = std::path::PathBuf::from(&p);
        if path.is_absolute() {
            path
        } else {
            let dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            let _ = std::fs::create_dir_all(&dir);
            dir.join(format!("captures/{}", path.display()))
        }
    });

    // 事件回调注入（采集层不直接依赖 Tauri）
    let handle = app.clone();
    let event_sink: Option<crate::collector::capture::EventSink> =
        Some(Box::new(move |event: &str, payload: &serde_json::Value| {
            let _ = handle.emit(event, payload);
        }));
    let session =
        CaptureSession::start(config, export, lib, event_sink).map_err(|e| e)?;
    let status = session.status();
    state.capture.manager.lock().unwrap().session = Some(session);
    Ok(status)
}

/// 停止抓包（线程干净退出）。
#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> CaptureStatus {
    let mut mgr = state.capture.manager.lock().unwrap();
    if let Some(s) = mgr.session.as_mut() {
        s.stop();
    }
    mgr.status()
}

/// 当前会话状态。
#[tauri::command]
pub fn get_capture_status(state: State<'_, AppState>) -> CaptureStatus {
    state.capture.manager.lock().unwrap().status()
}

/// 最近的解析包（Packet Inspector 实时视图）。
#[tauri::command]
pub fn get_capture_packets(state: State<'_, AppState>, max: Option<usize>) -> Vec<PacketInfo> {
    let mgr = state.capture.manager.lock().unwrap();
    match &mgr.session {
        Some(s) => s.recent_packets(max.unwrap_or(200).min(2000)),
        None => Vec::new(),
    }
}

/// 会话流统计（TCP 会话基础统计）。
#[tauri::command]
pub fn get_capture_flows(state: State<'_, AppState>) -> Vec<FlowSummary> {
    let mgr = state.capture.manager.lock().unwrap();
    match &mgr.session {
        Some(s) => s.flow_summaries(),
        None => Vec::new(),
    }
}

/// 取走 TCP 事件（重传 / RST / 建连耗时；抓包推导，来源标注 capture）。
#[tauri::command]
pub fn take_capture_metrics(
    state: State<'_, AppState>,
) -> Vec<crate::models::metrics::TcpMetricEvent> {
    let mgr = state.capture.manager.lock().unwrap();
    match &mgr.session {
        Some(s) => s.take_metrics(),
        None => Vec::new(),
    }
}

/// 取走建连耗时样本。
#[tauri::command]
pub fn take_capture_handshakes(
    state: State<'_, AppState>,
) -> Vec<crate::models::metrics::HandshakeTiming> {
    let mgr = state.capture.manager.lock().unwrap();
    match &mgr.session {
        Some(s) => s.take_handshakes(),
        None => Vec::new(),
    }
}
