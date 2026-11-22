//! Windows 网络数据采集层。
//!
//! 职责：调用 Windows API 采集网卡、TCP/UDP 连接、路由、DNS 事件、
//! 代理/VPN 智能、接口流量计数，输出统一的 `models` 数据结构。
//!
//! 约束：本层不得依赖任何 UI / Tauri 类型；输出必须为结构化真实数据。
//!
//! - `adapters`  GetAdaptersAddresses（网卡、IP、DNS、MTU、协商速率）✅
//! - `tcp`       GetExtendedTcpTable（TCP 连接表 + PID）✅
//! - `udp`       GetExtendedUdpTable（UDP 端点表 + PID）✅
//! - `routes`    GetBestInterfaceEx / GetIpForwardTable2（路由与归属接口）✅
//! - `dns`       DNS 缓存域名条目（能力边界见模块文档）✅
//! - `proxy`     Proxy Intelligence：系统代理 / WinHTTP / 监听推断 / VPN 分类 ✅
//! - `etw`       ETW 实时事件引擎封装（可选能力，管理员权限；未实现，降级为轮询）

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use serde::Serialize;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR_INET,
};

use crate::models::connection::Connection;
use crate::models::interface::NetworkInterface;

pub mod adapters;
pub mod capture;
pub mod dns;
pub mod etw;
pub mod processes;
pub mod proxy;
pub mod routes;
pub mod runtime;
pub mod tcp;
pub mod timeline;
pub mod udp;

/// 采集层错误类型。
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    /// Windows API 调用返回失败（Result 风格 API）。
    #[error("Windows API 错误: {0}")]
    Windows(#[from] windows::core::Error),
    /// Windows API 返回非成功码（WIN32_ERROR 风格 API）。
    #[error("Windows API 调用失败: {0}")]
    Api(String),
    /// 地址解析失败。
    #[error("无效的 IP 地址: {0}")]
    InvalidAddress(String),
}

/// 一次完整网络快照（collector 层输出契约，经 Tauri 命令序列化为 JSON 给前端）。
///
/// 注意：这是"某一时刻"的真实系统状态，不是历史累积；
/// 连接生命周期（first_seen 维护、断开判定）由 Phase 2 关联层完成。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSnapshot {
    /// 快照采集时间（统一 UTC）。
    pub timestamp: DateTime<Utc>,
    pub interfaces: Vec<NetworkInterface>,
    /// TCP 连接（含 LISTEN / ESTABLISHED 等全部状态）。
    pub tcp_connections: Vec<Connection>,
    /// UDP 端点（不是已建立连接）。
    pub udp_endpoints: Vec<Connection>,
    /// 采集过程中的能力受限说明（如进程名获取失败数量）。
    pub limitations: Vec<String>,
}

/// 执行一次完整网络快照采集。
///
/// 连接归属网卡通过 GetBestInterfaceEx 查询并按远端 IP 缓存，避免逐连接重复系统调用。
pub fn collect_snapshot() -> Result<NetworkSnapshot, CollectorError> {
    let timestamp = Utc::now();
    let interfaces = adapters::list_adapters()?;
    let tcp_connections = tcp::snapshot_tcp()?;
    let udp_endpoints = udp::snapshot_udp()?;

    let mut limitations = Vec::new();
    let unnamed = tcp_connections.iter().chain(udp_endpoints.iter()).filter(|c| c.process_name.is_none()).count();
    if unnamed > 0 {
        limitations.push(format!("{unnamed} 个连接的进程名因权限或生命周期原因未能获取（PID 可用）"));
    }

    // 连接归属网卡：按远端 IP 查询最优出接口（带缓存）。
    let mut best_if_cache: HashMap<String, Option<u32>> = HashMap::new();
    let mut tcp_connections = tcp_connections;
    for conn in tcp_connections.iter_mut() {
        if let Some(remote) = &conn.remote {
            let idx = *best_if_cache
                .entry(remote.ip.clone())
                .or_insert_with(|| routes::best_interface_index(&remote.ip));
            conn.interface_index = idx;
        }
    }

    Ok(NetworkSnapshot {
        timestamp,
        interfaces,
        tcp_connections,
        udp_endpoints,
        limitations,
    })
}

/// 将 SOCKADDR_INET 转换为 IP 字符串（IPv4 / IPv6）。
pub(crate) fn sockaddr_inet_to_ip(sa: &SOCKADDR_INET) -> Option<String> {
    // SOCKADDR_INET 的 si_family 与 Ipv4.sin_family / Ipv6.sin6_family 在同一偏移，
    // 读 union 第一个字段是安全的。
    let family = unsafe { sa.si_family };
    if family == AF_INET {
        let bytes: [u8; 4] =
            unsafe { std::mem::transmute(sa.Ipv4.sin_addr) };
        Some(Ipv4Addr::from(bytes).to_string())
    } else if family == AF_INET6 {
        let bytes: [u8; 16] = unsafe { sa.Ipv6.sin6_addr.u.Byte };
        Some(Ipv6Addr::from(bytes).to_string())
    } else {
        None
    }
}

/// 将 WinSock SOCKADDR（经 SOCKET_ADDRESS.lpSockaddr）转换为 IP 字符串。
///
/// SOCKADDR 与 SOCKADDR_INET 布局兼容（family 前缀 + 地址），按 INET/INET6 解读。
pub(crate) fn sockaddr_to_ip(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<String> {
    if sa.is_null() {
        return None;
    }
    let inet = sa as *const SOCKADDR_INET;
    // 通过 family 判断有效性后复用统一转换
    let family = unsafe { (*inet).si_family };
    if family != AF_INET && family != AF_INET6 {
        return None;
    }
    sockaddr_inet_to_ip(unsafe { &*inet })
}

/// 将 IP 字符串构造为 SOCKADDR_INET（端口为 0），用于路由查询。
pub(crate) fn ip_to_sockaddr_inet(ip: &str) -> Result<SOCKADDR_INET, CollectorError> {
    use std::net::IpAddr;
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| CollectorError::InvalidAddress(ip.to_string()))?;
    let mut sa = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(v4) => {
            let octets: [u8; 4] = v4.octets();
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_port = 0;
            sa.Ipv4.sin_addr = unsafe { std::mem::transmute(octets) };
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_port = 0;
            sa.Ipv6.sin6_flowinfo = 0;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    Ok(sa)
}

/// 拼接 `c_void` 指针的便捷函数（供 GetExtendedTcpTable 等使用）。
pub(crate) fn as_void_ptr<T>(p: *mut T) -> *mut c_void {
    p as *mut c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_roundtrip_v4() {
        let sa = ip_to_sockaddr_inet("192.168.1.10").unwrap();
        assert_eq!(sockaddr_inet_to_ip(&sa).unwrap(), "192.168.1.10");
    }

    #[test]
    fn sockaddr_roundtrip_v6() {
        let sa = ip_to_sockaddr_inet("fe80::1234").unwrap();
        assert_eq!(sockaddr_inet_to_ip(&sa).unwrap(), "fe80::1234");
    }

    #[test]
    fn invalid_ip_rejected() {
        assert!(ip_to_sockaddr_inet("not-an-ip").is_err());
    }
}
