//! UDP 端点采集：GetExtendedUdpTable 返回带 PID 的 UDP 端点快照。
//!
//! 注意（数据准确性）：UDP 是无连接协议，Windows UDP 表仅提供"本地端点 + PID"，
//! 没有远端地址、没有连接状态。所有 UDP 记录统一标记为
//! `state = Endpoint`、`remote = None`，不得与 TCP `Established` 混淆。

use chrono::{DateTime, Utc};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedUdpTable, MIB_UDP6TABLE_OWNER_MODULE, MIB_UDPTABLE_OWNER_MODULE,
    UDP_TABLE_OWNER_MODULE,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::{as_void_ptr, CollectorError};
use crate::collector::tcp::resolve_process_name;
use crate::models::connection::{
    derive_connection_id, Connection, ConnectionState, Endpoint, Protocol,
};

/// 采集全部 UDP 端点快照（IPv4 + IPv6，真实系统调用）。
pub fn snapshot_udp() -> Result<Vec<Connection>, CollectorError> {
    let now = Utc::now();
    let mut out = Vec::new();
    out.extend(snapshot_udp_v4(now)?);
    out.extend(snapshot_udp_v6(now)?);
    Ok(out)
}

fn snapshot_udp_v4(now: DateTime<Utc>) -> Result<Vec<Connection>, CollectorError> {
    let mut size: u32 = 0;
    let _ = unsafe {
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_MODULE,
            0,
        )
    };
    if size == 0 {
        return Ok(Vec::new());
    }

    // MIB_UDPROW_OWNER_MODULE 含 u64（liCreateTimestamp），需 8 字节对齐
    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(as_void_ptr(buf.as_mut_ptr())),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_MODULE,
            0,
        )
    };
    if rc != ERROR_SUCCESS.0 {
        return Err(CollectorError::Api(format!(
            "GetExtendedUdpTable(AF_INET) 失败: {}",
            rc
        )));
    }

    let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_MODULE;
    let n = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };

    Ok(rows
        .iter()
        .map(|r| {
            let local = Endpoint {
                ip: std::net::Ipv4Addr::from(u32::from_be(r.dwLocalAddr)).to_string(),
                port: u16::from_be((r.dwLocalPort & 0xffff) as u16),
            };
            build_endpoint(r.dwOwningPid, local, now)
        })
        .collect())
}

fn snapshot_udp_v6(now: DateTime<Utc>) -> Result<Vec<Connection>, CollectorError> {
    let mut size: u32 = 0;
    let _ = unsafe {
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_MODULE,
            0,
        )
    };
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(as_void_ptr(buf.as_mut_ptr())),
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_MODULE,
            0,
        )
    };
    if rc != ERROR_SUCCESS.0 {
        return Err(CollectorError::Api(format!(
            "GetExtendedUdpTable(AF_INET6) 失败: {}",
            rc
        )));
    }

    let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_MODULE;
    let n = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };

    Ok(rows
        .iter()
        .map(|r| {
            let local = Endpoint {
                ip: std::net::Ipv6Addr::from(r.ucLocalAddr).to_string(),
                port: u16::from_be((r.dwLocalPort & 0xffff) as u16),
            };
            build_endpoint(r.dwOwningPid, local, now)
        })
        .collect())
}

fn build_endpoint(pid: u32, local: Endpoint, now: DateTime<Utc>) -> Connection {
    Connection {
        id: derive_connection_id(Protocol::Udp, pid, &local, None),
        pid,
        process_name: resolve_process_name(pid),
        protocol: Protocol::Udp,
        local,
        remote: None,
        state: ConnectionState::Endpoint,
        interface_index: None,
        first_seen: now,
        last_seen: now,
        bytes_sent: 0,
        bytes_received: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实系统集成测试：系统当前必然存在 UDP 端点（本测试进程也持有 socket）。
    #[test]
    fn real_udp_snapshot_has_entries() {
        let eps = snapshot_udp().expect("GetExtendedUdpTable 应成功");
        assert!(!eps.is_empty(), "系统应存在至少一个 UDP 端点");
        for e in &eps {
            assert_eq!(e.protocol, Protocol::Udp, "协议字段必须为 udp");
            assert_eq!(e.state, ConnectionState::Endpoint, "UDP 状态必须为 endpoint");
            assert!(e.remote.is_none(), "UDP 端点不应有远端字段");
            assert!(e.local.port > 0, "UDP 端口不应为 0");
        }
    }
}
