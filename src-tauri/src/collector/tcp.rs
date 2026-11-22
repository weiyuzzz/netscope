//! TCP 连接采集：GetExtendedTcpTable（TCP_TABLE_OWNER_MODULE_ALL）返回带 PID 的连接快照。
//!
//! - IPv4 / IPv6 两个表分别查询；
//! - PID 直接来自表行（dwOwningPid），进程名经 OpenProcess + QueryFullProcessImageNameW 获取，
//!   获取失败（权限不足/进程刚退出）时如实置 None，不猜测；
//! - LISTEN 行远端为 0.0.0.0:0 / :::0，模型中置为 None（真实语义：无明确远端）；
//! - 连接 ID 由五元组+PID 派生，同一条连接跨采样保持稳定（关联层依赖此性质）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_MODULE, MIB_TCP6TABLE_OWNER_MODULE,
    MIB_TCPROW_OWNER_MODULE, MIB_TCPTABLE_OWNER_MODULE, TCP_TABLE_OWNER_MODULE_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{as_void_ptr, CollectorError};
use crate::models::connection::{
    derive_connection_id, Connection, ConnectionState, Endpoint, Protocol,
};

/// 采集全部 TCP 连接快照（IPv4 + IPv6，真实系统调用）。
pub fn snapshot_tcp() -> Result<Vec<Connection>, CollectorError> {
    let now = Utc::now();
    let mut out = Vec::new();
    out.extend(snapshot_tcp_v4(now)?);
    out.extend(snapshot_tcp_v6(now)?);
    Ok(out)
}

fn snapshot_tcp_v4(now: chrono::DateTime<Utc>) -> Result<Vec<Connection>, CollectorError> {
    // 第一次调用取所需缓冲大小（预期 ERROR_INSUFFICIENT_BUFFER）
    let mut size: u32 = 0;
    let _ = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_MODULE_ALL,
            0,
        )
    };
    if size == 0 {
        return Ok(Vec::new());
    }

    // MIB_TCPROW_OWNER_MODULE 含 u64（liCreateTimestamp），需 8 字节对齐 → u64 缓冲
    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(as_void_ptr(buf.as_mut_ptr())),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_MODULE_ALL,
            0,
        )
    };
    if rc != ERROR_SUCCESS.0 {
        return Err(CollectorError::Api(format!(
            "GetExtendedTcpTable(AF_INET) 失败: {}",
            rc
        )));
    }

    let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_MODULE;
    let n = unsafe { (*table).dwNumEntries } as usize;
    let rows =
        unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };

    Ok(rows
        .iter()
        .map(|r| unsafe { row_v4_to_connection(r, now) })
        .collect())
}

fn snapshot_tcp_v6(now: chrono::DateTime<Utc>) -> Result<Vec<Connection>, CollectorError> {
    let mut size: u32 = 0;
    let _ = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            windows::Win32::Networking::WinSock::AF_INET6.0 as u32,
            TCP_TABLE_OWNER_MODULE_ALL,
            0,
        )
    };
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(as_void_ptr(buf.as_mut_ptr())),
            &mut size,
            false,
            windows::Win32::Networking::WinSock::AF_INET6.0 as u32,
            TCP_TABLE_OWNER_MODULE_ALL,
            0,
        )
    };
    if rc != ERROR_SUCCESS.0 {
        return Err(CollectorError::Api(format!(
            "GetExtendedTcpTable(AF_INET6) 失败: {}",
            rc
        )));
    }

    let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_MODULE;
    let n = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };

    Ok(rows
        .iter()
        .map(|r| unsafe { row_v6_to_connection(r, now) })
        .collect())
}

/// 表行中的端口以网络字节序存放在 DWORD 低 16 位。
fn port_from_dword(v: u32) -> u16 {
    u16::from_be((v & 0xffff) as u16)
}

/// 解析 IPv4 TCP 行（无歧义字段布局，读取安全）。
unsafe fn row_v4_to_connection(
    r: *const MIB_TCPROW_OWNER_MODULE,
    now: chrono::DateTime<Utc>,
) -> Connection {
    let r = &*r;
    let local_ip = Ipv4Addr::from(u32::from_be(r.dwLocalAddr)).to_string();
    let local_port = port_from_dword(r.dwLocalPort);
    let remote_ip = Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)).to_string();
    let remote_port = port_from_dword(r.dwRemotePort);
    let pid = r.dwOwningPid;

    build_connection(
        Protocol::Tcp,
        pid,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        map_tcp_state(r.dwState),
        now,
    )
}

/// 解析 IPv6 TCP 行；链路本地地址附带 scope id（显示为 `fe80::1%N`）。
unsafe fn row_v6_to_connection(
    r: *const MIB_TCP6ROW_OWNER_MODULE,
    now: chrono::DateTime<Utc>,
) -> Connection {
    let r = &*r;
    let addr6 = std::net::Ipv6Addr::from(r.ucLocalAddr);
    let remote6 = std::net::Ipv6Addr::from(r.ucRemoteAddr);
    // 链路本地地址 + scope 才有区分意义；其余场景 scope 通常为 0
    let local_ip = with_scope(addr6, r.dwLocalScopeId);
    let remote_ip = with_scope(remote6, r.dwRemoteScopeId);
    let local_port = port_from_dword(r.dwLocalPort);
    let remote_port = port_from_dword(r.dwRemotePort);
    let pid = r.dwOwningPid;

    build_connection(
        Protocol::Tcp,
        pid,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        map_tcp_state(r.dwState),
        now,
    )
}

fn with_scope(addr: Ipv6Addr, scope: u32) -> String {
    if scope != 0 && addr.is_unicast_link_local() {
        format!("{addr}%{scope}")
    } else {
        addr.to_string()
    }
}

fn build_connection(
    protocol: Protocol,
    pid: u32,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    state: ConnectionState,
    now: chrono::DateTime<Utc>,
) -> Connection {
    // LISTEN 行远端为 0.0.0.0:0 / :::0，真实语义是"无明确远端"，置 None 而非伪造。
    let remote_is_placeholder = remote_ip.parse::<IpAddr>().is_ok_and(|a| a.is_unspecified()) && remote_port == 0;
    let remote = if remote_is_placeholder {
        None
    } else {
        Some(Endpoint {
            ip: remote_ip,
            port: remote_port,
        })
    };
    let local = Endpoint {
        ip: local_ip,
        port: local_port,
    };

    Connection {
        id: derive_connection_id(protocol, pid, &local, remote.as_ref()),
        pid,
        process_name: resolve_process_name(pid),
        protocol,
        local,
        remote,
        state,
        interface_index: None, // 由 collect_snapshot 统一通过路由查询填充
        first_seen: now,
        last_seen: now,
        bytes_sent: 0,
        bytes_received: 0,
    }
}

fn map_tcp_state(state: u32) -> ConnectionState {
    // windows-rs 常量为结构体常量，不能用作 match 模式，改用相等比较。
    use windows::Win32::NetworkManagement::IpHelper::*;
    let s = MIB_TCP_STATE(state as i32);
    if s == MIB_TCP_STATE_CLOSED {
        ConnectionState::Closed
    } else if s == MIB_TCP_STATE_LISTEN {
        ConnectionState::Listen
    } else if s == MIB_TCP_STATE_SYN_SENT {
        ConnectionState::SynSent
    } else if s == MIB_TCP_STATE_SYN_RCVD {
        ConnectionState::SynReceived
    } else if s == MIB_TCP_STATE_ESTAB {
        ConnectionState::Established
    } else if s == MIB_TCP_STATE_FIN_WAIT1 {
        ConnectionState::FinWait1
    } else if s == MIB_TCP_STATE_FIN_WAIT2 {
        ConnectionState::FinWait2
    } else if s == MIB_TCP_STATE_CLOSE_WAIT {
        ConnectionState::CloseWait
    } else if s == MIB_TCP_STATE_CLOSING {
        ConnectionState::Closing
    } else if s == MIB_TCP_STATE_LAST_ACK {
        ConnectionState::LastAck
    } else if s == MIB_TCP_STATE_TIME_WAIT {
        ConnectionState::TimeWait
    } else if s == MIB_TCP_STATE_DELETE_TCB {
        ConnectionState::DeleteTcb
    } else {
        ConnectionState::Closed
    }
}

/// 通过 OpenProcess + QueryFullProcessImageNameW 获取进程可执行文件名。
///
/// 返回 None 表示无法获取（系统进程 / 权限不足 / 进程已退出）——如实返回，不猜测。
pub fn resolve_process_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if ok && len > 0 {
            let full = String::from_utf16_lossy(&buf[..len as usize]);
            // 只取文件名部分（与产品规范 "Process Name" 字段一致）
            full.rsplit(['\\', '/']).next().map(|s| s.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实系统集成测试：系统当前必然存在 TCP 条目（监听或活动连接）。
    #[test]
    fn real_tcp_snapshot_has_entries() {
        let conns = snapshot_tcp().expect("GetExtendedTcpTable 应成功");
        assert!(!conns.is_empty(), "系统应存在至少一条 TCP 条目");
        for c in &conns {
            assert_eq!(c.protocol, Protocol::Tcp);
            assert!(!c.local.ip.is_empty(), "本地地址不应为空: {:?}", c.local);
        }
    }

    /// 真实端到端验证：在本测试中创建真实 TCP 监听端点，
    /// 快照必须能观察到它（PID、状态、端口全部来自真实系统表）。
    #[test]
    fn real_tcp_snapshot_contains_own_listener() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定临时端口应成功");
        let port = listener.local_addr().unwrap().port();

        let conns = snapshot_tcp().expect("快照采集应成功");
        let own = conns.iter().find(|c| {
            c.pid == std::process::id() && c.local.port == port && c.local.ip == "127.0.0.1"
        });

        let own = own.unwrap_or_else(|| {
            panic!("本进程刚创建的监听端点 127.0.0.1:{port} 应出现在真实 TCP 表中");
        });
        assert_eq!(own.state, ConnectionState::Listen, "该端点状态应为 Listen");
        assert!(own.remote.is_none(), "LISTEN 行远端应如实置 None");
        assert!(own.process_name.is_some(), "自身进程名应可解析");
    }

    /// 真实系统集成测试：本测试进程的进程名应能真实解析。
    #[test]
    fn own_process_name_resolves() {
        let name = resolve_process_name(std::process::id());
        assert!(name.is_some(), "自身进程名应可解析");
        let name = name.unwrap();
        assert!(
            name.to_lowercase().contains(".exe") || name.contains("netscope"),
            "解析结果应为可执行文件名: {name}"
        );
    }

    /// 无法打开的进程（PID 0 为 System Idle）应如实返回 None。
    #[test]
    fn pid_zero_returns_none() {
        assert!(resolve_process_name(0).is_none());
    }
}
