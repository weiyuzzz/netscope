//! 路由采集：GetBestInterfaceEx（连接归属接口）与 GetIpForwardTable2（默认网关）。
//!
//! - `best_interface_index`：给定远端 IP，查询系统真实路由决策的出接口索引，
//!   用于给连接打"所属网卡"标记（这是真实路由决策，不是推断）；
//! - `default_routes`：从活动路由表中提取默认路由（0.0.0.0/0、::/0），
//!   与 GetAdaptersAddresses 的 INCLUDE_GATEWAYS 互为校验。

use std::ffi::c_void;
use std::net::IpAddr;

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetBestInterfaceEx, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR, SOCKADDR_INET};

use super::{ip_to_sockaddr_inet, sockaddr_inet_to_ip, CollectorError};

/// 查询到指定远端地址的最优出接口索引（系统真实路由决策）。
/// 查询失败（如地址无效）返回 None，由调用方决定如何呈现。
pub fn best_interface_index(remote_ip: &str) -> Option<u32> {
    let sa = ip_to_sockaddr_inet(remote_ip).ok()?;
    let mut index: u32 = 0;
    let rc = unsafe {
        GetBestInterfaceEx(&sa as *const SOCKADDR_INET as *const SOCKADDR, &mut index)
    };
    if rc != ERROR_SUCCESS.0 {
        return None;
    }
    Some(index)
}

/// 提取默认路由：(接口索引, 下一跳 IP)。真实系统路由表，非推断。
pub fn default_routes() -> Result<Vec<(u32, String)>, CollectorError> {
    let mut out = Vec::new();
    for family in [AF_INET, AF_INET6] {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        unsafe {
            GetIpForwardTable2(family, &mut table).ok()?;
            if table.is_null() {
                continue;
            }
            let n = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
            for r in rows {
                // 默认路由：前缀长度 0 且前缀地址未指定
                if r.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                let prefix = &r.DestinationPrefix.Prefix;
                let family = prefix.si_family;
                let is_unspecified = if family == AF_INET {
                    std::mem::transmute::<_, [u8; 4]>(prefix.Ipv4.sin_addr)
                        .iter()
                        .all(|&b| b == 0)
                } else if family == AF_INET6 {
                    prefix.Ipv6.sin6_addr.u.Byte.iter().all(|&b| b == 0)
                } else {
                    false
                };
                if !is_unspecified {
                    continue;
                }
                // 下一跳有效（非 unspecified）才记录
                if let Some(next_hop) = sockaddr_inet_to_ip(&r.NextHop) {
                    let hop_unspecified = next_hop
                        .split('%')
                        .next()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .is_some_and(|a| a.is_unspecified());
                    if !hop_unspecified {
                        out.push((r.InterfaceIndex, next_hop));
                    }
                }
            }
            FreeMibTable(table as *const c_void);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实系统集成测试：公网地址必有路由决策（在有网络的环境下）。
    #[test]
    fn real_best_interface_for_public_ip() {
        match best_interface_index("8.8.8.8") {
            Some(idx) => assert!(idx > 0, "接口索引应为正数: {idx}"),
            None => panic!("8.8.8.8 的路由查询不应失败（无网络环境请跳过此机）"),
        }
    }

    /// 真实系统集成测试：系统存在默认路由（正常联网主机）。
    #[test]
    fn real_default_routes_exist() {
        let routes = default_routes().expect("GetIpForwardTable2 应成功");
        assert!(!routes.is_empty(), "联网主机应有默认路由");
        for (idx, hop) in &routes {
            assert!(*idx > 0, "接口索引应为正数");
            assert!(!hop.is_empty(), "下一跳不应为空");
        }
    }

    /// 无效地址应返回 None 而非 panic。
    #[test]
    fn invalid_ip_returns_none() {
        assert!(best_interface_index("not-an-ip").is_none());
        assert!(best_interface_index("999.999.999.999").is_none());
    }
}
