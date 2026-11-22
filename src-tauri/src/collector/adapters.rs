//! 网卡采集：GetAdaptersAddresses 输出 `models::NetworkInterface` 快照。
//!
//! 覆盖：IPv4/IPv6 地址、MAC、MTU、协商速率、DNS 服务器、网关、运行状态。
//! 使用 GAA_FLAG_INCLUDE_GATEWAYS 直接获取各接口网关（含 IPv6）。

use chrono::{DateTime, Utc};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_GATEWAYS,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK,
    IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::{
    IF_OPER_STATUS, IfOperStatusDormant, IfOperStatusDown, IfOperStatusLowerLayerDown,
    IfOperStatusNotPresent, IfOperStatusTesting, IfOperStatusUnknown, IfOperStatusUp,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use super::{sockaddr_to_ip, CollectorError};
use crate::models::interface::{InterfaceType, NetworkInterface, OperationalStatus};

/// 采集全部网卡信息快照（真实系统调用）。
pub fn list_adapters() -> Result<Vec<NetworkInterface>, CollectorError> {
    // 微软文档建议初始缓冲 15KB，空间不足时以返回值重试（最多 3 次）。
    const GAA_FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_SKIP_ANYCAST.0
            | GAA_FLAG_SKIP_MULTICAST.0
            | GAA_FLAG_INCLUDE_GATEWAYS.0
            | GAA_FLAG_INCLUDE_ALL_INTERFACES.0,
    );
    // 微软文档建议初始缓冲 15KB，空间不足时以返回值重试（最多 3 次）。
    let mut size: u32 = 15 * 1024;
    let mut head: *mut IP_ADAPTER_ADDRESSES_LH = std::ptr::null_mut();
    let mut owned_buf: Option<Vec<u64>> = None;

    for _ in 0..3 {
        // IP_ADAPTER_ADDRESSES_LH 含 u64 字段，需要 8 字节对齐 → 用 u64 数组作缓冲。
        let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAGS,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc == ERROR_SUCCESS.0 {
            head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            // 数据生命周期覆盖遍历过程；保住所有权防止内存被提前释放。
            owned_buf = Some(buf);
            break;
        }
        if rc != ERROR_BUFFER_OVERFLOW.0 {
            return Err(CollectorError::Api(format!(
                "GetAdaptersAddresses 失败: {}",
                rc
            )));
        }
    }

    if head.is_null() || owned_buf.is_none() {
        return Err(CollectorError::Api(
            "GetAdaptersAddresses 缓冲区分配失败".into(),
        ));
    }

    let now = Utc::now();
    let mut out = Vec::new();
    unsafe {
        let mut p = head;
        while !p.is_null() {
            let a = &*p;
            out.push(map_adapter(a, now));
            p = a.Next;
        }
    }
    // owned_buf 在此 drop，遍历已完成。
    drop(owned_buf);
    Ok(out)
}

unsafe fn map_adapter(a: &IP_ADAPTER_ADDRESSES_LH, now: DateTime<Utc>) -> NetworkInterface {
    let friendly_name = a.FriendlyName.to_string().unwrap_or_default();
    let description = a.Description.to_string().unwrap_or_default();
    let name = a.AdapterName.to_string().unwrap_or_default();

    // 单播地址（IPv4 / IPv6 混合）
    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
    let mut u = a.FirstUnicastAddress;
    while !u.is_null() {
        let ua = &*u;
        if let Some(ip) = sockaddr_to_ip(ua.Address.lpSockaddr) {
            if ip.contains(':') {
                ipv6_addresses.push(ip);
            } else {
                ipv4_addresses.push(ip);
            }
        }
        u = ua.Next;
    }

    // DNS 服务器
    let mut dns_servers = Vec::new();
    let mut d = a.FirstDnsServerAddress;
    while !d.is_null() {
        let da = &*d;
        if let Some(ip) = sockaddr_to_ip(da.Address.lpSockaddr) {
            dns_servers.push(ip);
        }
        d = da.Next;
    }

    // 网关（GAA_FLAG_INCLUDE_GATEWAYS）
    let mut gateways = Vec::new();
    let mut g = a.FirstGatewayAddress;
    while !g.is_null() {
        let ga = &*g;
        if let Some(ip) = sockaddr_to_ip(ga.Address.lpSockaddr) {
            gateways.push(ip);
        }
        g = ga.Next;
    }

    // MAC 地址
    let mac_len = a.PhysicalAddressLength as usize;
    let mac_address = if mac_len > 0 && mac_len <= a.PhysicalAddress.len() {
        Some(
            a.PhysicalAddress[..mac_len]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        None
    };

    // IfIndex 位于结构体头部匿名联合中（Anonymous1.Anonymous.IfIndex）
    let index = a.Anonymous1.Anonymous.IfIndex;

    NetworkInterface {
        index,
        name,
        friendly_name,
        description,
        if_type: map_if_type(a.IfType),
        operational_status: map_oper_status(a.OperStatus),
        speed_bps: a.TransmitLinkSpeed,
        mtu: a.Mtu,
        mac_address,
        ipv4_addresses,
        ipv6_addresses,
        dns_servers,
        gateways,
        first_seen: now,
        last_seen: now,
    }
}

fn map_if_type(t: u32) -> InterfaceType {
    match t {
        IF_TYPE_ETHERNET_CSMACD => InterfaceType::Ethernet,
        IF_TYPE_IEEE80211 => InterfaceType::Wifi,
        IF_TYPE_SOFTWARE_LOOPBACK => InterfaceType::Loopback,
        IF_TYPE_TUNNEL => InterfaceType::Tunnel,
        IF_TYPE_PPP => InterfaceType::Ppp,
        _ => InterfaceType::Other,
    }
}

fn map_oper_status(s: IF_OPER_STATUS) -> OperationalStatus {
    // windows-rs 常量为结构体常量，不能用作 match 模式，改用相等比较。
    if s == IfOperStatusUp {
        OperationalStatus::Up
    } else if s == IfOperStatusDown {
        OperationalStatus::Down
    } else if s == IfOperStatusTesting {
        OperationalStatus::Testing
    } else if s == IfOperStatusUnknown {
        OperationalStatus::Unknown
    } else if s == IfOperStatusDormant {
        OperationalStatus::Dormant
    } else if s == IfOperStatusNotPresent {
        OperationalStatus::NotPresent
    } else if s == IfOperStatusLowerLayerDown {
        OperationalStatus::LowerLayerDown
    } else {
        OperationalStatus::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实系统集成测试：本机至少有一块网卡，且存在有 IP 的接口。
    #[test]
    fn real_adapters_list_is_non_empty() {
        let ifaces = list_adapters().expect("GetAdaptersAddresses 应成功");
        assert!(!ifaces.is_empty(), "系统至少应枚举出一块网卡");
        assert!(
            ifaces.iter().any(|i| !i.ipv4_addresses.is_empty() || !i.ipv6_addresses.is_empty()),
            "至少应有一个接口持有 IP 地址"
        );
    }

    /// 真实系统集成测试：存在 Up 状态接口，其 MTU 合理。
    #[test]
    fn real_adapters_up_interface_fields_sane() {
        let ifaces = list_adapters().expect("GetAdaptersAddresses 应成功");
        let up = ifaces
            .iter()
            .filter(|i| {
                i.operational_status == OperationalStatus::Up
                    && i.if_type != InterfaceType::Loopback
            })
            .collect::<Vec<_>>();
        assert!(!up.is_empty(), "应存在非回环的 Up 接口");
        for i in &up {
            assert!(i.mtu > 0 && i.mtu <= 65536, "MTU 异常: {}", i.mtu);
            assert!(!i.name.is_empty(), "接口名称不应为空");
        }
    }
}
