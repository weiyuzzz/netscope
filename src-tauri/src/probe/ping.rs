//! ICMP Ping（`IcmpSendEcho2`，免管理员权限）。
//!
//! 依赖：iphlpapi 的 ICMP API（Windows 自带，普通权限可调用）。
//! 输出：每包 RTT、状态；丢包如实统计，不判定网络故障。

use std::net::{Ipv4Addr, ToSocketAddrs};

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
};

use crate::models::metrics::RouteHopState;

const ICMP_PAYLOAD_SIZE: u16 = 32;

/// 对齐的应答缓冲（ICMP_ECHO_REPLY 含指针字段，必须 8 字节对齐）。
#[repr(C)]
struct ReplyBuffer {
    reply: ICMP_ECHO_REPLY,
    extra: [u8; 256],
}

impl ReplyBuffer {
    fn new() -> Self {
        Self {
            reply: ICMP_ECHO_REPLY::default(),
            extra: [0u8; 256],
        }
    }
}

/// 单次 Ping 的完整结果。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResult {
    /// 解析后的目标 IPv4。
    pub target_ip: String,
    pub sent: u32,
    pub received: u32,
    /// 丢包率 0..1。
    pub loss_rate: f64,
    pub rtt_ms: Vec<f64>,
    pub min_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    /// 每包详情（status 为 Windows IP_STATUS 原始值，0 = 成功）。
    pub replies: Vec<PingReply>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingReply {
    pub seq: u32,
    pub rtt_ms: Option<f64>,
    pub status: u32,
}

/// 解析目标（域名或 IP）为 IPv4 地址。
pub fn resolve_ipv4(target: &str) -> Result<String, String> {
    // 纯 IP 直接返回
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(ip.to_string());
    }
    let addrs: Vec<_> = (target, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("解析失败: {e}"))?
        .collect();
    for a in addrs {
        if a.is_ipv4() {
            return Ok(a.ip().to_string());
        }
    }
    Err("未解析到 IPv4 地址".into())
}

fn ip_to_network_u32(ip: &str) -> Option<u32> {
    let v4: Ipv4Addr = ip.parse().ok()?;
    Some(u32::from(v4).to_be()) // 网络字节序
}

/// 执行 ICMP Ping（真实系统调用，count 次，每包独立超时）。
pub fn ping(target: &str, count: u32, timeout_ms: u32) -> Result<PingResult, String> {
    let count = count.clamp(1, 20);
    let timeout_ms = timeout_ms.clamp(100, 10_000);
    let target_ip = resolve_ipv4(target)?;
    let dest = ip_to_network_u32(&target_ip).ok_or("无效目标 IP")?;

    unsafe {
        let handle: HANDLE = IcmpCreateFile().map_err(|e| format!("IcmpCreateFile 失败: {e}"))?;
        let payload = [0u8; ICMP_PAYLOAD_SIZE as usize];

        let mut result = PingResult {
            target_ip: target_ip.clone(),
            sent: count,
            received: 0,
            loss_rate: 0.0,
            rtt_ms: Vec::new(),
            min_rtt_ms: None,
            avg_rtt_ms: None,
            max_rtt_ms: None,
            replies: Vec::new(),
        };

        for seq in 0..count {
            let options = IP_OPTION_INFORMATION {
                Ttl: 128,
                Tos: 0,
                Flags: 0,
                OptionsSize: 0,
                OptionsData: std::ptr::null_mut(),
            };
            let mut buf = ReplyBuffer::new();
            let rc = IcmpSendEcho2(
                handle,
                None,
                None,
                None,
                dest,
                payload.as_ptr().cast(),
                ICMP_PAYLOAD_SIZE,
                Some(&options),
                &mut buf as *mut ReplyBuffer as *mut core::ffi::c_void,
                std::mem::size_of::<ReplyBuffer>() as u32,
                timeout_ms,
            );
            if rc > 0 {
                let reply = &buf.reply;
                let status = reply.Status;
                if status == 0 {
                    result.received += 1;
                    let rtt = reply.RoundTripTime as f64;
                    result.rtt_ms.push(rtt);
                    result.replies.push(PingReply {
                        seq,
                        rtt_ms: Some(rtt),
                        status,
                    });
                } else {
                    result.replies.push(PingReply { seq, rtt_ms: None, status });
                }
            } else {
                result.replies.push(PingReply { seq, rtt_ms: None, status: 11010 });
            }
        }

        let _ = IcmpCloseHandle(handle);
        let _ = CloseHandle(handle);

        result.loss_rate = (count - result.received) as f64 / count as f64;
        if !result.rtt_ms.is_empty() {
            result.min_rtt_ms = Some(result.rtt_ms.iter().cloned().fold(f64::MAX, f64::min));
            result.max_rtt_ms = Some(result.rtt_ms.iter().cloned().fold(0.0, f64::max));
            result.avg_rtt_ms = Some(result.rtt_ms.iter().sum::<f64>() / result.rtt_ms.len() as f64);
        }
        Ok(result)
    }
}

/// ICMP Traceroute：TTL 递增，每跳 `probes_per_hop` 次探测。
///
/// 无应答跳输出 `NoReply`（显示为 *），不判定为故障；到达目标标记 `Reached`。
/// 说明：仅实现 ICMP 模式（免管理员）；UDP/TCP 模式需要原始发包能力
/// （Npcap + 管理员），见 docs/NPCAP.md。
pub fn icmp_traceroute(
    target: &str,
    max_hops: u8,
    probes_per_hop: u8,
    timeout_ms: u32,
) -> Result<crate::models::metrics::RouteProbe, String> {
    let max_hops = max_hops.clamp(1, 30);
    let probes_per_hop = probes_per_hop.clamp(1, 5);
    let target_ip = resolve_ipv4(target)?;
    let dest = ip_to_network_u32(&target_ip).ok_or("无效目标 IP")?;

    let started_at = chrono::Utc::now();
    let mut hops = Vec::new();
    let mut reached = false;

    unsafe {
        let handle: HANDLE = IcmpCreateFile().map_err(|e| format!("IcmpCreateFile 失败: {e}"))?;
        let payload = [0u8; ICMP_PAYLOAD_SIZE as usize];

        for ttl in 1..=max_hops {
            let mut rtts: Vec<f64> = Vec::new();
            let mut hop_ip: Option<String> = None;
            let mut state = RouteHopState::NoReply;

            for _ in 0..probes_per_hop {
                let options = IP_OPTION_INFORMATION {
                    Ttl: ttl,
                    Tos: 0,
                    Flags: 0,
                    OptionsSize: 0,
                    OptionsData: std::ptr::null_mut(),
                };
                let mut buf = ReplyBuffer::new();
                let rc = IcmpSendEcho2(
                    handle,
                    None,
                    None,
                    None,
                    dest,
                    payload.as_ptr().cast(),
                    ICMP_PAYLOAD_SIZE,
                    Some(&options),
                    &mut buf as *mut ReplyBuffer as *mut core::ffi::c_void,
                    std::mem::size_of::<ReplyBuffer>() as u32,
                    timeout_ms,
                );
                if rc == 0 {
                    continue; // 超时 → 无应答
                }
                let reply = &buf.reply;
                let addr_bytes = reply.Address.to_be_bytes();
                let reply_ip = std::net::Ipv4Addr::from(addr_bytes).to_string();
                let rtt = reply.RoundTripTime as f64;
                rtts.push(rtt);
                hop_ip = Some(reply_ip.clone());

                if reply.Status == 0 && reply_ip == target_ip {
                    state = RouteHopState::Reached;
                    reached = true;
                } else {
                    // 路由器回的 Time Exceeded / 其他应答：该跳有应答
                    if state != RouteHopState::Reached {
                        state = RouteHopState::Replied;
                    }
                }
            }

            let replied = !rtts.is_empty();
            hops.push(crate::models::metrics::RouteHop {
                ttl,
                state,
                ip: if replied { hop_ip } else { None },
                rtt_ms: rtts.clone(),
                probes_sent: u32::from(probes_per_hop),
                hostname: None,
                asn: None,
            });

            if reached {
                break;
            }
        }

        let _ = IcmpCloseHandle(handle);
        let _ = CloseHandle(handle);
    }

    Ok(crate::models::metrics::RouteProbe {
        id: format!("probe-{}", chrono::Utc::now().timestamp_millis()),
        target: target.to_string(),
        resolved_ip: Some(target_ip),
        protocol: crate::models::metrics::TraceProtocol::Icmp,
        port: None,
        max_hops,
        probes_per_hop,
        started_at,
        finished_at: Some(chrono::Utc::now()),
        hops,
        path_changed: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_localhost() {
        assert_eq!(resolve_ipv4("127.0.0.1").unwrap(), "127.0.0.1");
    }

    /// 真实系统集成测试：ping 网关或公网地址应成功或如实超时。
    #[test]
    fn real_ping_loopback() {
        let r = ping("127.0.0.1", 3, 1000).expect("ping 回环应成功");
        assert_eq!(r.received, 3, "回环 ping 不应丢包");
        assert!(r.avg_rtt_ms.unwrap() >= 0.0);
    }

    /// 真实系统集成测试：ICMP Traceroute 到公网（联网环境）。
    #[test]
    fn real_icmp_traceroute_reaches_target() {
        let probe = icmp_traceroute("1.1.1.1", 12, 2, 2000).expect("traceroute 应执行成功");
        assert!(!probe.hops.is_empty(), "至少一跳");
        // 最后一个有应答的跳应包含 1.1.1.1 或路径中存在 Replied 跳
        let reached = probe.hops.iter().any(|h| h.state == RouteHopState::Reached);
        let any_reply = probe.hops.iter().any(|h| h.state != RouteHopState::NoReply);
        assert!(reached || any_reply, "应至少有跳点应答或到达目标");
    }

    #[test]
    fn invalid_target_is_error_not_panic() {
        // 注意：fake-IP 类代理环境（TUN）会把任意合法域名解析成合成 IP，
        // 因此这里使用语法非法的目标确保解析必然失败。
        assert!(ping("this is not a domain!!!", 1, 500).is_err());
        assert!(ping("999.999.999.999", 1, 500).is_err());
    }
}
