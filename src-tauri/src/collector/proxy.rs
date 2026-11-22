//! Proxy Intelligence 采集器。
//!
//! 分机制检测（严格区分，不混同）：
//! 1. **WinInet 系统代理**：注册表 `HKCU\...\Internet Settings`（影响多数桌面应用）
//! 2. **WinHTTP 代理**：`WinHttpGetDefaultProxyConfiguration`（服务/系统组件）
//! 3. **本地代理服务**：环回监听端口特征 + 被其他进程连接的行为证据（推断，带置信度）
//! 4. **TUN / VPN / 虚拟网卡**：接口描述关键词 + IfType 分类
//! 5. **默认路由变化**：路由表快照差分
//! 6. **公网出口 IP**：仅用户主动触发（调用系统 curl，不在后台轮询）
//!
//! 所有推断关系携带 `Confidence`；不伪造代理内部链路。

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use windows::core::{PWSTR, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, GlobalFree, HGLOBAL};
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2, MIB_IF_ROW2};
use windows::Win32::NetworkManagement::Ndis::IF_OPER_STATUS;
use windows::Win32::Networking::WinHttp::{
    WinHttpGetDefaultProxyConfiguration, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_PROXY_INFO,
};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};

use super::CollectorError;
use crate::models::connection::{Connection, ConnectionState};
use crate::models::proxy::{
    Confidence, EgressInfo, ProxyLink, ProxyMechanism, ProxyProtocol, ProxyServer,
    VirtualAdapterKind, VpnInterface,
};

/// 将 UTF-8 字符串转为 NUL 结尾宽字符缓冲（供注册表 API 使用）。
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// 1. WinInet 系统代理（注册表）
// ---------------------------------------------------------------------------

/// 注册表中的 WinInet 代理配置（原始形态）。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SystemProxyInfo {
    pub enabled: bool,
    /// 各协议代理 "host:port"（WinInet 原始串按协议拆分）。
    pub servers: Vec<(ProxyProtocol, String, u16)>,
    /// PAC 自动配置 URL（可同时存在）。
    pub autoconfig_url: Option<String>,
}

/// 解析 WinInet ProxyServer 值。
///
/// 两种格式：
/// - `127.0.0.1:7890`（所有协议共用，WinInet 视为 HTTP 代理）
/// - `http=1.2.3.4:8080;https=1.2.3.4:8443;socks=1.2.3.4:1080`（分协议）
pub fn parse_proxy_server_value(
    value: &str,
    out: &mut Vec<(ProxyProtocol, String, u16)>,
) {
    if value.contains('=') {
        for part in value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((scheme, addr)) = part.split_once('=') else { continue };
            if let Some((host, port)) = parse_host_port(addr.trim()) {
                let proto = match scheme.to_ascii_lowercase().as_str() {
                    "http" => ProxyProtocol::Http,
                    "https" => ProxyProtocol::Https,
                    "socks" => ProxyProtocol::Unknown, // 4/5 无法从注册表区分
                    _ => ProxyProtocol::Unknown,
                };
                out.push((proto, host, port));
            }
        }
    } else if let Some((host, port)) = parse_host_port(value.trim()) {
        // 无前缀 = HTTP 代理（WinInet 行为）
        out.push((ProxyProtocol::Http, host, port));
    }
}

/// 解析 "host:port"（容忍 IPv6 [::1]:1080 形式）。
pub fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(stripped) = s.strip_prefix('[') {
        // IPv6 [::1]:1080
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        let port = rest.strip_prefix(':')?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.contains(':') {
        return None; // 裸 IPv6 无端口，不支持
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// 读取 WinInet 系统代理（真实注册表读取）。
pub fn read_system_proxy() -> Result<SystemProxyInfo, CollectorError> {
    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let mut info = SystemProxyInfo::default();
    let key_w = wide(KEY);
    let enable_name = wide("ProxyEnable");
    let server_name = wide("ProxyServer");
    let autoconfig_name = wide("AutoConfigURL");

    let mut enable: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(key_w.as_ptr()),
            PCWSTR::from_raw(enable_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut enable as *mut u32).cast()),
            Some(&mut size),
        )
    };
    info.enabled = rc == ERROR_SUCCESS && enable != 0;

    let mut buf = [0u16; 2048];
    let mut blen = (buf.len() as u32) * 2;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(key_w.as_ptr()),
            PCWSTR::from_raw(server_name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut blen),
        )
    };
    if rc == ERROR_SUCCESS && blen >= 2 {
        let len = (blen as usize) / 2;
        let value = String::from_utf16_lossy(&buf[..len.min(buf.len())]);
        let value = value.trim_end_matches('\0');
        parse_proxy_server_value(value, &mut info.servers);
    }

    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(key_w.as_ptr()),
            PCWSTR::from_raw(autoconfig_name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut blen),
        )
    };
    if rc == ERROR_SUCCESS && blen >= 2 {
        let len = (blen as usize) / 2;
        let value = String::from_utf16_lossy(&buf[..len.min(buf.len())]);
        info.autoconfig_url = Some(value.trim_end_matches('\0').to_string());
    }

    Ok(info)
}

/// 转换为统一 ProxyServer 列表（mechanism = WinInet，confidence = Confirmed）。
pub fn system_proxy_servers(info: &SystemProxyInfo) -> Vec<ProxyServer> {
    let now = Utc::now();
    info.servers
        .iter()
        .map(|(proto, host, port)| ProxyServer {
            id: format!("win_inet:{host}:{port}"),
            mechanism: ProxyMechanism::WinInet,
            protocol: *proto,
            host: host.clone(),
            port: *port,
            process_name: None,
            pid: None,
            source: "HKCU\\Internet Settings (ProxyEnable=1)".into(),
            confidence: Confidence::Confirmed,
            first_seen: now,
            last_seen: now,
            active: info.enabled,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 2. WinHTTP 代理
// ---------------------------------------------------------------------------

/// 读取 WinHTTP 默认代理（真实 API）。
pub fn read_winhttp_proxy() -> Result<Option<ProxyServer>, CollectorError> {
    unsafe {
        let mut info = WINHTTP_PROXY_INFO {
            dwAccessType: WINHTTP_ACCESS_TYPE_NO_PROXY,
            lpszProxy: PWSTR::null(),
            lpszProxyBypass: PWSTR::null(),
        };
        WinHttpGetDefaultProxyConfiguration(&mut info)
            .map_err(CollectorError::Windows)?;

        if info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY
            && !info.lpszProxy.is_null()
        {
            let proxy = info.lpszProxy.to_string().unwrap_or_default();
            let _ = GlobalFree(Some(HGLOBAL(info.lpszProxy.as_ptr().cast())));
            let _ = GlobalFree(Some(HGLOBAL(info.lpszProxyBypass.as_ptr().cast())));

            let now = Utc::now();
            let mut servers = Vec::new();
            parse_proxy_server_value(&proxy, &mut servers);
            let (proto, host, port) = servers
                .first()
                .cloned()
                .unwrap_or((ProxyProtocol::Unknown, proxy.clone(), 0));
            return Ok(Some(ProxyServer {
                id: format!("win_http:{host}:{port}"),
                mechanism: ProxyMechanism::WinHttp,
                protocol: proto,
                host,
                port,
                process_name: None,
                pid: None,
                source: "WinHttpGetDefaultProxyConfiguration (NAMED_PROXY)".into(),
                confidence: Confidence::Confirmed,
                first_seen: now,
                last_seen: now,
                active: true,
            }));
        }

        // NO_PROXY / AUTOMATIC_PROXY：如实返回 None（AUTOMATIC 带说明）
        let _ = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
        let _ = GlobalFree(Some(HGLOBAL(info.lpszProxy.as_ptr().cast())));
        let _ = GlobalFree(Some(HGLOBAL(info.lpszProxyBypass.as_ptr().cast())));
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// 3. 本地代理服务（环回监听 + 行为证据）
// ---------------------------------------------------------------------------

/// 常见代理端口 → 协议推断（端口惯例 ≠ 协议确认，置信度 Inferred）。
const WELL_KNOWN_PROXY_PORTS: &[(u16, ProxyProtocol, &str)] = &[
    (1080, ProxyProtocol::Socks5, "SOCKS 注册端口"),
    (1081, ProxyProtocol::Socks5, "SOCKS 备用"),
    (9050, ProxyProtocol::Socks5, "Tor 默认"),
    (7890, ProxyProtocol::Http, "Clash mixed 默认"),
    (7891, ProxyProtocol::Socks5, "Clash SOCKS 默认"),
    (7897, ProxyProtocol::Http, "Clash Verge 默认"),
    (8118, ProxyProtocol::Http, "Privoxy 默认"),
    (8888, ProxyProtocol::Http, "常见 HTTP 代理"),
    (3128, ProxyProtocol::Http, "Squid 默认"),
    (8080, ProxyProtocol::Http, "常见 HTTP 代理"),
    (10808, ProxyProtocol::Socks5, "v2rayN 默认"),
    (10809, ProxyProtocol::Http, "v2rayN 默认"),
    (20170, ProxyProtocol::Http, "常见 HTTP 代理"),
    (20171, ProxyProtocol::Socks5, "常见 SOCKS"),
];

/// 环回监听 + 客户端连接行为 → 本地代理服务与使用链路（推断）。
///
/// 判据（诚实分级）：
/// - 已知代理端口上有监听 → `Inferred`（端口惯例证据）；
/// - 该监听被 ≥3 个其他进程连接 → 即使端口未知也标记 `Speculative`；
/// - 客户端进程 → 代理：`ProxyLink`（evidence = time_window）。
pub fn detect_local_proxies(
    tcp: &[Connection],
) -> (Vec<ProxyServer>, Vec<ProxyLink>) {
    let now = Utc::now();

    // 环回监听（127.0.0.1 / 0.0.0.0 / ::）→ listener_port → (pid, name)
    let mut listeners: HashMap<u16, &Connection> = HashMap::new();
    for c in tcp {
        if c.state == ConnectionState::Listen
            && (c.local.ip == "127.0.0.1" || c.local.ip == "0.0.0.0" || c.local.ip == "::")
            && c.pid != 0
            && c.pid != 4
        {
            listeners.entry(c.local.port).or_insert(c);
        }
    }

    // 客户端连接计数：dst=127.0.0.1:port 且发起进程 != 监听进程
    let mut clients: HashMap<u16, HashMap<u32, usize>> = HashMap::new();
    for c in tcp {
        if let Some(remote) = &c.remote {
            if remote.ip == "127.0.0.1" && c.state == ConnectionState::Established {
                if let Some(l) = listeners.get(&remote.port) {
                    if l.pid != c.pid {
                        clients
                            .entry(remote.port)
                            .or_default()
                            .entry(c.pid)
                            .or_insert(0);
                        *clients
                            .get_mut(&remote.port)
                            .unwrap()
                            .get_mut(&c.pid)
                            .unwrap() += 1;
                    }
                }
            }
        }
    }

    let mut servers = Vec::new();
    let mut links = Vec::new();

    for (port, listener) in &listeners {
        let known = WELL_KNOWN_PROXY_PORTS.iter().find(|(p, _, _)| p == port);
        let client_pids: Vec<u32> = clients.get(port).map(|m| m.keys().cloned().collect()).unwrap_or_default();
        let client_count = client_pids.len();

        let (proto, port_note, confidence) = match known {
            Some((_, proto, note)) => (*proto, *note, Confidence::Inferred),
            None => {
                if client_count >= 3 {
                    (ProxyProtocol::Unknown, "被多个进程连接", Confidence::Speculative)
                } else {
                    continue; // 无证据：不标记（诚实优先）
                }
            }
        };

        let server = ProxyServer {
            id: format!("local_listener:127.0.0.1:{port}"),
            mechanism: ProxyMechanism::LocalListener,
            protocol: proto,
            host: "127.0.0.1".into(),
            port: *port,
            process_name: listener.process_name.clone(),
            pid: Some(listener.pid),
            source: format!("环回监听（{port_note}）；客户端进程数 {client_count}"),
            confidence,
            first_seen: now,
            last_seen: now,
            active: true,
        };
        let server_id = server.id.clone();

        for pid in client_pids {
            let client_name = tcp
                .iter()
                .find(|c| c.pid == pid)
                .and_then(|c| c.process_name.clone());
            links.push(ProxyLink {
                pid,
                process_name: client_name,
                proxy_id: server_id.clone(),
                evidence: crate::models::topology::CorrelationEvidence::TimeWindow,
                confidence: Confidence::Inferred,
                observed_connections: *clients.get(port).unwrap().get(&pid).unwrap() as u32,
                last_seen: now,
            });
        }
        servers.push(server);
    }

    (servers, links)
}

// ---------------------------------------------------------------------------
// 4. TUN / VPN / 虚拟网卡分类
// ---------------------------------------------------------------------------

/// 由适配器快照 + 默认路由归属分类 VPN / 虚拟网卡。
///
/// 分类依据全部来自 description / friendly name / IfType（证据型，不猜测）。
pub fn classify_vpn_interfaces(
    interfaces: &[crate::models::interface::NetworkInterface],
    default_routes: &[(u32, String)],
) -> Vec<VpnInterface> {
    let now = Utc::now();
    interfaces
        .iter()
        .filter(|i| classify_kind(i) != VirtualAdapterKind::Physical)
        .map(|i| {
            let default_owner = default_routes.iter().any(|(idx, _)| *idx == i.index);
            let gateway = default_routes
                .iter()
                .find(|(idx, _)| *idx == i.index)
                .map(|(_, gw)| gw.clone());
            VpnInterface {
                if_index: i.index,
                kind: classify_kind(i),
                friendly_name: i.friendly_name.clone(),
                description: i.description.clone(),
                ipv4_addresses: i.ipv4_addresses.clone(),
                ipv6_addresses: i.ipv6_addresses.clone(),
                is_default_route_owner: default_owner,
                gateway_of_default: gateway,
                speed_bps: i.speed_bps,
                operational_status: format!("{:?}", i.operational_status).to_lowercase(),
                first_seen: now,
                last_seen: now,
                active: true,
            }
        })
        .collect()
}

/// 分类单个适配器（证据关键词匹配，全部小写比较）。
pub fn classify_kind(
    i: &crate::models::interface::NetworkInterface,
) -> VirtualAdapterKind {
    if i.if_type == crate::models::interface::InterfaceType::Loopback {
        return VirtualAdapterKind::Loopback;
    }
    let text = format!("{} {}", i.description, i.friendly_name).to_lowercase();
    if text.contains("tailscale") {
        return VirtualAdapterKind::Tailscale;
    }
    if text.contains("wireguard") {
        return VirtualAdapterKind::WireGuard;
    }
    if text.contains("tap-windows") || text.contains("tap adapter") || text.contains("openvpn") {
        return VirtualAdapterKind::OpenVpnTap;
    }
    if text.contains("hyper-v")
        || text.contains("vethernet")
        || text.contains("wsl")
        || text.contains("docker")
        || text.contains("default switch")
        || text.contains("virtual switch")
    {
        return VirtualAdapterKind::HyperVSwitch;
    }
    if i.if_type == crate::models::interface::InterfaceType::Tunnel
        || text.contains("tun")
        || text.contains("vpn")
    {
        return VirtualAdapterKind::Tun;
    }
    if text.contains("virtual") {
        return VirtualAdapterKind::OtherVirtual;
    }
    VirtualAdapterKind::Physical
}

// ---------------------------------------------------------------------------
// 5. 接口流量计数器（GetIfTable2，WAL 差分在 runtime 层做）
// ---------------------------------------------------------------------------

/// 接口字节计数快照（差分前原始值）。
#[derive(Debug, Clone, Default)]
pub struct InterfaceCounters {
    pub entries: HashMap<u32, (u64, u64, IF_OPER_STATUS)>, // (in_octets, out_octets, status)
}

/// 读取全部接口的字节计数器（真实系统调用）。
pub fn read_interface_counters() -> Result<InterfaceCounters, CollectorError> {
    let mut out = InterfaceCounters::default();
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        GetIfTable2(&mut table).ok().map_err(CollectorError::Windows)?;
        if !table.is_null() {
            let n = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
            for r in rows {
                let row: &MIB_IF_ROW2 = r;
                out.entries.insert(
                    row.InterfaceIndex,
                    (row.InOctets, row.OutOctets, row.OperStatus),
                );
            }
            FreeMibTable(table as *const std::ffi::c_void);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 6. 公网出口探测（用户主动触发）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IpinfoResponse {
    ip: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    #[serde(default)]
    org: Option<String>,
}

/// 通过系统 curl 探测公网出口（用户主动触发；默认服务 ipinfo.io，含 ASN/地理）。
///
/// 失败如实返回 error 字段（网络不通 / 无 curl / 服务不可达），不静默。
pub fn probe_egress_ip() -> EgressInfo {
    let mut info = EgressInfo::default();
    info.timestamp = Some(Utc::now());

    match run_curl_json("https://ipinfo.io/json", 8) {
        Ok(body) => {
            if let Ok(parsed) = serde_json::from_str::<IpinfoResponse>(&body) {
                info.ip = parsed.ip;
                info.country = parsed.country;
                info.region = parsed.region;
                info.city = parsed.city;
                if let Some(org) = parsed.org {
                    // org 形如 "AS4134 CHINANET-JS" → 取首段为 ASN
                    let mut parts = org.splitn(2, ' ');
                    info.asn = parts.next().map(|s| s.to_string());
                    info.org = parts.next().map(|s| s.to_string());
                }
                info.source = Some("ipinfo.io".into());
                return info;
            }
            info.error = Some(format!("ipinfo 响应解析失败: {body:.120}"));
        }
        Err(e) => info.error = Some(e),
    }

    // 降级：ipify 只给 IP
    match run_curl_text("https://api.ipify.org", 8) {
        Ok(ip) if !ip.trim().is_empty() => {
            info.ip = Some(ip.trim().to_string());
            info.source = Some("ipify".into());
        }
        Ok(_) => {}
        Err(e) => {
            info.error = Some(format!(
                "{}; ipify 亦失败: {e}",
                info.error.unwrap_or_default()
            ))
        }
    }
    info
}

/// 调用系统 curl（Win10 1803+ 自带），隐藏窗口，限超时。
fn run_curl_text(url: &str, timeout_secs: u64) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let out = Command::new("curl.exe")
        .args(["-s", "--max-time", &timeout_secs.to_string(), url])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("curl 执行失败: {e}"))?;
    if !out.status.success() {
        return Err(format!("curl 退出码 {}", out.status.code().unwrap_or(-1)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn run_curl_json(url: &str, timeout_secs: u64) -> Result<String, String> {
    run_curl_text(url, timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::adapters;

    #[test]
    fn parse_simple_proxy_value() {
        let mut out = Vec::new();
        parse_proxy_server_value("127.0.0.1:7890", &mut out);
        assert_eq!(
            out,
            vec![(ProxyProtocol::Http, "127.0.0.1".into(), 7890)]
        );
    }

    #[test]
    fn parse_per_protocol_value() {
        let mut out = Vec::new();
        parse_proxy_server_value("http=1.2.3.4:8080;https=1.2.3.4:8443;socks=1.2.3.4:1080", &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], (ProxyProtocol::Http, "1.2.3.4".into(), 8080));
        assert_eq!(out[1], (ProxyProtocol::Https, "1.2.3.4".into(), 8443));
        assert_eq!(out[2], (ProxyProtocol::Unknown, "1.2.3.4".into(), 1080));
    }

    #[test]
    fn parse_ipv6_proxy() {
        let mut out = Vec::new();
        parse_proxy_server_value("[::1]:1080", &mut out);
        assert_eq!(out, vec![(ProxyProtocol::Http, "::1".into(), 1080)]);
    }

    #[test]
    fn invalid_values_ignored() {
        let mut out = Vec::new();
        parse_proxy_server_value("not-a-proxy", &mut out);
        parse_proxy_server_value("", &mut out);
        parse_proxy_server_value("1.2.3.4:notaport", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn local_proxy_inference_requires_evidence() {
        use crate::models::connection::{derive_connection_id, Endpoint, Protocol};
        let now = Utc::now();
        let mk = |pid: u32, lport: u16, rip: &str, rport: u16, state: ConnectionState| {
            let local = Endpoint { ip: "127.0.0.1".into(), port: lport };
            let remote = Endpoint { ip: rip.into(), port: rport };
            Connection {
                id: derive_connection_id(Protocol::Tcp, pid, &local, Some(&remote)),
                pid,
                process_name: Some(format!("p{pid}.exe")),
                protocol: Protocol::Tcp,
                local,
                remote: Some(remote),
                state,
                interface_index: None,
                first_seen: now,
                last_seen: now,
                bytes_sent: 0,
                bytes_received: 0,
            }
        };

        // 已知端口监听 → Inferred
        let tcp = vec![mk(100, 7890, "0.0.0.0", 0, ConnectionState::Listen)];
        let (servers, links) = detect_local_proxies(&tcp);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].confidence, Confidence::Inferred);
        assert_eq!(servers[0].port, 7890);
        assert!(links.is_empty(), "无客户端连接不应产生使用链路");

        // 未知端口 + 3 个客户端进程 → Speculative + 3 条链路
        let tcp = vec![
            mk(100, 29999, "127.0.0.1", 0, ConnectionState::Listen),
            mk(1, 40001, "127.0.0.1", 29999, ConnectionState::Established),
            mk(2, 40002, "127.0.0.1", 29999, ConnectionState::Established),
            mk(3, 40003, "127.0.0.1", 29999, ConnectionState::Established),
        ];
        let (servers, links) = detect_local_proxies(&tcp);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].confidence, Confidence::Speculative);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].confidence, Confidence::Inferred);

        // 未知端口 + 1 个客户端（如本地 dev server）→ 不标记
        let tcp = vec![
            mk(100, 3000, "127.0.0.1", 0, ConnectionState::Listen),
            mk(1, 40001, "127.0.0.1", 3000, ConnectionState::Established),
        ];
        let (servers, _) = detect_local_proxies(&tcp);
        assert!(servers.is_empty(), "无证据端口不得标记为代理");
    }

    #[test]
    fn vpn_classification_by_description() {
        use crate::models::interface::{NetworkInterface, OperationalStatus, InterfaceType};
        let now = Utc::now();
        let mk = |index: u32, desc: &str, name: &str, if_type: InterfaceType| NetworkInterface {
            index,
            name: format!("if{index}"),
            friendly_name: name.into(),
            description: desc.into(),
            if_type,
            operational_status: OperationalStatus::Up,
            speed_bps: 0,
            mtu: 1500,
            mac_address: None,
            ipv4_addresses: vec!["10.0.0.1".into()],
            ipv6_addresses: vec![],
            dns_servers: vec![],
            gateways: vec![],
            first_seen: now,
            last_seen: now,
        };

        let ifaces = vec![
            mk(1, "Tailscale Tunnel", "Tailscale", InterfaceType::Tunnel),
            mk(2, "OpenVPN TAP-Windows6", "以太网 2", InterfaceType::Ethernet),
            mk(3, "Hyper-V Virtual Ethernet Adapter", "vEthernet (WSL)", InterfaceType::Ethernet),
            mk(4, "WireGuard Tunnel", "WireGuard", InterfaceType::Tunnel),
            mk(5, "Realtek PCIe GbE", "以太网", InterfaceType::Ethernet),
        ];
        let vpns = classify_vpn_interfaces(&ifaces, &[]);
        let kinds: Vec<VirtualAdapterKind> = vpns.iter().map(|v| v.kind).collect();
        assert!(kinds.contains(&VirtualAdapterKind::Tailscale));
        assert!(kinds.contains(&VirtualAdapterKind::OpenVpnTap));
        assert!(kinds.contains(&VirtualAdapterKind::HyperVSwitch));
        assert!(kinds.contains(&VirtualAdapterKind::WireGuard));
        assert_eq!(kinds.len(), 4, "物理网卡不应被分类为虚拟");
    }

    #[test]
    fn default_route_owner_flag() {
        use crate::models::interface::{NetworkInterface, OperationalStatus, InterfaceType};
        let now = Utc::now();
        let iface = NetworkInterface {
            index: 7,
            name: "if7".into(),
            friendly_name: "Tailscale".into(),
            description: "Tailscale Tunnel".into(),
            if_type: InterfaceType::Tunnel,
            operational_status: OperationalStatus::Up,
            speed_bps: 0,
            mtu: 1280,
            mac_address: None,
            ipv4_addresses: vec!["100.64.1.2".into()],
            ipv6_addresses: vec![],
            dns_servers: vec![],
            gateways: vec![],
            first_seen: now,
            last_seen: now,
        };
        let vpns = classify_vpn_interfaces(&[iface], &[(7, "100.64.0.1".into())]);
        assert_eq!(vpns.len(), 1);
        assert!(vpns[0].is_default_route_owner, "默认路由经此接口应如实标注");
        assert_eq!(vpns[0].gateway_of_default.as_deref(), Some("100.64.0.1"));
    }

    // ---- 真实系统集成测试 ----

    #[test]
    fn real_system_proxy_read() {
        // 无论是否启用代理，读取本身必须成功
        let info = read_system_proxy().expect("注册表读取应成功");
        for (proto, host, port) in &info.servers {
            assert!(!host.is_empty());
            assert!(*port > 0);
            let _ = proto;
        }
    }

    #[test]
    fn real_winhttp_proxy_read() {
        let result = read_winhttp_proxy().expect("WinHTTP API 应成功");
        if let Some(s) = result {
            assert!(!s.host.is_empty());
        }
    }

    #[test]
    fn real_interface_counters() {
        let counters = read_interface_counters().expect("GetIfTable2 应成功");
        assert!(!counters.entries.is_empty(), "至少有一个接口");
    }

    #[test]
    fn real_vpn_classification_on_this_machine() {
        let ifaces = adapters::list_adapters().unwrap();
        let routes = crate::collector::routes::default_routes().unwrap_or_default();
        let vpns = classify_vpn_interfaces(&ifaces, &routes);
        // 本机运行 Tailscale（见 docs/COLLECTION.md），应能识别
        assert!(
            vpns.iter().any(|v| v.kind == VirtualAdapterKind::Tailscale),
            "本机 Tailscale 接口应被识别（实测环境）"
        );
    }
}
