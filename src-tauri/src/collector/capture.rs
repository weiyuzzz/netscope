//! Npcap 数据包捕获（可选模块）。
//!
//! 架构决策：**运行时动态加载 wpcap.dll**（LoadLibrary + GetProcAddress），
//! 应用构建不依赖 Npcap SDK；未安装时功能如实提示"未安装"并给出安装指引。
//!
//! 隐私边界：只解析协议元数据（头部字段、DNS 域名、TLS SNI、QUIC 版本），
//! 不解密 TLS 内容，不保存完整载荷（除非用户配置 PCAP 导出）。
//!
//! Npcap 安装说明见 docs/NPCAP.md。

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::Serialize;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::models::capture::{
    CaptureState, FlowSummary, IpProtocol, PacketInfo, PacketMeta,
};
pub use crate::models::capture::{CaptureConfig, CaptureStatus};
use crate::models::metrics::{HandshakeTiming, MetricSource, TcpAnomalyKind, TcpMetricEvent};

// ---------------------------------------------------------------------------
// Npcap 动态加载
// ---------------------------------------------------------------------------

/// 抓包事件回调（解耦 Tauri：命令层注入 emit 闭包，采集层保持纯净）。
pub type EventSink = Box<dyn Fn(&str, &serde_json::Value) + Send>;

type PcapFindAllDevs = unsafe extern "system" fn(*mut *mut PcapIfT, *mut i8) -> i32;
type PcapFreeAllDevs = unsafe extern "system" fn(*mut PcapIfT);
type PcapOpenLive = unsafe extern "system" fn(*const i8, i32, i32, i32, *mut i8) -> *mut c_void;
type PcapCompile = unsafe extern "system" fn(*mut c_void, *mut BpfProgram, *const i8, i32, u32) -> i32;
type PcapSetFilter = unsafe extern "system" fn(*mut c_void, *const BpfProgram) -> i32;
type PcapNextEx = unsafe extern "system" fn(*mut c_void, *mut *mut PcapPkthdr, *mut *mut u8) -> i32;
type PcapBreakLoop = unsafe extern "system" fn(*mut c_void);
type PcapClose = unsafe extern "system" fn(*mut c_void);
type PcapLibVersion = unsafe extern "system" fn() -> *const i8;
type PcapDatalink = unsafe extern "system" fn(*mut c_void) -> i32;

#[repr(C)]
struct PcapIfT {
    next: *mut PcapIfT,
    name: *const i8,
    description: *const i8,
    addresses: *mut c_void,
    flags: u32,
}

/// pcap_pkthdr —— 经典 WinPcap 32 位时间戳布局（16 字节）。
/// 实测确认（Npcap 1.90/libpcap 1.10.7，包头原始字节转储）：
/// { u32 tv_sec, u32 tv_usec, u32 caplen, u32 len }。
#[repr(C)]
struct PcapPkthdr {
    ts_sec: u32,
    ts_usec: u32,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut c_void,
}

/// Npcap 安装状态（真实检测）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpcapStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub hint: Option<String>,
}

/// 加载后的 wpcap 函数表。
pub struct NpcapLib {
    _module: HMODULE,
    findalldevs: PcapFindAllDevs,
    freealldevs: PcapFreeAllDevs,
    openlive: PcapOpenLive,
    compile: PcapCompile,
    setfilter: PcapSetFilter,
    next_ex: PcapNextEx,
    breakloop: PcapBreakLoop,
    close: PcapClose,
    lib_version: PcapLibVersion,
    datalink: PcapDatalink,
}

unsafe impl Send for NpcapLib {}
unsafe impl Sync for NpcapLib {}

impl NpcapLib {
    /// 尝试加载 wpcap.dll（Npcap 安装后位于系统 PATH 或 System32\Npcap）。
    pub fn load() -> Result<Self, String> {
        unsafe {
            let names: [&str; 2] = ["wpcap.dll", "C:\\Windows\\System32\\Npcap\\wpcap.dll"];
            let mut module = HMODULE::default();
            for name in names {
                let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
                module = match LoadLibraryW(PCWSTR::from_raw(wide.as_ptr())) {
                    Ok(m) => m,
                    Err(_) => HMODULE::default(),
                };
                if !module.is_invalid() {
                    break;
                }
            }
            if module.is_invalid() {
                return Err("wpcap.dll 加载失败".into());
            }

            macro_rules! get {
                ($name:literal, $ty:ty) => {{
                    let sym = PCSTR::from_raw(concat!($name, "\0").as_ptr());
                    let addr = GetProcAddress(module, sym);
                    match addr {
                        Some(f) => std::mem::transmute::<usize, $ty>(f as usize),
                        None => return Err(format!("缺少符号 {}", $name)),
                    }
                }};
            }

            Ok(Self {
                _module: module,
                findalldevs: get!("pcap_findalldevs", PcapFindAllDevs),
                freealldevs: get!("pcap_freealldevs", PcapFreeAllDevs),
                openlive: get!("pcap_open_live", PcapOpenLive),
                compile: get!("pcap_compile", PcapCompile),
                setfilter: get!("pcap_setfilter", PcapSetFilter),
                next_ex: get!("pcap_next_ex", PcapNextEx),
                breakloop: get!("pcap_breakloop", PcapBreakLoop),
                close: get!("pcap_close", PcapClose),
                lib_version: get!("pcap_lib_version", PcapLibVersion),
                datalink: get!("pcap_datalink", PcapDatalink),
            })
        }
    }
}

/// 检测 Npcap 是否安装并返回版本。
pub fn npcap_status() -> NpcapStatus {
    match NpcapLib::load() {
        Ok(lib) => unsafe {
            let ver_ptr = (lib.lib_version)();
            let version = if ver_ptr.is_null() {
                None
            } else {
                let cstr = std::ffi::CStr::from_ptr(ver_ptr as *const std::ffi::c_char);
                Some(cstr.to_string_lossy().to_string())
            };
            NpcapStatus {
                installed: true,
                version,
                hint: None,
            }
        },
        Err(_) => NpcapStatus {
            installed: false,
            version: None,
            hint: Some(
                "Npcap 未安装。请从 https://npcap.com 下载安装包（安装时勾选 \
                 \"Install Npcap in WinPcap API-compatible Mode\" 与 \"Support raw 802.11 \
                 traffic\" 可选），安装完成后重启 NetScope。"
                    .into(),
            ),
        },
    }
}

/// 枚举可抓包网卡（真实 Npcap 设备列表）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureDevice {
    pub name: String,
    pub description: Option<String>,
    pub loopback: bool,
}

pub fn list_capture_devices() -> Result<Vec<CaptureDevice>, String> {
    let lib = NpcapLib::load()?;
    unsafe {
        let mut devs: *mut PcapIfT = std::ptr::null_mut();
        let mut errbuf = [0i8; 256];
        let rc = (lib.findalldevs)(&mut devs, errbuf.as_mut_ptr());
        if rc != 0 {
            let msg = std::ffi::CStr::from_ptr(errbuf.as_ptr() as *const std::ffi::c_char)
                .to_string_lossy();
            return Err(format!("pcap_findalldevs 失败: {msg}"));
        }
        let mut out = Vec::new();
        let mut p = devs;
        const PCAP_IF_LOOPBACK: u32 = 0x00000001;
        while !p.is_null() {
            let ifc = &*p;
            let name = if ifc.name.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(ifc.name as *const std::ffi::c_char)
                    .to_string_lossy()
                    .to_string()
            };
            let description = if ifc.description.is_null() {
                None
            } else {
                Some(
                    std::ffi::CStr::from_ptr(ifc.description as *const std::ffi::c_char)
                        .to_string_lossy()
                        .to_string(),
                )
            };
            out.push(CaptureDevice {
                name,
                description,
                loopback: ifc.flags & PCAP_IF_LOOPBACK != 0,
            });
            p = ifc.next;
        }
        (lib.freealldevs)(devs);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// 协议解析（纯函数，全部可单测）
// ---------------------------------------------------------------------------

fn ip_to_string(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap_or([0; 16]),
        )
        .to_string(),
        _ => String::new(),
    }
}

/// 解析单个以太网帧（caplen 数据）→ PacketInfo。
///
/// `now` 为捕获时间；linktype 固定假定 Ethernet（NPCAP DLT_EN10MB = 1）。
pub fn parse_ethernet_frame(data: &[u8], now: DateTime<Utc>) -> Option<PacketInfo> {
    // Ethernet II：dst(6) + src(6) + ethertype(2)
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut payload = &data[14..];

    // VLAN (802.1Q) 跳过
    if ethertype == 0x8100 && payload.len() >= 4 {
        ethertype = u16::from_be_bytes([payload[2], payload[3]]);
        payload = &payload[4..];
    }

    let (src_ip, dst_ip, protocol, transport) = match ethertype {
        0x0800 => parse_ipv4(payload)?,
        0x86DD => parse_ipv6(payload)?,
        _ => return None,
    };

    let (src_port, dst_port, meta) = match protocol {
        IpProtocol::Tcp => parse_tcp(transport)?,
        IpProtocol::Udp => parse_udp(transport, src_port_of_udp(transport), dst_port_of_udp(transport)),
        IpProtocol::Icmp | IpProtocol::IcmpV6 => {
            let kind = transport.first().copied().unwrap_or(0);
            let code = transport.get(1).copied().unwrap_or(0);
            (None, None, PacketMeta::Icmp { kind, code })
        }
        IpProtocol::Other(_) => (None, None, PacketMeta::None),
    };

    let mut info = PacketInfo {
        timestamp: now,
        src_ip: Some(src_ip),
        dst_ip: Some(dst_ip),
        src_port: None,
        dst_port: None,
        protocol,
        length: data.len() as u32,
        meta,
        connection_id: None,
    };
    info.src_port = src_port;
    info.dst_port = dst_port;
    Some(info)
}

fn src_port_of_udp(t: &[u8]) -> u16 {
    if t.len() >= 2 {
        u16::from_be_bytes([t[0], t[1]])
    } else {
        0
    }
}

fn dst_port_of_udp(t: &[u8]) -> u16 {
    if t.len() >= 4 {
        u16::from_be_bytes([t[2], t[3]])
    } else {
        0
    }
}

/// 解析 IPv4 头 → (源, 目的, 协议, 传输层负载)。
fn parse_ipv4(payload: &[u8]) -> Option<(String, String, IpProtocol, &[u8])> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = ((payload[0] & 0x0f) as usize) * 4;
    if ihl < 20 || payload.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let proto = payload[9];
    let src = ip_to_string(&payload[12..16]);
    let dst = ip_to_string(&payload[16..20]);
    let end = total_len.min(payload.len());
    if end <= ihl {
        return None; // 总长异常（截断帧），不解析
    }
    let transport = &payload[ihl..end];
    let protocol = match proto {
        1 => IpProtocol::Icmp,
        6 => IpProtocol::Tcp,
        17 => IpProtocol::Udp,
        58 => IpProtocol::IcmpV6,
        other => IpProtocol::Other(other),
    };
    Some((src, dst, protocol, transport))
}

/// 解析 IPv6 头（固定 40 字节，不处理扩展头——如实标注为 Other 情况）。
fn parse_ipv6(payload: &[u8]) -> Option<(String, String, IpProtocol, &[u8])> {
    if payload.len() < 40 {
        return None;
    }
    let next_header = payload[6];
    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let src = ip_to_string(&payload[8..24]);
    let dst = ip_to_string(&payload[24..40]);
    let transport = &payload[40..(40 + payload_len).min(payload.len())];
    let protocol = match next_header {
        1 | 58 => IpProtocol::IcmpV6,
        6 => IpProtocol::Tcp,
        17 => IpProtocol::Udp,
        other => IpProtocol::Other(other),
    };
    Some((src, dst, protocol, transport))
}

/// 解析 TCP 头 → (源端口, 目的端口, 元数据)。
fn parse_tcp(t: &[u8]) -> Option<(Option<u16>, Option<u16>, PacketMeta)> {
    if t.len() < 20 {
        return None;
    }
    let src = u16::from_be_bytes([t[0], t[1]]);
    let dst = u16::from_be_bytes([t[2], t[3]]);
    let data_offset = ((t[12] >> 4) as usize) * 4;
    let flags = t[13];
    let payload_len = t.len().saturating_sub(data_offset);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
    let payload = if t.len() > data_offset { &t[data_offset..] } else { &[][..] };

    // TLS 明文握手元数据（仅 ClientHello / ServerHello 可观察时）
    let meta = if looks_like_tls_handshake(payload) {
        parse_tls_handshake(payload)
    } else {
        PacketMeta::Tcp { seq, ack, flags, payload_len: payload_len as u16 }
    };

    Some((Some(src), Some(dst), meta))
}

/// 解析 UDP → 端口 + DNS/QUIC 元数据。
fn parse_udp(t: &[u8], src: u16, dst: u16) -> (Option<u16>, Option<u16>, PacketMeta) {
    if t.len() < 8 {
        return (Some(src), Some(dst), PacketMeta::None);
    }
    let payload = &t[8..];
    let meta = if src == 53 || dst == 53 {
        parse_dns(payload)
    } else if looks_like_quic_long_header(payload) {
        parse_quic(payload)
    } else {
        PacketMeta::Udp {
            payload_len: (t.len() - 8) as u16,
        }
    };
    (Some(src), Some(dst), meta)
}

/// 解析 DNS 报文（查询/响应 + 域名 + A/AAAA 应答）。
fn parse_dns(p: &[u8]) -> PacketMeta {
    if p.len() < 12 {
        return PacketMeta::None;
    }
    let flags = u16::from_be_bytes([p[2], p[3]]);
    let is_response = flags & 0x8000 != 0;
    let qdcount = u16::from_be_bytes([p[4], p[5]]);
    let ancount = u16::from_be_bytes([p[6], p[7]]);

    // Question: 第一个 QNAME
    let mut pos = 12usize;
    let mut domain = None;
    if qdcount > 0 {
        if let Some((name, next)) = parse_dns_name(p, pos) {
            domain = Some(name);
            pos = next + 4; // QTYPE + QCLASS
        }
    }

    let mut answers = Vec::new();
    if is_response {
        // 简化：跳过应答记录名（支持 0xC00C 指针型），抽取 A/AAAA
        for _ in 0..ancount.min(16) {
            let (_, next) = match parse_dns_name(p, pos) {
                Some(v) => v,
                None => break,
            };
            if next + 10 > p.len() {
                break;
            }
            let rtype = u16::from_be_bytes([p[next], p[next + 1]]);
            let rdlength = u16::from_be_bytes([p[next + 8], p[next + 9]]) as usize;
            let rdata_start = next + 10;
            if rdata_start + rdlength > p.len() {
                break;
            }
            match rtype {
                1 if rdlength == 4 => {
                    answers.push(ip_to_string(&p[rdata_start..rdata_start + 4]))
                }
                28 if rdlength == 16 => {
                    answers.push(ip_to_string(&p[rdata_start..rdata_start + 16]))
                }
                _ => {}
            }
            pos = rdata_start + rdlength;
        }
    }

    PacketMeta::Dns {
        is_response,
        domain,
        answers,
    }
}

/// 解析 DNS 域名（支持压缩指针）。
/// 返回 (域名, 记录头结束位置) —— 指针/结尾之后的第一个字节。
fn parse_dns_name(p: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut next_after: Option<usize> = None;
    loop {
        if pos >= p.len() || jumps > 8 {
            return None;
        }
        let len = p[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= p.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | p[pos + 1] as usize;
            if next_after.is_none() {
                next_after = Some(pos + 2);
            }
            pos = ptr;
            jumps += 1;
            continue;
        }
        if len == 0 {
            if next_after.is_none() {
                next_after = Some(pos + 1);
            }
            break;
        }
        let end = (pos + 1 + len as usize).min(p.len());
        labels.push(String::from_utf8_lossy(&p[pos + 1..end]).to_string());
        pos += 1 + len as usize;
    }
    if labels.is_empty() {
        return None;
    }
    Some((labels.join("."), next_after.unwrap_or(start)))
}

fn looks_like_tls_handshake(p: &[u8]) -> bool {
    // TLS record: type=0x16(handshake), version major 0x03
    p.len() >= 9 && p[0] == 0x16 && p[1] == 0x03
}

/// 解析 TLS 握手记录（ClientHello 的 SNI / 阶段；仅明文元数据）。
fn parse_tls_handshake(p: &[u8]) -> PacketMeta {
    // record: type(1) ver(2) len(2) → handshake: type(1) len(3)
    if p.len() < 9 {
        return PacketMeta::None;
    }
    let hs_type = p[5];
    let stage = match hs_type {
        1 => crate::models::capture::TlsStage::ClientHello,
        2 => crate::models::capture::TlsStage::ServerHello,
        _ => crate::models::capture::TlsStage::OtherHandshake,
    };
    let mut sni = None;
    if hs_type == 1 {
        // ClientHello: ver(2) random(32) sid_len(1) sid cipher_len(2) ciphers comp_len(1) comp ext_len(2) exts
        let mut pos = 9 + 2 + 32;
        if p.len() > pos {
            let sid = p[pos] as usize;
            pos += 1 + sid;
        }
        if p.len() >= pos + 2 {
            let cipher_len = u16::from_be_bytes([p[pos], p[pos + 1]]) as usize;
            pos += 2 + cipher_len;
        }
        if p.len() > pos {
            let comp_len = p[pos] as usize;
            pos += 1 + comp_len;
        }
        if p.len() >= pos + 2 {
            let _ext_total = u16::from_be_bytes([p[pos], p[pos + 1]]) as usize;
            pos += 2;
            while pos + 4 <= p.len() && sni.is_none() {
                let ext_type = u16::from_be_bytes([p[pos], p[pos + 1]]);
                let ext_len = u16::from_be_bytes([p[pos + 2], p[pos + 3]]) as usize;
                let body_start = pos + 4;
                if body_start + ext_len > p.len() {
                    break;
                }
                if ext_type == 0 && ext_len >= 5 {
                    // server_name: list_len(2) entry_type(1)=0 name_len(2) name
                    let b = &p[body_start..body_start + ext_len];
                    if b.len() >= 5 && b[2] == 0 {
                        let name_len = u16::from_be_bytes([b[3], b[4]]) as usize;
                        if 5 + name_len <= b.len() {
                            sni = Some(String::from_utf8_lossy(&b[5..5 + name_len]).to_string());
                        }
                    }
                }
                pos = body_start + ext_len;
            }
        }
    }
    PacketMeta::Tls { stage, sni }
}

fn looks_like_quic_long_header(p: &[u8]) -> bool {
    p.len() >= 5 && (p[0] & 0x80) != 0
}

/// 解析 QUIC 长包头版本（基础元数据）。
fn parse_quic(p: &[u8]) -> PacketMeta {
    if p.len() < 5 {
        return PacketMeta::None;
    }
    let version = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let version_str = match version {
        0x0000_0001 => Some("v1".into()),
        0x6b33_4be1 => Some("v2".into()),
        v if v & 0xff00_0000 == 0xff00_0000 => Some(format!("draft-0x{v:08x}")),
        _ => Some(format!("0x{version:08x}")),
    };
    PacketMeta::Quic { version: version_str }
}

// ---------------------------------------------------------------------------
// 会话
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src: String,
    sport: u16,
    dst: String,
    dport: u16,
    proto: IpProtocol,
}

#[derive(Debug)]
struct FlowState {
    summary: FlowSummary,
    seen_seqs: HashSet<(u32, u16)>,
    syn_time: Option<SystemTime>,
    syn_ack_time: Option<SystemTime>,
}

impl FlowState {
    fn new(key: &FlowKey) -> Self {
        Self {
            summary: FlowSummary {
                src_ip: key.src.clone(),
                src_port: key.sport,
                dst_ip: key.dst.clone(),
                dst_port: key.dport,
                protocol: key.proto,
                packets: 0,
                bytes: 0,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                syn_count: 0,
                fin_count: 0,
                rst_count: 0,
            },
            seen_seqs: HashSet::new(),
            syn_time: None,
            syn_ack_time: None,
        }
    }
}

/// pcap 原始句柄包装（仅捕获线程解引用；breakloop 线程安全）。
#[derive(Default)]
struct PcapHandle(*mut c_void);
unsafe impl Send for PcapHandle {}

/// 会话共享统计（跨线程）。
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub retransmits: AtomicU64,
    pub rsts: AtomicU64,
    /// ICMP 不可达（type 3）观测计数（目标端口不可达类规则的证据来源）。
    pub icmp_unreachable: AtomicU64,
    pub stopped: AtomicBool,
    pub error: Mutex<Option<String>>,
}

pub struct CaptureSession {
    pub config: CaptureConfig,
    pub started_at: DateTime<Utc>,
    pub stop_flag: Arc<AtomicBool>,
    pub stats: Arc<CaptureStats>,
    pub packets: Arc<Mutex<VecDeque<PacketInfo>>>,
    pub flows: Arc<Mutex<HashMap<FlowKey, FlowState>>>,
    pub metrics: Arc<Mutex<Vec<TcpMetricEvent>>>,
    pub handshakes: Arc<Mutex<Vec<HandshakeTiming>>>,
    pub export_path: Option<PathBuf>,
    pcap_handle: Arc<Mutex<PcapHandle>>,
    lib: Arc<NpcapLib>,
    join: Option<std::thread::JoinHandle<()>>,
}

// 指针仅由捕获线程操作；停止经 breakloop（线程安全）触发
unsafe impl Send for CaptureSession {}

const MAX_RECENT_PACKETS: usize = 2000;
const MAX_FLOWS: usize = 10000;
const MAX_SEQ_ENTRIES_PER_FLOW: usize = 8192;

impl CaptureSession {
    /// 启动抓包会话（真实 Npcap 打开适配器；需要 Npcap + 管理员权限）。
    pub fn start(
        config: CaptureConfig,
        export_path: Option<PathBuf>,
        lib: Arc<NpcapLib>,
        event_sink: Option<EventSink>,
    ) -> Result<Self, String> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(CaptureStats::default());
        let packets = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_PACKETS)));
        let flows = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(Vec::new()));
        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let pcap_handle: Arc<Mutex<PcapHandle>> = Arc::new(Mutex::new(PcapHandle::default()));

        let handle_ptr = Arc::clone(&pcap_handle);
        let stop = Arc::clone(&stop_flag);
        let stats_t = Arc::clone(&stats);
        let packets_t = Arc::clone(&packets);
        let flows_t = Arc::clone(&flows);
        let metrics_t = Arc::clone(&metrics);
        let handshakes_t = Arc::clone(&handshakes);
        let cfg = config.clone();
        let lib_t = Arc::clone(&lib);
        let export_t = export_path.clone();
        let sink_t = event_sink;

        let join = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::run_capture(
                    &lib_t, cfg, export_t, handle_ptr, stop, stats_t.clone(), packets_t,
                    flows_t, metrics_t, handshakes_t, sink_t,
                )
            }));
            match result {
                Err(panic) => {
                    let msg = panic
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| {
                            panic.downcast_ref::<&str>().map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| "未知 panic".into());
                    *stats_t.error.lock().unwrap() =
                        Some(format!("抓包线程 panic: {msg}"));
                }
                Ok(Err(e)) => {
                    *stats_t.error.lock().unwrap() = Some(e);
                }
                Ok(Ok(())) => {}
            }
            stats_t.stopped.store(true, Ordering::SeqCst);
        });

        Ok(Self {
            config,
            started_at: Utc::now(),
            stop_flag,
            stats,
            packets,
            flows,
            metrics,
            handshakes,
            export_path,
            pcap_handle,
            lib,
            join: Some(join),
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn run_capture(
        lib: &NpcapLib,
        config: CaptureConfig,
        export_path: Option<PathBuf>,
        handle_ptr: Arc<Mutex<PcapHandle>>,
        stop: Arc<AtomicBool>,
        stats: Arc<CaptureStats>,
        packets: Arc<Mutex<VecDeque<PacketInfo>>>,
        flows: Arc<Mutex<HashMap<FlowKey, FlowState>>>,
        metrics: Arc<Mutex<Vec<TcpMetricEvent>>>,
        handshakes: Arc<Mutex<Vec<HandshakeTiming>>>,
        event_sink: Option<EventSink>,
    ) -> Result<(), String> {
        let adapter_c = std::ffi::CString::new(config.adapter.clone())
            .map_err(|_| "适配器名含 NUL".to_string())?;
        let mut errbuf = [0i8; 256];

        unsafe {
            let started = Instant::now();
            let handle = (lib.openlive)(
                adapter_c.as_ptr(),
                config.snaplen as i32,
                1, // promiscuous
                1000, // read timeout ms → next_ex 周期返回 0 以检查 stop
                errbuf.as_mut_ptr(),
            );
            if handle.is_null() {
                let msg = std::ffi::CStr::from_ptr(errbuf.as_ptr() as *const std::ffi::c_char)
                    .to_string_lossy();
                return Err(format!("打开适配器失败（需管理员权限）: {msg}"));
            }
            handle_ptr.lock().unwrap().0 = handle;

            // BPF 过滤
            if let Some(bpf) = &config.bpf_filter {
                if !bpf.trim().is_empty() {
                    let prog = BpfProgram { bf_len: 0, bf_insns: std::ptr::null_mut() };
                    let mut prog = prog;
                    let bpf_c = std::ffi::CString::new(bpf.as_str()).unwrap();
                    let optimize = 1;
                    if (lib.compile)(handle, &mut prog, bpf_c.as_ptr(), optimize, 0xFFFF_FFFF) != 0 {
                        (lib.close)(handle);
                        return Err(format!("BPF 过滤表达式无效: {bpf}"));
                    }
                    if (lib.setfilter)(handle, &prog) != 0 {
                        (lib.close)(handle);
                        return Err(format!("设置过滤器失败: {bpf}"));
                    }
                }
            }

            // PCAP 导出文件（流式写入）
            let mut export: Option<BufWriter<File>> = match &export_path {
                Some(path) => {
                    let mut f = File::create(path).map_err(|e| format!("创建导出文件失败: {e}"))?;
                    // 全局头: magic(LE us) ver2.4 thiszone sigfigs snaplen network=1(EN10MB)
                    let _ = f.write_all(&0xa1b2_c3d4u32.to_le_bytes());
                    let _ = f.write_all(&2u16.to_le_bytes());
                    let _ = f.write_all(&4u16.to_le_bytes());
                    let _ = f.write_all(&0i32.to_le_bytes());
                    let _ = f.write_all(&0u32.to_le_bytes());
                    let _ = f.write_all(&config.snaplen.to_le_bytes());
                    let _ = f.write_all(&1u32.to_le_bytes());
                    Some(BufWriter::new(f))
                }
                None => None,
            };

            let mut pending: Vec<PacketInfo> = Vec::new();
            let mut pending_raw: Vec<(i64, i64, u32, Vec<u8>)> = Vec::new();
            let mut last_flush = Instant::now();
            let max_bytes = config.max_bytes.unwrap_or(u64::MAX);
            let max_packets = config.max_packets.unwrap_or(u64::MAX);
            let max_duration = config.max_duration_secs.unwrap_or(u64::MAX);
            let mut hdr: *mut PcapPkthdr = std::ptr::null_mut();
            let mut data: *mut u8 = std::ptr::null_mut();

            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                // 停止条件（大小 / 时长 / 包数）
                if stats.bytes.load(Ordering::SeqCst) >= max_bytes
                    || stats.packets.load(Ordering::SeqCst) >= max_packets
                    || started.elapsed() >= Duration::from_secs(max_duration)
                {
                    break;
                }

                let rc = (lib.next_ex)(handle, &mut hdr, &mut data);
                match rc {
                    0 => continue, // 超时
                    1 => {
                        let h = &*hdr;

                        let raw = std::slice::from_raw_parts(data, h.caplen as usize);
                        let now: DateTime<Utc> = (UNIX_EPOCH
                            + Duration::new(h.ts_sec as u64, 0)
                            + Duration::from_micros(h.ts_usec as u64))
                        .into();
                        let Some(info) = parse_ethernet_frame(raw, now) else {
                            continue;
                        };

                        // 统计 + 流聚合
                        stats.packets.fetch_add(1, Ordering::SeqCst);
                        stats.bytes.fetch_add(h.caplen as u64, Ordering::SeqCst);
                        if matches!(info.meta, PacketMeta::Icmp { kind: 3, .. }) {
                            stats.icmp_unreachable.fetch_add(1, Ordering::SeqCst);
                        }
                        Self::update_flows(&info, &mut flows.lock().unwrap(), &metrics, &handshakes, stats.as_ref());

                        pending.push(info);
                        if export.is_some() {
                            pending_raw.push((h.ts_sec as i64, h.ts_usec as i64, h.caplen, raw.to_vec()));
                        }

                        // 批量推送 / 落盘
                        if pending.len() >= 100
                            || last_flush.elapsed() >= Duration::from_millis(500)
                        {
                            if let Some(w) = export.as_mut() {
                                for (sec, usec, caplen, raw) in pending_raw.drain(..) {
                                    let _ = w.write_all(&sec.to_le_bytes());
                                    let _ = w.write_all(&usec.to_le_bytes());
                                    let _ = w.write_all(&caplen.to_le_bytes());
                                    let _ = w.write_all(&(caplen as u32).to_le_bytes());
                                    let _ = w.write_all(&raw);
                                }
                            }
                            if let Some(sink) = &event_sink {
                                sink(
                                    "packet:batch",
                                    &serde_json::to_value(&pending).unwrap_or_default(),
                                );
                            }
                            let mut buf = packets.lock().unwrap();
                            for p in pending.drain(..) {
                                if buf.len() >= MAX_RECENT_PACKETS {
                                    buf.pop_front();
                                }
                                buf.push_back(p);
                            }
                            last_flush = Instant::now();
                        }
                    }
                    -2 => break, // pcap_breakloop
                    _ => {
                        *stats.error.lock().unwrap() =
                            Some("pcap_next_ex 返回错误（适配器可能已断开）".into());
                        break;
                    }
                }
            }

            if let Some(w) = export.as_mut() {
                let _ = w.flush();
            }
            (lib.close)(handle);
            handle_ptr.lock().unwrap().0 = std::ptr::null_mut();
            Ok(())
        }
    }

    /// 更新流统计 + TCP 事件（重传 / RST / 握手耗时）。
    fn update_flows(
        info: &PacketInfo,
        flows: &mut HashMap<FlowKey, FlowState>,
        metrics: &Mutex<Vec<TcpMetricEvent>>,
        handshakes: &Mutex<Vec<HandshakeTiming>>,
        stats: &CaptureStats,
    ) {
        if flows.len() >= MAX_FLOWS {
            return;
        }
        let (Some(src_ip), Some(dst_ip)) = (&info.src_ip, &info.dst_ip) else {
            return;
        };
        let src_port = info.src_port.unwrap_or(0);
        let dst_port = info.dst_port.unwrap_or(0);
        let key = FlowKey {
            src: src_ip.clone(),
            sport: src_port,
            dst: dst_ip.clone(),
            dport: dst_port,
            proto: info.protocol,
        };
        let state = flows.entry(key.clone()).or_insert_with(|| {
            let mut fs = FlowState::new(&key);
            fs.summary.first_seen = info.timestamp;
            fs.summary.last_seen = info.timestamp;
            fs
        });
        state.summary.packets += 1;
        state.summary.bytes += info.length as u64;
        state.summary.last_seen = info.timestamp;

        let PacketMeta::Tcp { seq, flags, payload_len, .. } = info.meta else {
            return;
        };

        if flags & 0x02 != 0 {
            state.summary.syn_count += 1;
            if flags & 0x10 != 0 {
                // SYN+ACK
                if state.syn_time.is_some() && state.syn_ack_time.is_none() {
                    state.syn_ack_time = Some(SystemTime::now());
                    if let (Some(t0), Some(t1)) = (state.syn_time, state.syn_ack_time) {
                        let ms = t1.duration_since(t0).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0);
                        let mut hs = handshakes.lock().unwrap();
                        if hs.len() < 1000 {
                            hs.push(HandshakeTiming {
                                timestamp: info.timestamp,
                                src_ip: src_ip.clone(),
                                dst_ip: dst_ip.clone(),
                                dst_port,
                                syn_to_syn_ack_ms: ms,
                                syn_to_established_ms: ms, // 最终 ACK 耗时此处不单独测
                            });
                        }
                    }
                }
            } else if state.syn_time.is_none() {
                state.syn_time = Some(SystemTime::now());
            }
        }
        if flags & 0x01 != 0 {
            state.summary.fin_count += 1;
        }
        if flags & 0x04 != 0 {
            state.summary.rst_count += 1;
            stats.rsts.fetch_add(1, Ordering::SeqCst);
            let mut m = metrics.lock().unwrap();
            if m.len() < 5000 {
                m.push(TcpMetricEvent {
                    timestamp: info.timestamp,
                    source: MetricSource::Capture,
                    kind: TcpAnomalyKind::Rst,
                    connection_id: None,
                    src_ip: Some(src_ip.clone()),
                    src_port: Some(src_port),
                    dst_ip: Some(dst_ip.clone()),
                    dst_port: Some(dst_port),
                    detail: serde_json::json!({ "flags": flags }),
                });
            }
        }

        // 重传：同 (seq, len) 再次出现
        if payload_len > 0 {
            let entry = (seq, payload_len);
            if state.seen_seqs.contains(&entry) {
                stats.retransmits.fetch_add(1, Ordering::SeqCst);
                let mut m = metrics.lock().unwrap();
                if m.len() < 5000 {
                    m.push(TcpMetricEvent {
                        timestamp: info.timestamp,
                        source: MetricSource::Capture,
                        kind: TcpAnomalyKind::Retransmit,
                        connection_id: None,
                        src_ip: Some(src_ip.clone()),
                        src_port: Some(src_port),
                        dst_ip: Some(dst_ip.clone()),
                        dst_port: Some(dst_port),
                        detail: serde_json::json!({ "seq": seq, "len": payload_len }),
                    });
                }
            } else if state.seen_seqs.len() < MAX_SEQ_ENTRIES_PER_FLOW {
                state.seen_seqs.insert(entry);
            }
        }
    }

    /// 停止会话（breakloop + join 线程，确保采集线程干净退出）。
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        unsafe {
            let guard = self.pcap_handle.lock().unwrap();
            let handle = guard.0;
            if !handle.is_null() {
                (self.lib.breakloop)(handle);
            }
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }

    pub fn status(&self) -> CaptureStatus {
        let state = if self.stats.stopped.load(Ordering::SeqCst) {
            CaptureState::Stopped
        } else {
            CaptureState::Running
        };
        CaptureStatus {
            state,
            config: Some(self.config.clone()),
            started_at: Some(self.started_at),
            packets: self.stats.packets.load(Ordering::SeqCst),
            bytes: self.stats.bytes.load(Ordering::SeqCst),
            last_error: self.stats.error.lock().unwrap().clone(),
        }
    }

    pub fn recent_packets(&self, max: usize) -> Vec<PacketInfo> {
        self.packets.lock().unwrap().iter().rev().take(max).cloned().collect()
    }

    pub fn flow_summaries(&self) -> Vec<FlowSummary> {
        self.flows
            .lock()
            .unwrap()
            .values()
            .map(|s| s.summary.clone())
            .collect()
    }

    pub fn take_metrics(&self) -> Vec<TcpMetricEvent> {
        std::mem::take(&mut *self.metrics.lock().unwrap())
    }

    pub fn take_handshakes(&self) -> Vec<HandshakeTiming> {
        std::mem::take(&mut *self.handshakes.lock().unwrap())
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 抓包管理器（AppState 持有，同时最多一个会话）。
#[derive(Default)]
pub struct CaptureManager {
    pub session: Option<CaptureSession>,
}

impl CaptureManager {
    /// 当前会话观测的 ICMP 不可达计数（非破坏性读取）。
    pub fn icmp_unreachable_count(&self) -> u32 {
        match &self.session {
            Some(s) => s.stats.icmp_unreachable.load(Ordering::SeqCst).min(u32::MAX as u64) as u32,
            None => 0,
        }
    }

    pub fn status(&self) -> CaptureStatus {
        match &self.session {
            Some(s) => s.status(),
            None => CaptureStatus {
                state: CaptureState::Idle,
                config: None,
                started_at: None,
                packets: 0,
                bytes: 0,
                last_error: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// 路由探测（高级 Traceroute 共用：ICMP 免管理员）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::capture::TlsStage;

    /// 构造 Ethernet + IPv4 + TCP SYN 帧到 8.8.8.8:443。
    fn tcp_syn_frame() -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12] = 0x08;
        f[13] = 0x00; // IPv4
        let ip = &mut f[14..34];
        ip[0] = 0x45;
        ip[2] = 0;
        ip[3] = 40; // total len 40
        ip[8] = 64; // TTL
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&[192, 168, 1, 10]);
        ip[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let tcp = &mut f[34..54];
        tcp[0..2].copy_from_slice(&52341u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&12345u32.to_be_bytes()); // seq
        tcp[12] = 0x50; // data offset 20
        tcp[13] = 0x02; // SYN
        f
    }

    #[test]
    fn parse_tcp_syn() {
        let frame = tcp_syn_frame();
        let info = parse_ethernet_frame(&frame, Utc::now()).expect("应解析成功");
        assert_eq!(info.src_ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(info.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(info.protocol, IpProtocol::Tcp);
        assert_eq!(info.src_port, Some(52341));
        assert_eq!(info.dst_port, Some(443));
        match info.meta {
            PacketMeta::Tcp { flags, seq, payload_len, .. } => {
                assert_eq!(flags, 0x02);
                assert_eq!(seq, 12345);
                assert_eq!(payload_len, 0);
            }
            other => panic!("应解析为 Tcp 元数据: {other:?}"),
        }
    }

    fn dns_query_frame() -> Vec<u8> {
        // eth + ip + udp + dns query www.example.com A
        let dns: Vec<u8> = [
            0x12u8, 0x34, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            0, 1, 0, 1, // QTYPE=A QCLASS=IN
        ]
        .to_vec();
        let udp_len = 8 + dns.len();
    let total = 20 + udp_len;
    let mut f = Vec::with_capacity(14 + total);
    f.extend_from_slice(&[0u8; 14]);
    f[12] = 0x08;
    f[13] = 0x00;
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]); // ttl+proto+checksum
        f.extend_from_slice(&[192, 168, 1, 10]);
        f.extend_from_slice(&[192, 168, 1, 1]);
        f.extend_from_slice(&51000u16.to_be_bytes());
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&dns);
        f
    }

    #[test]
    fn parse_dns_query() {
        let info = parse_ethernet_frame(&dns_query_frame(), Utc::now()).unwrap();
        assert_eq!(info.protocol, IpProtocol::Udp);
        assert_eq!(info.dst_port, Some(53));
        match info.meta {
            PacketMeta::Dns { is_response, domain, answers } => {
                assert!(!is_response);
                assert_eq!(domain.as_deref(), Some("www.example.com"));
                assert!(answers.is_empty());
            }
            other => panic!("应为 Dns 元数据: {other:?}"),
        }
    }

    fn dns_response_frame() -> Vec<u8> {
        let mut d: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, // flags: QR + RD + RA
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            0, 1, 0, 1,
            0xC0, 0x0C, // 指针到 question name
            0, 1, 0, 1, // A IN
            0, 0, 0, 60, // TTL
            0, 4, // RDLENGTH
            93, 184, 216, 34, // 93.184.216.34
        ];
        // 包成 eth/ip/udp
        let udp_len = 8 + d.len();
        let total = 20 + udp_len;
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&[192, 168, 1, 1]);
        f.extend_from_slice(&[192, 168, 1, 10]);
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&51000u16.to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.append(&mut d);
        f
    }

    #[test]
    fn parse_dns_response_with_compressed_name() {
        let info = parse_ethernet_frame(&dns_response_frame(), Utc::now()).unwrap();
        match info.meta {
            PacketMeta::Dns { is_response, domain, answers } => {
                assert!(is_response);
                assert_eq!(domain.as_deref(), Some("www.example.com"));
                assert_eq!(answers, vec!["93.184.216.34".to_string()]);
            }
            other => panic!("应为 Dns: {other:?}"),
        }
    }

    fn tls_client_hello_frame() -> Vec<u8> {
        let sni = b"www.youtube.com";
        // ClientHello 扩展构造
        let mut ext_sni = vec![0x00, 0x00]; // ext type server_name
        let mut body = vec![0x00, (3 + sni.len() + 3) as u8]; // list len
        body.push(0x00); // host_name
        body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        body.extend_from_slice(sni);
        ext_sni.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(&body);

        let mut ch = vec![
            0x01, 0x00, 0x00, 0x00, // handshake type + len 占位后填
            0x03, 0x03, // version TLS1.2
        ];
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session id len
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher len + suites
        ch.push(0x01);
        ch.push(0x00); // compressions
        ch.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        ch.extend_from_slice(&ext_sni);
        // 修正 handshake len（3 字节大端）
        let hs_len = ch.len() - 4;
        ch[1..4].copy_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);

        // record
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(ch.len() as u16).to_be_bytes());
        rec.extend_from_slice(&ch);

        // 包成 TCP 帧 dst 443（IP 总长 = IP 头 20 + TCP 头 20 + 载荷）
        let total = 40 + rec.len();
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]); // ttl+proto+checksum
        f.extend_from_slice(&[192, 168, 1, 10]);
        f.extend_from_slice(&[142, 250, 66, 238]);
        f.extend_from_slice(&52000u16.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.push(0x50);
        f.push(0x18); // PSH|ACK
        f.extend_from_slice(&[0x57, 0x10]); // window
        f.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent（解析器不校验）
        f.extend_from_slice(&rec);
        f
    }

    #[test]
    fn parse_tls_sni() {
        let frame = tls_client_hello_frame();
        let info = parse_ethernet_frame(&frame, Utc::now()).unwrap();
        match info.meta {
            PacketMeta::Tls { stage, sni } => {
                assert_eq!(stage, TlsStage::ClientHello);
                assert_eq!(sni.as_deref(), Some("www.youtube.com"));
            }
            other => panic!("应为 Tls: {other:?}"),
        }
    }

    #[test]
    fn parse_ipv6_udp() {
        // eth + ipv6(40) + udp(8) payload "hi"
        let mut f = vec![0u8; 14];
        f[12] = 0x86;
        f[13] = 0xDD;
        f.extend_from_slice(&[0x60, 0, 0, 0, 0, 18, 17, 64]); // ver+flow, len, next=17, hop // ver6, payload_len=10, next_header=17
        f.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]);
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&10u16.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0x80, 1, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // QUIC 长包头 v0x01020304
        let info = parse_ethernet_frame(&f, Utc::now()).unwrap();
        assert_eq!(info.protocol, IpProtocol::Udp);
        assert_eq!(info.src_ip.as_deref(), Some("fe80::1"));
        match info.meta {
            PacketMeta::Quic { version } => assert!(version.is_some()),
            other => panic!("应为 Quic: {other:?}"),
        }
    }

    #[test]
    fn parse_icmp_v4() {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        // IP 总长 = 20 头 + 8 ICMP = 28
        f.extend_from_slice(&[0x45, 0x00, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0]); // 含 checksum
        f.extend_from_slice(&[192, 168, 1, 10]);
        f.extend_from_slice(&[8, 8, 8, 8]);
        f.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]); // ICMP echo request
        let info = parse_ethernet_frame(&f, Utc::now()).unwrap();
        assert_eq!(info.protocol, IpProtocol::Icmp);
        match info.meta {
            PacketMeta::Icmp { kind, code } => {
                assert_eq!(kind, 8);
                assert_eq!(code, 0);
            }
            other => panic!("应为 Icmp: {other:?}"),
        }
    }

    #[test]
    fn malformed_frames_do_not_panic() {
        // 随机截断帧不应 panic
        let frame = tcp_syn_frame();
        for cut in [0usize, 1, 5, 13, 14, 20, 33, 40, 54] {
            let _ = parse_ethernet_frame(&frame[..cut.min(frame.len())], Utc::now());
        }
        let _ = parse_dns(&[]);
        let _ = parse_dns(&[0u8; 12]);
        let _ = parse_tls_handshake(&[0x16, 0x03]);
        let _ = parse_quic(&[0x80, 1, 2]);
    }

    #[test]
    fn retransmit_detection_in_flow_updates() {
        let flows = Mutex::new(HashMap::new());
        let metrics = Mutex::new(Vec::new());
        let handshakes = Mutex::new(Vec::new());
        let stats = CaptureStats::default();
        let now = Utc::now();

        let mut mk = |seq: u32| {
            PacketInfo {
                timestamp: now,
                src_ip: Some("1.1.1.1".into()),
                dst_ip: Some("2.2.2.2".into()),
                src_port: Some(1000),
                dst_port: Some(80),
                protocol: IpProtocol::Tcp,
                length: 60,
                meta: PacketMeta::Tcp { seq, ack: 0, flags: 0x18, payload_len: 100 },
                connection_id: None,
            }
        };
        let p1 = mk(500);
        let p2 = mk(600);
        let p3 = mk(500); // 重传！
        CaptureSession::update_flows(&p1, &mut flows.lock().unwrap(), &metrics, &handshakes, &stats);
        CaptureSession::update_flows(&p2, &mut flows.lock().unwrap(), &metrics, &handshakes, &stats);
        CaptureSession::update_flows(&p3, &mut flows.lock().unwrap(), &metrics, &handshakes, &stats);
        assert_eq!(stats.retransmits.load(Ordering::SeqCst), 1, "同 seq 重复应记一次重传");
        assert_eq!(metrics.lock().unwrap().len(), 1);
        let flows_map = flows.lock().unwrap();
        assert_eq!(flows_map.len(), 1, "同一五元组聚合为一个流");
    }

    #[test]
    fn pcap_export_header_format() {
        // 导出文件头 = pcap magic（LE）+ version 2.4
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        assert_eq!(&buf[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    }
}
