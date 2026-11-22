//! 数据包捕获模型（Npcap 可选模块，二轮新增）。
//!
//! 隐私与边界：只解析协议元数据，不解密 TLS 内容，不保存完整载荷。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// IP 传输协议（IANA 分配号，未识别的保留原始编号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    Icmp,
    IcmpV6,
    Tcp,
    Udp,
    Other(u8),
}

/// 应用层可观察元数据（只取可可靠解析的部分）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PacketMeta {
    /// 无应用层元数据。
    None,
    /// TCP 头部字段。
    Tcp {
        seq: u32,
        ack: u32,
        flags: u8,
        payload_len: u16,
    },
    /// UDP（长度）。
    Udp { payload_len: u16 },
    /// ICMP 类型/代码。
    Icmp { kind: u8, code: u8 },
    /// DNS：查询或响应 + 域名 + 应答 IP（可解析时）。
    Dns {
        is_response: bool,
        domain: Option<String>,
        answers: Vec<String>,
    },
    /// TLS 握手元数据（明文可观察时）：SNI / 握手阶段。不含内容。
    Tls {
        stage: TlsStage,
        sni: Option<String>,
    },
    /// QUIC 基础元数据（长包头可观察时）：版本。
    Quic { version: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsStage {
    ClientHello,
    ServerHello,
    OtherHandshake,
}

/// 单包解析结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketInfo {
    /// 捕获时间（UTC 微秒精度）。
    pub timestamp: DateTime<Utc>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: IpProtocol,
    /// 原始报文长度（字节）。
    pub length: u32,
    pub meta: PacketMeta,
    /// 所属连接 ID（能可靠关联到连接表时）。
    pub connection_id: Option<String>,
}

/// 抓包会话配置（用户主动启用时提供）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureConfig {
    /// Npcap 适配器设备名（pcap 设备路径）。
    pub adapter: String,
    /// 展示名称。
    pub adapter_friendly: String,
    /// BPF 过滤表达式（可空）。
    pub bpf_filter: Option<String>,
    /// 快照长度（字节，默认 65535）。
    pub snaplen: u32,
    /// 大小上限（字节），达到后自动停止。
    pub max_bytes: Option<u64>,
    /// 持续时间上限（秒），达到后自动停止。
    pub max_duration_secs: Option<u64>,
    /// 包数上限。
    pub max_packets: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Idle,
    Running,
    Stopped,
    Error,
}

/// 抓包会话状态（前端轮询/事件展示）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    pub state: CaptureState,
    pub config: Option<CaptureConfig>,
    pub started_at: Option<DateTime<Utc>>,
    pub packets: u64,
    pub bytes: u64,
    /// 最近错误（如实展示）。
    pub last_error: Option<String>,
}

/// 一个 TCP/UDP 会话的基础统计（5 元组聚合）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: IpProtocol,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// TCP flags 计数（SYN/FIN/RST 观测次数）。
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_meta_tagged_serialization() {
        let meta = PacketMeta::Dns {
            is_response: true,
            domain: Some("example.com".into()),
            answers: vec!["93.184.216.34".into()],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"type\":\"dns\""));
        let back: PacketMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);
    }

    #[test]
    fn other_protocol_keeps_number() {
        let p = IpProtocol::Other(47);
        let json = serde_json::to_string(&p).unwrap();
        let back: IpProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(back, IpProtocol::Other(47));
    }

    #[test]
    fn tcp_flags_not_lost() {
        let meta = PacketMeta::Tcp { seq: 100, ack: 200, flags: 0x12, payload_len: 0 };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"flags\":18"));
    }
}
