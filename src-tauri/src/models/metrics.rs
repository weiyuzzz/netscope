//! 网络质量与指标模型（二轮新增）。
//!
//! 数据来源标注原则：
//! - `source = System`：来自连接表轮询差分 / 接口计数器（系统级事实）；
//! - `source = Capture`：来自 Npcap 抓包推导（观测值）；
//! 两类指标在 UI 分开呈现，不伪装成精确测量。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 单网卡实时速率采样。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceRate {
    pub if_index: u32,
    pub friendly_name: String,
    /// 接收速率 bytes/s（计数器差分）。
    pub rx_bps: f64,
    /// 发送速率 bytes/s。
    pub tx_bps: f64,
    /// 累计计数（GetIfTable2 原始值）。
    pub rx_total: u64,
    pub tx_total: u64,
    pub operational_status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricSource {
    /// 连接表轮询 / 接口计数器差分（系统级事实）。
    System,
    /// Npcap 抓包推导（观测值）。
    Capture,
}

/// TCP 异常/事件类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpAnomalyKind {
    /// 重传（抓包：同方向同 seq 再次出现）。
    Retransmit,
    /// 重复 ACK（抓包可观察时）。
    DupAck,
    /// RST。
    Rst,
    /// 建连失败（轮询观察：SYN_SENT 长时间未转 ESTABLISHED / 直接消失）。
    SynFailure,
    /// 连接超时判定（系统级：状态迁移超窗）。
    Timeout,
}

/// 单条 TCP 事件/异常记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpMetricEvent {
    pub timestamp: DateTime<Utc>,
    pub source: MetricSource,
    pub kind: TcpAnomalyKind,
    pub connection_id: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    /// 详情（如重传的 seq、连续次数）。
    pub detail: serde_json::Value,
}

/// TCP 建连耗时（可靠测量：抓包 SYN→SYN/ACK→ACK 时间差；否则不提供）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeTiming {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    /// SYN → SYN/ACK（毫秒）。
    pub syn_to_syn_ack_ms: f64,
    /// SYN → ACK 完成三步握手（毫秒）。
    pub syn_to_established_ms: f64,
}

/// 网络质量时间序列点（写入 network_quality 表并推送前端曲线）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkQualityPoint {
    pub timestamp: DateTime<Utc>,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub tcp_total: u32,
    pub tcp_established: u32,
    pub udp_endpoints: u32,
    /// 近期 TCP 异常计数（窗口内）。
    pub retransmits_recent: u32,
    pub rst_recent: u32,
    pub syn_failures_recent: u32,
}

/// 路由探测协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceProtocol {
    Icmp,
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHopState {
    /// 有应答。
    Replied,
    /// 无应答（*，不判定故障）。
    NoReply,
    /// 目标到达（TTL 到达目标端口）。
    Reached,
}

/// 单跳探测结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteHop {
    pub ttl: u8,
    pub state: RouteHopState,
    /// 响应者 IP（无应答为 None）。
    pub ip: Option<String>,
    /// 每次探测的 RTT（毫秒），无应答缺失。
    pub rtt_ms: Vec<f64>,
    /// 丢包率 = 缺失/总探测。
    pub probes_sent: u32,
    pub hostname: Option<String>,
    /// ASN（如 "AS4134 CHINANET"），可获取时。
    pub asn: Option<String>,
}

/// 一次路由探测记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteProbe {
    pub id: String,
    pub target: String,
    pub resolved_ip: Option<String>,
    pub protocol: TraceProtocol,
    pub port: Option<u16>,
    pub max_hops: u8,
    pub probes_per_hop: u8,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub hops: Vec<RouteHop>,
    /// 与上一次同目标探测的路径是否发生变化（可对比时）。
    pub path_changed: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_sources_distinct() {
        assert_eq!(
            serde_json::to_string(&MetricSource::System).unwrap(),
            "\"system\""
        );
        assert_eq!(
            serde_json::to_string(&MetricSource::Capture).unwrap(),
            "\"capture\""
        );
    }

    #[test]
    fn route_hop_noreply_semantics() {
        let hop = RouteHop {
            ttl: 3,
            state: RouteHopState::NoReply,
            ip: None,
            rtt_ms: vec![],
            probes_sent: 3,
            hostname: None,
            asn: None,
        };
        let json = serde_json::to_string(&hop).unwrap();
        // 无应答跳必须显示为 no_reply 状态，ip 为 null —— 不判定为故障
        assert!(json.contains("\"state\":\"no_reply\""));
        assert!(json.contains("\"ip\":null"));
    }
}
