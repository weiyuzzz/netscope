//! 主动网络探测层（Phase 4 实现）。
//!
//! - `ping`       ICMP Ping（IP/域名，延迟与丢包统计）
//! - `traceroute` TTL 递增路由探测（每跳 IP 与响应时间）
//! - `dns_probe`  DNS 查询测试（指定服务器解析指定域名）
//!
//! 约束：对不响应 ICMP 的节点输出"超时/无响应"，不得判定为故障。

pub mod dns_probe;
pub mod ping;
pub mod traceroute;
