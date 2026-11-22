//! Traceroute 协议模式说明。
//!
//! - **ICMP 模式**（默认，免管理员）：见 [`crate::probe::ping::icmp_traceroute`]，
//!   通过 IcmpSendEcho2 的 TTL 选项实现，普通权限可用；
//! - **UDP / TCP 模式**：需要向网络发送伪造 TTL 的原始报文并观察 ICMP
//!   Time Exceeded —— 依赖 Npcap 发包能力 + 管理员权限。安装 Npcap 后在
//!   Route Explorer 中启用（能力检测见 [`crate::collector::capture::npcap_status`]）。
//!   未满足条件时如实提示"需要 Npcap + 管理员权限"，不降级为伪造数据。
//!
//! 路由探测结果统一输出 `models::metrics::RouteProbe`，由拓扑层映射为
//! RouteHop 节点（边携带 evidence = probe_observation）。
