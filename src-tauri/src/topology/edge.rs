//! 拓扑边生成规则与生命周期约定。
//!
//! - `proc-ip` 边按 (pid, remote_ip) 聚合显示活跃连接，连接明细保留在
//!   Connections 页 —— 图上不合并时间维度，仅聚合当前活跃集合；
//! - `domain-ip` 边必须携带 evidence 与 correlated_at（DNS 解析 ≠ 连接）；
//! - `proc-proxy` 边必须携带 confidence（inferred 不得呈现为确认）；
//! - `route-probe` 边携带 evidence=probe_observation（主动探测事实）。
