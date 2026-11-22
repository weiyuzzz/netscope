//! DNS ↔ 连接/IP 关联。
//!
//! Phase 1 采集层只能提供"近期解析过的域名集合"（缓存域名，无时间线）。
//! 本模块按以下规则建立关联，全部携带证据与置信度：
//!
//! - 域名出现在缓存 + 存在进程对该域名解析结果 IP 的活跃连接
//!   → domain-ip 边（evidence = time_window，低置信度，Phase 1 基线）；
//! - 仅域名在缓存、无对应连接 → 仅创建 domain 节点（dns_only 展示）；
//! - ETW DNS 事件（管理员可选）上线后升级为 dns_then_connect（高置信度）。
//!
//! 无法确认来源进程的 DNS 关联不分配给任何进程 —— 不猜测归属。


use chrono::{DateTime, Utc};

/// 域名 → IP 的一条关联结论。
#[derive(Debug, Clone, PartialEq)]
pub struct DomainIpLink {
    pub domain: String,
    pub ip: String,
    pub evidence: crate::models::topology::CorrelationEvidence,
    pub correlated_at: DateTime<Utc>,
}

/// 按当前活跃连接的远端 IP，为缓存域名建立（或更新）关联。
///
/// `domain` 列表来自 DNS 缓存；`ip_domains` 为 ip → 域名倒排（由缓存域名
/// 与历史解析记录构建）。此函数只做"有连接证据才建边"的守门。
pub fn correlate(
    domains: &[String],
    active_remote_ips: &std::collections::HashSet<String>,
    now: DateTime<Utc>,
) -> Vec<DomainIpLink> {
    let _ = domains;
    let _ = active_remote_ips;
    let _ = now;
    // Phase 1：缓存无法提供域名→IP 映射（见 docs/COLLECTION.md §3.1），
    // 因此这里返回空 —— 不伪造关联。映射由 probe/dns_probe 主动解析补全（Phase 2/4）。
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_evidence_no_link() {
        let now = Utc::now();
        let links = correlate(
            &["example.com".to_string()],
            &std::collections::HashSet::new(),
            now,
        );
        assert!(links.is_empty(), "无映射证据时不得产生关联");
    }
}
