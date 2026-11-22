//! 拓扑节点 ID 规则。
//!
//! 统一的节点 ID 构造函数，保证前后端 ID 语义一致：
//! - host            `host:local`
//! - adapter/vpn     `adapter:{if_index}`
//! - gateway         `gw:{ip}`
//! - dns             `dns:{ip}`
//! - process         `process:{pid}:{name}`
//! - remote ip       `ip:{ip}`
//! - domain          `domain:{domain}`
//! - proxy           `proxy:{mechanism}:{host}:{port}`（ProxyServer.id）
//! - route hop       `hop:{target}:{ttl}:{ip}`

/// 节点 ID 构造工具。
pub mod id {
    pub fn host() -> String {
        "host:local".into()
    }

    pub fn adapter(if_index: u32) -> String {
        format!("adapter:{if_index}")
    }

    pub fn gateway(ip: &str) -> String {
        format!("gw:{ip}")
    }

    pub fn dns(ip: &str) -> String {
        format!("dns:{ip}")
    }

    pub fn process(pid: u32, name: Option<&str>) -> String {
        format!("process:{pid}:{}", name.unwrap_or_default())
    }

    pub fn remote_ip(ip: &str) -> String {
        format!("ip:{ip}")
    }

    pub fn domain(domain: &str) -> String {
        format!("domain:{domain}")
    }

    pub fn proxy(proxy_id: &str) -> String {
        format!("proxy:{proxy_id}")
    }

    pub fn route_hop(target: &str, ttl: u8, ip: &str) -> String {
        format!("hop:{target}:{ttl}:{ip}")
    }
}
