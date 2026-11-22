//! DNS 采集：读取系统 DNS 缓存条目（dnsapi.dll `DnsGetCacheDataTable`）。
//!
//! ## 方案评估与能力边界（基于本机 Win10 19045 实测，如实记录）
//!
//! | 方案 | 能提供 | 权限 | 结论 |
//! |---|---|---|---|
//! | ETW DNS-Client 提供程序 | 查询事件全量（域名、结果、服务器、进程） | 需管理员启动实时会话 | Phase 2+ 可选增强 |
//! | `DnsGetCacheDataTable` | 缓存中的**域名 + 记录类型** | 普通权限 | **Phase 1 采用（基线）** |
//!
//! ## 已验证的限制
//!
//! 1. **记录数据（IP）不内联**：实测（原始内存转储）`DNS_CACHE_ENTRY.wDataLength = 0`，
//!    结构体后紧跟堆分配元数据。旧版 Windows 内联存放 A/AAAA 数据的布局在
//!    Win10 19045 上不成立。因此本模块**不输出 IP**——猜测 IP 字节布局违反数据准确性原则。
//!    域名→IP 映射由 Phase 2 关联层通过连接观察与主动 DNS 探测（probe/dns_probe）建立。
//! 2. **无查询时间戳 / DNS 服务器 / 来源进程**：同样需 ETW 才能获得。
//! 3. 经由此路径得到的"近期解析域名"集合仅作为关联线索，拓扑中标注低置信度。

use std::collections::BTreeSet;

use serde::Serialize;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::NetworkManagement::Dns::{DnsFree, DnsFreeRecordList, DNS_RECORDW};

use super::CollectorError;

/// DNS 记录类型常量（Windows DNS_RECORD wType）。
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_AAAA: u16 = 28;

/// 系统 DNS 缓存中的一个域名条目（近期真实解析过）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsCacheEntry {
    pub domain: String,
    /// Windows 记录类型（1=A，5=CNAME，12=PTR，28=AAAA 等）。
    pub record_type: u16,
}

// windows-rs 0.62 未封装此 API，手动声明（dnsapi.dll 标准导出，普通权限可调用）。
#[link(name = "dnsapi")]
extern "system" {
    fn DnsGetCacheDataTable(ppentryheads: *mut *mut DNS_RECORDW) -> i32;
}

/// 读取当前系统 DNS 缓存的域名条目（仅可靠字段：域名 + 记录类型）。
pub fn read_dns_cache() -> Result<Vec<DnsCacheEntry>, CollectorError> {
    let mut head: *mut DNS_RECORDW = std::ptr::null_mut();
    let ok = unsafe { DnsGetCacheDataTable(&mut head) };
    if ok == 0 {
        let code = unsafe { GetLastError() }.0;
        return Err(CollectorError::Api(format!(
            "DnsGetCacheDataTable 失败: {code}"
        )));
    }

    // BTreeSet 保证输出顺序稳定、天然去重（同一域名可能同时存在多条类型记录）。
    let mut out: BTreeSet<DnsCacheEntry> = BTreeSet::new();

    unsafe {
        let mut p = head;
        while !p.is_null() {
            let rec = &*p;
            let domain = rec.pName.to_string().unwrap_or_default();
            if !domain.is_empty() {
                out.insert(DnsCacheEntry {
                    domain,
                    record_type: rec.wType,
                });
            }
            p = rec.pNext;
        }
        DnsFree(Some(head as *const std::ffi::c_void), DnsFreeRecordList);
    }

    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::ToSocketAddrs;

    /// 真实系统集成测试：缓存条目应结构良好（域名非空、类型合法）。
    #[test]
    fn real_dns_cache_is_structured() {
        let cache = read_dns_cache().expect("读取系统 DNS 缓存应成功");
        for e in &cache {
            assert!(!e.domain.is_empty(), "域名不应为空");
            assert!(e.record_type > 0, "记录类型应为正数");
        }
    }

    /// 真实端到端验证：先做一次真实 DNS 解析，其域名必须出现在系统缓存中。
    ///
    /// 注意：本机若运行 fake-IP 类代理（TUN 模式），解析结果 IP 为代理合成的
    /// 保留段地址，与缓存中记录不一一对应，因此这里只断言"域名级"事实。
    /// 需要 DNS Client 服务（Windows 默认启用）。
    #[test]
    fn real_dns_cache_reflects_recent_resolution() {
        // 通过系统解析器触发真实 DNS 查询（结果进入 DNS Client 缓存）
        let resolved: Vec<std::net::SocketAddr> = ("www.microsoft.com", 443)
            .to_socket_addrs()
            .expect("解析应成功")
            .collect();
        assert!(!resolved.is_empty(), "联网环境下解析应返回地址");

        let cache = read_dns_cache().expect("读取缓存应成功");
        assert!(
            cache.iter().any(|e| e.domain == "www.microsoft.com"),
            "刚解析过的域名应存在于系统 DNS 缓存中"
        );
    }
}
