//! 诊断工具：转储系统 DNS 缓存条目（域名 + 记录类型）。
//!
//! 用于验证 DNS 缓存采集能力边界（记录数据在 Win10 19045 上不内联，详见
//! `src/collector/dns.rs` 模块文档）。
//!
//! 运行：`cargo run --example dns_cache_dump`（在 src-tauri 目录下）

use netscope_lib::collector::dns::read_dns_cache;

fn main() {
    match read_dns_cache() {
        Ok(cache) => {
            println!("DNS 缓存条目数: {}", cache.len());
            for e in &cache {
                let kind = match e.record_type {
                    1 => "A",
                    5 => "CNAME",
                    12 => "PTR",
                    28 => "AAAA",
                    _ => "OTHER",
                };
                println!("  [{kind:>5}] {}", e.domain);
            }
        }
        Err(e) => {
            eprintln!("读取失败: {e}");
            std::process::exit(1);
        }
    }
}
