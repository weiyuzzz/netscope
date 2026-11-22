//! DNS 主动探测与 ASN 查询。
//!
//! - `resolve_via_udp`：向指定 DNS 服务器发送 UDP 查询（最小化 DNS 客户端，
//!   仅用于主动探测场景，不替代系统解析器）；
//! - `dns_txt_lookup`：查询 TXT 记录（Team Cymru ASN 映射服务）；
//! - `asn_for_ip`：IP → "AS4134" 形式的 ASN 标注（可获取时）。

use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// DNS 查询测试结果（Diagnostics 页使用）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProbeResult {
    pub domain: String,
    pub server: String,
    pub answers: Vec<String>,
    /// 响应耗时（毫秒）；无响应为 None。
    pub elapsed_ms: Option<f64>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

static DNS_ID: AtomicU16 = AtomicU16::new(0x1234);

/// 构造 DNS 查询包（A 或 TXT）。
fn build_query(id: u16, qtype: u16, name: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // RD
    p.extend_from_slice(&[0x00, 0x01]); // qdcount=1
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]); // IN
    p
}

/// 解析域名（跳过压缩指针时仅处理非指针与首指针场景，探测用途足够）。
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

/// 解析 A/AAAA/TXT 应答。
fn parse_answers(p: &[u8], want_type: u16) -> Option<Vec<String>> {
    if p.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([p[2], p[3]]);
    if flags & 0x8000 == 0 {
        return Some(Vec::new()); // 非应答
    }
    let ancount = u16::from_be_bytes([p[6], p[7]]);
    // 跳过 question：名字（不能只用长度，域名可能被查询原样写入——从 12 开始走名字）
    let mut pos = 12;
    if let Some((_, next)) = parse_dns_name(p, pos) {
        pos = next + 4;
    } else {
        return None;
    }
    let mut out = Vec::new();
    for _ in 0..ancount.min(16) {
        let (_, next) = parse_dns_name(p, pos)?;
        if next + 10 > p.len() {
            break;
        }
        let rtype = u16::from_be_bytes([p[next], p[next + 1]]);
        let rdlength = u16::from_be_bytes([p[next + 8], p[next + 9]]) as usize;
        let rdata = next + 10;
        if rdata + rdlength > p.len() {
            break;
        }
        match rtype {
            1 if rdlength == 4 => {
                out.push(format!(
                    "{}.{}.{}.{}",
                    p[rdata],
                    p[rdata + 1],
                    p[rdata + 2],
                    p[rdata + 3]
                ));
            }
            28 if rdlength == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&p[rdata..rdata + 16]);
                out.push(std::net::Ipv6Addr::from(b).to_string());
            }
            16 => {
                // TXT：首字节为串长（可多段，此处取第一段）
                if rdlength >= 1 {
                    let l = p[rdata] as usize;
                    if 1 + l <= rdlength {
                        out.push(String::from_utf8_lossy(&p[rdata + 1..rdata + 1 + l]).to_string());
                    }
                }
            }
            _ => {}
        }
        pos = rdata + rdlength;
    }
    Some(out)
}

/// 向指定 DNS 服务器发送 UDP 查询并解析应答（真实网络探测）。
fn query_dns(server: &str, qtype: u16, name: &str, timeout_ms: u64) -> Result<Vec<String>, String> {
    let id = DNS_ID.fetch_add(1, Ordering::SeqCst);
    let packet = build_query(id, qtype, name);
    let addr = format!("{server}:53");
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("绑定失败: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| format!("设置超时失败: {e}"))?;
    socket
        .send_to(&packet, &addr)
        .map_err(|e| format!("发送失败: {e}"))?;
    let mut buf = [0u8; 1024];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("无响应（超时或被拦截）: {e}"))?;
    let resp = &buf[..n];
    // 校验事务 ID
    if resp.len() >= 2 && u16::from_be_bytes([resp[0], resp[1]]) != id {
        return Err("响应 ID 不匹配".into());
    }
    parse_answers(resp, qtype).ok_or_else(|| "响应解析失败".to_string())
}

/// DNS 查询测试（Diagnostics / Route Explorer 使用）：向指定服务器解析域名。
pub fn dns_query_test(domain: &str, server: Option<&str>) -> DnsProbeResult {
    let started = std::time::Instant::now();
    // 服务器优先级：用户指定 > 系统接口 DNS（真实读取）> 默认公共 DNS
    let server = server
        .map(|s| s.to_string())
        .or_else(|| {
            crate::collector::adapters::list_adapters()
                .ok()
                .and_then(|list| {
                    list.iter()
                        .find(|i| !i.dns_servers.is_empty())
                        .map(|i| i.dns_servers[0].clone())
                })
        })
        .unwrap_or_else(|| "8.8.8.8".into());

    let mut result = DnsProbeResult {
        domain: domain.to_string(),
        server: server.clone(),
        answers: Vec::new(),
        elapsed_ms: None,
        error: None,
        timestamp: Utc::now(),
    };
    match query_dns(&server, 1, domain, 3000) {
        Ok(ans) => {
            result.answers = ans;
            result.elapsed_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
            if result.answers.is_empty() {
                result.error = Some("响应无 A 记录（NXDOMAIN 或仅 CNAME）".into());
            }
        }
        Err(e) => {
            result.elapsed_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
            result.error = Some(e);
        }
    }
    result
}

/// IP → ASN（Team Cymru origin.asn.cymru.com TXT，联网可获取时）。
/// 返回形如 "AS4134 (CHINANET)" 的字符串；失败返回 None（UI 显示 '-'）。
pub fn asn_for_ip(ip: &str) -> Option<String> {
    let octets: Vec<&str> = ip.split('%').next()?.split('.').collect();
    if octets.len() != 4 {
        return None; // 仅 IPv4
    }
    let name = format!(
        "origin.{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );
    let server = crate::collector::adapters::list_adapters()
        .ok()
        .and_then(|list| {
            list.iter()
                .find(|i| !i.dns_servers.is_empty())
                .map(|i| i.dns_servers[0].clone())
        })
        .unwrap_or_else(|| "8.8.8.8".into());
    let txts = query_dns(&server, 16, &name, 2000).ok()?;
    let first = txts.first()?;
    // 格式："AS4134 | 93.184.216.0/24 | US | arin | 2006-02-13"
    let parts: Vec<&str> = first.split('|').map(|s| s.trim()).collect();
    let mut asn = parts.first()?.to_string();
    // cymru 返回裸数字（如 "15169"），统一补 AS 前缀
    if !asn.starts_with("AS") {
        asn = format!("AS{asn}");
    }
    if parts.len() > 2 {
        Some(format!("{} ({})", asn, parts[2]))
    } else {
        Some(asn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_shape() {
        let q = build_query(0x1234, 1, "example.com");
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[q.len() - 4..], [0, 1, 0, 1]);
    }

    /// 真实系统集成测试：向系统 DNS 解析 www.example.com（联网环境）。
    #[test]
    fn real_dns_query_test() {
        let r = dns_query_test("www.example.com", None);
        if r.error.is_some() {
            // 无网络 / DNS 被代理劫持：如实跳过（不判失败）
            eprintln!("dns probe error（环境限制）: {:?}", r.error);
            return;
        }
        assert!(!r.answers.is_empty());
        assert!(r.elapsed_ms.unwrap() > 0.0);
    }

    /// 真实系统集成测试：cymru ASN 查询（联网环境；失败则跳过）。
    #[test]
    fn real_asn_lookup() {
        let r = asn_for_ip("8.8.8.8");
        if r.is_none() {
            eprintln!("ASN 查询不可用（网络限制），跳过");
            return;
        }
        let asn = r.unwrap();
        assert!(asn.starts_with("AS"), "应返回 AS 形式: {asn}");
    }
}
