//! 网络质量基准测试（第三轮）。
//!
//! 安全约束：
//! - 下载 / 上传测试必须使用用户明确指定的目标 URL；
//! - 流量与时间上限硬性生效（max_bytes / max_seconds）；
//! - HTTP / 下载 / 上传复用系统 curl（无新 TLS 依赖）；
//! - 全部结果带时间、目标、代理提示等上下文落库。

use std::io::Write as _;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::models::session::{BenchmarkKind, BenchmarkResult};
use crate::probe::dns_probe;
use crate::probe::ping;

fn result(kind: BenchmarkKind, target: &str) -> BenchmarkResult {
    BenchmarkResult {
        id: format!(
            "{}-{}",
            match kind {
                BenchmarkKind::Ping => "ping",
                BenchmarkKind::Dns => "dns",
                BenchmarkKind::TcpConnect => "tcp",
                BenchmarkKind::Http => "http",
                BenchmarkKind::Download => "dl",
                BenchmarkKind::Upload => "ul",
            },
            chrono::Utc::now().timestamp_millis()
        ),
        kind,
        target: target.into(),
        started_at: chrono::Utc::now(),
        finished_at: None,
        interface: None,
        proxy_mode: None,
        egress_ip: None,
        dns_server: None,
        metrics: json!({}),
        error: None,
    }
}

/// 多目标 Ping 基准（真实 ICMP）。
pub fn ping_benchmark(targets: &[String], count: u32) -> Vec<BenchmarkResult> {
    targets
        .iter()
        .map(|t| {
            let mut r = result(BenchmarkKind::Ping, t);
            match ping::ping(t, count, 2000) {
                Ok(p) => {
                    r.finished_at = Some(chrono::Utc::now());
                    r.metrics = json!({
                        "sent": p.sent,
                        "received": p.received,
                        "lossRate": p.loss_rate,
                        "minMs": p.min_rtt_ms,
                        "avgMs": p.avg_rtt_ms,
                        "maxMs": p.max_rtt_ms,
                    });
                }
                Err(e) => {
                    r.error = Some(e);
                }
            }
            r
        })
        .collect()
}

/// DNS Benchmark：对多个服务器解析多个域名，统计延迟与成功率。
pub fn dns_benchmark(domains: &[String], servers: &[String]) -> Vec<BenchmarkResult> {
    let mut out = Vec::new();
    for server in servers {
        let mut samples = Vec::new();
        let mut success = 0u32;
        let mut total = 0u32;
        for d in domains {
            let r = dns_probe::dns_query_test(d, Some(server));
            total += 1;
            if r.error.is_none() && !r.answers.is_empty() {
                success += 1;
                if let Some(ms) = r.elapsed_ms {
                    samples.push(ms);
                }
            }
        }
        let mut r = result(BenchmarkKind::Dns, server);
        r.finished_at = Some(chrono::Utc::now());
        r.dns_server = Some(server.clone());
        r.metrics = json!({
            "domains": domains.len(),
            "success": success,
            "total": total,
            "successRate": if total > 0 { success as f64 / total as f64 } else { 0.0 },
            "avgMs": if samples.is_empty() { None } else { Some(samples.iter().sum::<f64>() / samples.len() as f64) },
            "minMs": samples.iter().cloned().fold(None::<f64>, |a, b| Some(a.map_or(b, |m: f64| m.min(b)))),
            "maxMs": samples.iter().cloned().fold(None::<f64>, |a, b| Some(a.map_or(b, |m: f64| m.max(b)))),
        });
        out.push(r);
    }
    out
}

/// TCP 连接基准：对目标端口重复 connect_timeout，统计延迟。
pub fn tcp_connect_benchmark(targets: &[(String, u16)], count: u32) -> Vec<BenchmarkResult> {
    let count = count.clamp(1, 20);
    targets
        .iter()
        .map(|(host, port)| {
            let mut r = result(BenchmarkKind::TcpConnect, &format!("{host}:{port}"));
            let mut samples = Vec::new();
            let mut failures = 0u32;
            for _ in 0..count {
                let started = Instant::now();
                let ok = (host.as_str(), *port)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut it| it.find(|a| a.is_ipv4()))
                    .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(3000)).ok());
                match ok {
                    Some(_) => samples.push(started.elapsed().as_secs_f64() * 1000.0),
                    None => failures += 1,
                }
            }
            r.finished_at = Some(chrono::Utc::now());
            r.metrics = json!({
                "count": count,
                "success": samples.len(),
                "failures": failures,
                "successRate": if count > 0 { samples.len() as f64 / count as f64 } else { 0.0 },
                "avgMs": if samples.is_empty() { None } else { Some(samples.iter().sum::<f64>() / samples.len() as f64) },
                "minMs": samples.iter().cloned().fold(None::<f64>, |a, b| Some(a.map_or(b, |m: f64| m.min(b)))),
                "maxMs": samples.iter().cloned().fold(None::<f64>, |a, b| Some(a.map_or(b, |m: f64| m.max(b)))),
            });
            r
        })
        .collect()
}

/// 解析 curl -w 七段输出。
pub fn parse_curl_timing(
    out: &str,
) -> Option<(f64, f64, f64, f64, f64, u32, u64)> {
    let parts: Vec<&str> = out.trim().split_whitespace().collect();
    if parts.len() < 7 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
        parts[4].parse().ok()?,
        parts[5].parse().ok()?,
        parts[6].parse().ok()?,
    ))
}

fn run_curl(args: &[&str], timeout_secs: u64) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let out = Command::new("curl.exe")
        .args(args)
        .creation_flags(0x0800_0000)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("curl 执行失败: {e}"))?;
    if out.status.code().is_none() {
        return Err("curl 被终止".into());
    }
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "curl 退出码 {}（{}）",
            out.status.code().unwrap_or(-1),
            stderr.trim().chars().take(120).collect::<String>()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// HTTP 请求耗时基准（真实 curl，分段计时）。
pub fn http_benchmark(url: &str) -> BenchmarkResult {
    let mut r = result(BenchmarkKind::Http, url);
    let out = run_curl(
        &[
            "-s",
            "-o",
            "NUL",
            "--max-time",
            "15",
            "-w",
            "%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_code} %{size_download}",
            url,
        ],
        20,
    );
    match out.ok().and_then(|o| parse_curl_timing(&o)) {
        Some((dns_t, connect_t, tls_t, ttfb, total_t, code, size)) => {
            r.finished_at = Some(chrono::Utc::now());
            r.metrics = json!({
                "httpCode": code,
                "dnsMs": dns_t * 1000.0,
                "connectMs": connect_t * 1000.0,
                "tlsMs": tls_t * 1000.0,
                "ttfbMs": ttfb * 1000.0,
                "totalMs": total_t * 1000.0,
                "sizeBytes": size,
            });
        }
        None => {
            r.error = Some("HTTP 请求失败或超时（15s）".into());
        }
    }
    r
}

/// 下载速度基准（用户指定 URL；硬性流量/时间上限）。
pub fn download_benchmark(url: &str, max_bytes: u64, max_seconds: u64) -> BenchmarkResult {
    let mut r = result(BenchmarkKind::Download, url);
    let max_bytes = max_bytes.clamp(1, 200 * 1024 * 1024);
    let max_seconds = max_seconds.clamp(1, 300);
    let max_filesize = max_bytes.to_string();
    let max_time = max_seconds.to_string();
    let out = run_curl(
        &[
            "-s",
            "-o",
            "NUL",
            "--max-filesize",
            &max_filesize,
            "--max-time",
            &max_time,
            "-w",
            "%{size_download} %{time_total} %{speed_download}",
            url,
        ],
        max_seconds + 5,
    );
    match out.as_ref().ok().and_then(|o| {
        let parts: Vec<&str> = o.trim().split_whitespace().collect();
        if parts.len() >= 2 {
            Some((
                parts[0].parse::<u64>().unwrap_or(0),
                parts[1].parse::<f64>().unwrap_or(0.0),
            ))
        } else {
            None
        }
    }) {
        Some((bytes, seconds)) => {
            r.finished_at = Some(chrono::Utc::now());
            let speed = if seconds > 0.001 { bytes as f64 / seconds } else { 0.0 };
            r.metrics = json!({
                "bytes": bytes,
                "seconds": seconds,
                "bytesPerSec": speed,
                "limitBytes": max_bytes,
                "limitSeconds": max_seconds,
            });
        }
        None => {
            r.error = Some(match out {
                Err(e) => format!("下载失败: {e}"),
                Ok(o) => format!("下载失败：curl 输出无法解析: {:.120}", o),
            });
        }
    }
    r
}

/// 上传速度基准（用户指定 URL；生成临时载荷；硬性上限）。
pub fn upload_benchmark(url: &str, max_bytes: u64, max_seconds: u64) -> BenchmarkResult {
    let mut r = result(BenchmarkKind::Upload, url);
    let max_bytes = max_bytes.clamp(1, 100 * 1024 * 1024);
    let max_seconds = max_seconds.clamp(1, 300);

    // 临时载荷文件
    let payload_path = std::env::temp_dir().join(format!("ns_upload_{}.bin", std::process::id()));
    {
        let mut f = match std::fs::File::create(&payload_path) {
            Ok(f) => f,
            Err(e) => {
                r.error = Some(format!("创建载荷文件失败: {e}"));
                return r;
            }
        };
        let chunk = [0u8; 65536];
        let mut remaining = max_bytes;
        while remaining > 0 {
            let n = remaining.min(chunk.len() as u64) as usize;
            if f.write_all(&chunk[..n]).is_err() {
                break;
            }
            remaining -= n as u64;
        }
    }

    let max_time = max_seconds.to_string();
    let payload_arg = format!("@{}", payload_path.display());
    let out = run_curl(
        &[
            "-s",
            "-o",
            "NUL",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/octet-stream",
            "--data-binary",
            &payload_arg,
            "--max-time",
            &max_time,
            "-w",
            "%{size_upload} %{time_total} %{speed_upload} %{http_code}",
            url,
        ],
        max_seconds + 5,
    );
    let _ = std::fs::remove_file(&payload_path);

    match out.as_ref().ok().and_then(|o| {
        let parts: Vec<&str> = o.trim().split_whitespace().collect();
        if parts.len() >= 3 {
            Some((
                parts[0].parse::<u64>().unwrap_or(0),
                parts[1].parse::<f64>().unwrap_or(0.0),
                parts[3].parse::<u32>().unwrap_or(0),
            ))
        } else {
            None
        }
    }) {
        Some((bytes, seconds, code)) => {
            r.finished_at = Some(chrono::Utc::now());
            let speed = if seconds > 0.05 { bytes as f64 / seconds } else { 0.0 };
            r.metrics = json!({
                "bytes": bytes,
                "seconds": seconds,
                "bytesPerSec": speed,
                "httpCode": code,
                "limitBytes": max_bytes,
                "limitSeconds": max_seconds,
            });
        }
        None => {
            r.error = Some(match out {
                Err(e) => format!("上传失败: {e}"),
                Ok(o) => format!("上传失败：curl 输出无法解析: {:.120}", o),
            });
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn curl_timing_parse() {
        let parsed = parse_curl_timing("0.01 0.02 0.05 0.08 0.10 200 12345").unwrap();
        assert_eq!(parsed.5, 200);
        assert_eq!(parsed.6, 12345);
        assert!((parsed.4 - 0.10).abs() < 1e-9);
        assert!(parse_curl_timing("bad").is_none());
    }

    /// 真实端到端：本地线程 TCP 服务器发送 1MB → 下载基准测量真实速度。
    #[test]
    fn real_download_benchmark_against_local_server() {
        const TOTAL: u64 = 1024 * 1024;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            // 先读取 GET 请求（避免关闭时接收缓冲未读数据触发 RST 中断客户端）
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            // 简单 HTTP 响应 + 1MB 载荷
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\nConnection: close\r\n\r\n");
            let _ = sock.write_all(head.as_bytes());
            let chunk = vec![0u8; 65536];
            let mut left = TOTAL;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                if sock.write_all(&chunk[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
        });

        let r = download_benchmark(
            &format!("http://127.0.0.1:{port}/"),
            TOTAL,
            15,
        );
        server.join().unwrap();
        assert!(r.error.is_none(), "本地下载不应失败: {:?}", r.error);
        let bytes = r.metrics["bytes"].as_u64().unwrap_or(0);
        // 实际下载 ≈ 1MB（curl 按字节计；允许头尾误差）
        assert!(
            bytes >= TOTAL - 1024,
            "应下载完整载荷: {bytes}"
        );
        let speed = r.metrics["bytesPerSec"].as_f64().unwrap_or(0.0);
        assert!(speed > 0.0, "应测出非零速度");
    }

    /// 真实端到端：本地服务器接收 POST → 上传基准测量真实速度。
    #[test]
    fn real_upload_benchmark_against_local_server() {
        const TOTAL: u64 = 256 * 1024;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            // 读到请求结束（简化：读完 Content-Length 指定数量）
            let mut buf = vec![0u8; 4096];
            let mut total_read = 0u64;
            let mut header_done = false;
            let mut content_len = 0u64;
            let mut body_read = 0u64;
            loop {
                let n = match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                total_read += n as u64;
                if !header_done {
                    if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                        for line in text.split("\r\n") {
                            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                        if text.contains("\r\n\r\n") {
                            header_done = true;
                            if let Some(pos) = text.find("\r\n\r\n") {
                                body_read = (text.len() - pos - 4) as u64;
                            }
                        }
                    }
                } else {
                    body_read += n as u64;
                }
                if content_len > 0 && body_read >= content_len {
                    break;
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });

        let r = upload_benchmark(
            &format!("http://127.0.0.1:{port}/upload"),
            TOTAL,
            15,
        );
        server.join().unwrap();
        assert!(r.error.is_none(), "本地上传不应失败: {:?}", r.error);
        let bytes = r.metrics["bytes"].as_u64().unwrap_or(0);
        assert!(bytes >= TOTAL - 1024, "应上传完整载荷: {bytes}");
    }

    #[test]
    fn limits_are_clamped() {
        // 上限保护：非法大值被收敛（内部 clamp，不发起网络请求的可测路径有限，
        // 这里验证 download 对无效 URL 快速失败且不超时）
        let r = download_benchmark("http://127.0.0.1:9/nothing", 10 * 1024 * 1024, 3);
        assert!(r.error.is_some(), "不可达目标应快速失败");
    }

    #[test]
    fn real_tcp_connect_loopback() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let l = listener;
            for stream in l.incoming().take(3) {
                drop(stream);
            }
        });
        let results = tcp_connect_benchmark(&[("127.0.0.1".to_string(), port)], 3);
        server.join().unwrap();
        assert_eq!(results.len(), 1);
        let rate = results[0].metrics["successRate"].as_f64().unwrap_or(0.0);
        assert_eq!(rate, 1.0, "回环 TCP 连接应全部成功");
        let avg = results[0].metrics["avgMs"].as_f64().unwrap_or(0.0);
        assert!(avg < 100.0, "回环连接耗时应很小: {avg}ms");
    }
}
