//! 诊断报告生成与导出（第三轮）。
//!
//! - HTML / JSON 导出（结构化数据 + 可读模板）；
//! - PDF 导出：通过系统 Edge 无头模式打印 HTML（Windows 10/11 自带，无新依赖）；
//! - 敏感信息脱敏：导出前可隐藏本地 IP / 主机名 / 域名 / 公网 IP（按用户选择）。

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::Serialize;

use crate::models::session::{
    DiagnosticFinding, RcaReport, Severity, TimelineEvent,
};

/// 脱敏选项（导出前由用户勾选）。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskOptions {
    pub mask_local_ips: bool,
    pub mask_public_ips: bool,
    pub mask_hostnames: bool,
    pub mask_domains: bool,
}

/// 脱敏上下文（要隐藏的具体值，来自真实采集）。
#[derive(Debug, Clone, Default)]
pub struct MaskContext {
    pub local_ips: HashSet<String>,
    pub public_ips: HashSet<String>,
    pub hostnames: HashSet<String>,
    pub domains: HashSet<String>,
}

/// 判断 IPv4 是否为私网地址（本地）。
pub fn is_private_ipv4(ip: &str) -> bool {
    let parts: Vec<u32> = ip
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() != 4 {
        return false;
    }
    let (a, b) = (parts[0], parts[1]);
    a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && (16..=31).contains(&b)) || (a == 169 && b == 254)
}

/// 对文本执行脱敏（替换已知敏感值为占位符）。
pub fn mask_text(text: &str, options: &MaskOptions, ctx: &MaskContext) -> String {
    let mut out = text.to_string();
    let mut replace_all = |out: &mut String, values: &HashSet<String>, tag: &str| {
        for (i, v) in values.iter().enumerate() {
            if v.is_empty() {
                continue;
            }
            *out = out.replace(v.as_str(), &format!("[{tag}{i}]"));
        }
    };
    if options.mask_local_ips {
        replace_all(&mut out, &ctx.local_ips, "本地IP");
    }
    if options.mask_public_ips {
        replace_all(&mut out, &ctx.public_ips, "公网IP");
    }
    if options.mask_hostnames {
        replace_all(&mut out, &ctx.hostnames, "主机名");
    }
    if options.mask_domains {
        replace_all(&mut out, &ctx.domains, "域名");
    }
    // 全局兜底：私网 IP 模式扫描（本地 IP 集合未覆盖到的）
    if options.mask_local_ips {
        out = mask_private_ip_patterns(&out);
    }
    out
}

/// 扫描并替换文本中所有私网 IPv4 字面量。
pub fn mask_private_ip_patterns(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut counter = 0;
    while i < bytes.len() {
        // 探测形如 a.b.c.d 的序列
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut octets: Vec<u32> = Vec::new();
            let mut ok = true;
            for part in 0..4 {
                let mut val = 0u32;
                let mut digits = 0;
                while j < bytes.len() && bytes[j].is_ascii_digit() && digits < 3 {
                    val = val * 10 + (bytes[j] - b'0') as u32;
                    j += 1;
                    digits += 1;
                }
                if digits == 0 || val > 255 {
                    ok = false;
                    break;
                }
                octets.push(val);
                if part < 3 {
                    if j < bytes.len() && bytes[j] == b'.' {
                        j += 1;
                    } else {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && (j >= bytes.len() || !(bytes[j].is_ascii_digit() || bytes[j] == b'.')) {
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                if is_private_ipv4(&ip) {
                    let _ = write!(out, "[本地IP{}]", counter);
                    counter += 1;
                    i = j;
                    continue;
                }
            }
            i = start + 1;
            out.push(bytes[start] as char);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn severity_badge(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "严重",
        Severity::Warning => "警告",
        Severity::Info => "提示",
    }
}

/// 生成 HTML 报告（自包含，浏览器直接打开 / 转 PDF）。
pub fn build_html_report(
    title: &str,
    findings: &[DiagnosticFinding],
    rca: Option<&RcaReport>,
    timeline: &[TimelineEvent],
) -> String {
    let mut html = String::new();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
    let _ = write!(
        html,
        r#"<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{title}</title>
<style>
body {{ background: #0b1220; color: #e2e8f0; font-family: "Segoe UI", system-ui, sans-serif; margin: 0; padding: 32px; }}
h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; color: #22d3ee; margin-top: 28px; }}
.card {{ background: #111a2c; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin: 10px 0; }}
.sev-critical {{ color: #f87171; font-weight: 600; }}
.sev-warning {{ color: #fbbf24; font-weight: 600; }}
.sev-info {{ color: #64748b; font-weight: 600; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #1e293b; }}
th {{ color: #64748b; font-weight: 500; }}
.evidence {{ color: #94a3b8; font-size: 12px; }}
.conf {{ float: right; font-size: 12px; color: #a78bfa; }}
</style></head><body>
<h1>{title}</h1>
<p class="evidence">生成时间：{now}</p>
"#
    );

    // 故障概要
    let _ = write!(html, "<h2>1. 诊断结论</h2>");
    if findings.is_empty() {
        let _ = write!(html, r#"<div class="card evidence">窗口内未发现触发规则的异常（不等于无故障：部分指标需 Npcap 或管理员权限采集）。</div>"#);
    }
    for f in findings {
        let sev = severity_badge(&f.severity);
        let _ = write!(
            html,
            r#"<div class="card"><div><span class="sev-{sev}">[{sev}]</span> {title} <span class="conf">置信度 {conf:?}</span></div>
<div class="evidence">规则 {rule} · 检测于 {at}</div>"#,
            sev = sev,
            title = html_escape(&f.title),
            conf = f.confidence,
            rule = html_escape(&f.rule_id),
            at = f.detected_at.format("%Y-%m-%d %H:%M:%S"),
        );
        for e in &f.evidence {
            let _ = write!(
                html,
                r#"<div class="evidence">证据：{}（{}，{}）</div>"#,
                html_escape(&e.description),
                html_escape(&e.source),
                e.timestamp.format("%H:%M:%S")
            );
        }
        let _ = write!(html, "<div class=\"evidence\">可能原因：{}</div>", html_escape(&f.possible_causes.join("；")));
        let _ = write!(html, "<div class=\"evidence\">验证建议：{}</div>", html_escape(&f.verification.join("；")));
        let _ = write!(html, "</div>");
    }

    // RCA
    if let Some(r) = rca {
        let _ = write!(html, "<h2>2. 根因分析（{subject}）</h2>", subject = html_escape(&r.subject));
        let _ = write!(html, r#"<div class="card"><div>症状：{}</div>"#, html_escape(&r.symptom));
        let _ = write!(html, "<div class=\"evidence\">观察证据：</div>");
        for o in &r.observations {
            let _ = write!(
                html,
                "<div class=\"evidence\">· {}（{}，{}）</div>",
                html_escape(&o.description),
                html_escape(&o.source),
                o.timestamp.format("%H:%M:%S")
            );
        }
        let _ = write!(html, "<div class=\"evidence\">可能原因：</div>");
        for c in &r.causes {
            let _ = write!(
                html,
                "<div class=\"evidence\">· {}（置信度 {:?}，{} 条证据）</div>",
                html_escape(&c.description),
                c.confidence,
                c.evidence.len()
            );
        }
        let _ = write!(html, "<div class=\"evidence\">建议：{}</div>", html_escape(&r.suggestions.join("；")));
        let _ = write!(html, "</div>");
    }

    // 时间线
    let _ = write!(html, "<h2>3. 关键事件时间线（最近 {} 条）</h2>", timeline.len());
    let _ = write!(
        html,
        "<table><tr><th>时间</th><th>来源</th><th>类型</th><th>摘要</th></tr>"
    );
    for e in timeline.iter().rev().take(200) {
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.timestamp.format("%H:%M:%S"),
            html_escape(&e.source),
            html_escape(&e.kind),
            html_escape(&e.summary)
        );
    }
    let _ = write!(html, "</table></body></html>");
    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// PDF 导出：系统 Edge 无头模式打印 HTML（Windows 10/11 自带）。
pub fn html_to_pdf(html_path: &std::path::Path, pdf_path: &std::path::Path) -> Result<(), String> {
    const EDGE_CANDIDATES: [&str; 2] = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ];
    let edge = EDGE_CANDIDATES
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| "未找到 Microsoft Edge（PDF 导出需要 Edge 或手动用浏览器打印 HTML）".to_string())?;

    let url = format!("file:///{}", html_path.to_string_lossy().replace('\\', "/"));
    let output = std::process::Command::new(edge)
        .args([
            "--headless",
            "--disable-gpu",
            &format!("--print-to-pdf={}", pdf_path.to_string_lossy()),
            "--no-pdf-header-footer",
            &url,
        ])
        .output()
        .map_err(|e| format!("启动 Edge 失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Edge 打印失败（退出码 {}）",
            output.status.code().unwrap_or(-1)
        ));
    }
    if !pdf_path.exists() {
        return Err("PDF 未生成".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::proxy::Confidence;
    use crate::models::session::EvidenceRef;
    use chrono::Utc;

    #[test]
    fn private_ip_pattern_masking() {
        let out = mask_private_ip_patterns("连接 192.168.1.10 失败，公网 8.8.8.8 正常，网关 192.168.0.1");
        assert!(out.contains("[本地IP"), "私网 IP 应被脱敏: {out}");
        assert!(out.contains("8.8.8.8"), "公网 IP 不应被本地规则脱敏: {out}");
    }

    #[test]
    fn known_value_masking() {
        let options = MaskOptions {
            mask_local_ips: true,
            mask_public_ips: true,
            mask_hostnames: true,
            mask_domains: true,
        };
        let mut ctx = MaskContext::default();
        ctx.local_ips.insert("192.168.1.10".into());
        ctx.public_ips.insert("203.0.113.5".into());
        ctx.hostnames.insert("DESKTOP-RNBV6M6".into());
        ctx.domains.insert("google.com".into());
        let out = mask_text(
            "主机 DESKTOP-RNBV6M6 经 192.168.1.10 访问 google.com，出口 203.0.113.5",
            &options,
            &ctx,
        );
        assert!(!out.contains("192.168.1.10"));
        assert!(!out.contains("DESKTOP-RNBV6M6"));
        assert!(!out.contains("google.com"));
        assert!(!out.contains("203.0.113.5"));
    }

    #[test]
    fn html_report_structure() {
        let f = DiagnosticFinding {
            rule_id: "iface.link_down".into(),
            title: "网卡断开".into(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            detected_at: Utc::now(),
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "timeline:interface_changed".into(),
                timestamp: Utc::now(),
                description: "网卡 以太网 状态: up → down".into(),
            }],
            possible_causes: vec!["物理链路断开".into()],
            verification: vec!["检查线缆".into()],
        };
        let html = build_html_report("测试报告", &[f.clone()], None, &[]);
        assert!(html.contains("诊断结论"));
        assert!(html.contains("网卡断开"));
        assert!(html.contains("严重"));
        assert!(html.contains("up → down"));
        // HTML 注入防护：标题中的尖括号被转义
        let mut f2 = f.clone();
        f2.title = "<script>alert(1)</script>".into();
        let html2 = build_html_report("注入测试", &[f2], None, &[]);
        assert!(!html2.contains("<script>alert"), "必须转义 HTML");
    }

    #[test]
    fn html_escape_works() {
        assert_eq!(html_escape("<a>"), "&lt;a&gt;");
    }
}
