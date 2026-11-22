//! 诊断工具：对真实数据库运行诊断规则 + 导出 HTML 报告（端到端验证）。

fn main() {
    let path = std::env::var("NS_DB").unwrap_or_else(|_| {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        format!("{appdata}/dev.netscope.app/netscope.db")
    });
    let conn = rusqlite::Connection::open(&path).expect("打开数据库失败");

    // 最近 30 分钟时间线
    let since = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
    let timeline = netscope_lib::storage::history_repository::query_timeline(
        &conn, Some(&since), None, None, None, 5000,
    )
    .expect("查询时间线失败");
    println!("窗口时间线事件: {}", timeline.len());

    let ctx = netscope_lib::analyzer::rules::DiagnosticContext {
        now: chrono::Utc::now(),
        timeline: &timeline,
        syn_failures_recent: 0,
        retrans_recent: 0,
        rst_recent: 0,
        handshake_p95_ms: None,
        proxy_conn_failures: 0,
        ping_loss_rate: None,
        dns_result_changes: 0,
        icmp_unreachable: 0,
        proxy_servers: Vec::new(),
        proxy_listener_gone: false,
        dns_probe_failures: 0,
        dns_avg_ms: None,
        dns_baseline_ms: None,
        ping_avg_ms: None,
        ping_baseline_ms: None,
    };
    let findings = netscope_lib::analyzer::rules::run_rules(&ctx, &[]);
    println!("诊断结论: {} 条", findings.len());
    for f in &findings {
        println!(
            "  [{}] {} ({:?}, {} 条证据)",
            serde_json::to_string(&f.severity).unwrap(),
            f.title,
            f.confidence,
            f.evidence.len()
        );
    }

    // RCA：以最近一次 DNS 域名为对象
    let subject = timeline
        .iter()
        .filter(|e| e.kind == "dns_new")
        .last()
        .and_then(|e| e.payload.get("domain").and_then(|v| v.as_str()))
        .unwrap_or("msedge.exe")
        .to_string();
    println!("RCA 对象: {subject}");
    let input = netscope_lib::analyzer::diagnostics::RcaInput {
        subject: subject.clone(),
        window_start: chrono::Utc::now() - chrono::Duration::minutes(30),
        window_end: chrono::Utc::now(),
        timeline: &timeline,
        proxies: &[],
        vpn: &[],
        route_probes: &[],
        dns_server: None,
    };
    let report = netscope_lib::analyzer::diagnostics::analyze(&input);
    println!("症状: {}", report.symptom);
    println!("观察 {} 条 / 原因 {} 条", report.observations.len(), report.causes.len());
    for c in &report.causes {
        println!("  - {}（{:?}）", c.description, c.confidence);
    }

    // HTML 报告导出（真实数据）
    let html = netscope_lib::analyzer::report::build_html_report(
        "NetScope 诊断报告（端到端验证）",
        &findings,
        Some(&report),
        &timeline,
    );
    let out = std::env::temp_dir().join("netscope-r3-report.html");
    std::fs::write(&out, &html).expect("写报告失败");
    println!("HTML 报告: {}", out.display());
}
