//! 规则驱动的诊断引擎（第三轮）。
//!
//! 设计原则：
//! - 每条规则是纯函数：输入 `DiagnosticContext`（时间线窗口 + 当前状态 + 指标），
//!   输出 `Option<DiagnosticFinding>`；全部可合成数据单测；
//! - 结论必须引用证据（来源 + 时间 + 描述）；单指标不得得出确定性根因；
//! - 置信度随佐证数量提升；规则可被用户禁用（diagnostic_rules 表）。

use chrono::{DateTime, Utc};

use crate::models::proxy::Confidence;
use crate::models::session::{
    DiagnosticFinding, DiagnosticRuleMeta, EvidenceRef, Severity, TimelineEvent,
};

/// 诊断上下文（引擎输入，全部来自真实采集）。
pub struct DiagnosticContext<'a> {
    pub now: DateTime<Utc>,
    /// 时间线窗口（最近 N 分钟，时间正序）。
    pub timeline: &'a [TimelineEvent],
    pub syn_failures_recent: u32,
    pub retrans_recent: u32,
    pub rst_recent: u32,
    /// 最近抓包建连耗时样本 P95（毫秒，可空）。
    pub handshake_p95_ms: Option<f64>,
    /// 系统代理服务器当前列表（host:port）。
    pub proxy_servers: Vec<String>,
    /// 本地代理监听是否消失（此前存在 → 现在无）。
    pub proxy_listener_gone: bool,
    /// DNS 主动探测最近失败次数。
    pub dns_probe_failures: u32,
    /// DNS 主动探测最近平均延迟（毫秒，可空）。
    pub dns_avg_ms: Option<f64>,
    /// DNS 历史平均延迟基线（毫秒，可空）。
    pub dns_baseline_ms: Option<f64>,
    /// 连接到本地代理端口的失败/关闭次数（调用方从时间线计算）。
    pub proxy_conn_failures: u32,
    /// 最近 ping 丢包率（0..1，可空）。
    pub ping_loss_rate: Option<f64>,
    /// DNS 解析结果变化次数（连续探测结果对比，调用方填充）。
    pub dns_result_changes: u32,
    /// 抓包观测的 ICMP 不可达（type 3）计数。
    pub icmp_unreachable: u32,
    /// 最近 ping 平均延迟（毫秒，可空）。
    pub ping_avg_ms: Option<f64>,
    /// ping 历史基线（毫秒，可空）。
    pub ping_baseline_ms: Option<f64>,
}

impl<'a> DiagnosticContext<'a> {
    /// 统计窗口内某类时间线事件数量。
    pub fn count_kind(&self, kind: &str) -> usize {
        self.timeline.iter().filter(|e| e.kind == kind).count()
    }

    /// 窗口内某类事件的证据引用（最新在前）。
    pub fn evidence_of_kind(&self, kind: &str, max: usize) -> Vec<EvidenceRef> {
        self.timeline
            .iter()
            .filter(|e| e.kind == kind)
            .rev()
            .take(max)
            .map(|e| EvidenceRef {
                source: format!("timeline:{}", e.kind),
                timestamp: e.timestamp,
                description: e.summary.clone(),
            })
            .collect()
    }

    /// 窗口内连接打开/关闭数量。
    pub fn conn_open_closed(&self) -> (usize, usize) {
        (
            self.count_kind("conn_opened"),
            self.count_kind("conn_closed"),
        )
    }
}

/// 规则注册表（元数据，UI 开关用）。第一批 16 条。
pub fn rule_registry() -> Vec<DiagnosticRuleMeta> {
    let mk = |rule_id: &str,
              category: &str,
              title: &str,
              severity: Severity,
              description: &str| {
        DiagnosticRuleMeta {
            rule_id: rule_id.into(),
            category: category.into(),
            title: title.into(),
            severity,
            description: description.into(),
            enabled: true,
        }
    };
    vec![
        mk("dns.probe_failure", "DNS", "DNS 主动解析失败", Severity::Critical, "窗口内 DNS 主动探测出现失败"),
        mk("dns.latency_anomaly", "DNS", "DNS 延迟异常", Severity::Warning, "DNS 平均延迟显著高于历史基线（需基线且超过绝对阈值）"),
        mk("tcp.syn_failure", "TCP", "TCP 建连失败", Severity::Warning, "SYN_SENT 连接消失且未到达 ESTABLISHED"),
        mk("tcp.handshake_slow", "TCP", "连接建立耗时异常", Severity::Warning, "SYN→SYN/ACK P95 超过阈值（需抓包）"),
        mk("tcp.retransmit_increase", "TCP", "TCP 重传增加", Severity::Warning, "窗口内重传事件数量异常（需抓包）"),
        mk("tcp.rst_increase", "TCP", "RST 异常增加", Severity::Warning, "窗口内 RST 事件数量异常（需抓包）"),
        mk("tcp.frequent_disconnect", "TCP", "连接频繁断开", Severity::Info, "窗口内连接关闭数量显著高于建立"),
        mk("iface.link_down", "接口", "网卡断开", Severity::Critical, "接口运行状态 up → down"),
        mk("iface.ip_change", "接口", "IP 地址变化", Severity::Info, "接口 IPv4 地址发生变化"),
        mk("iface.speed_drop", "接口", "网卡协商速率下降", Severity::Warning, "协商速率下降超过 50%"),
        mk("iface.gateway_change", "接口", "默认网关变化", Severity::Warning, "系统默认路由发生变化"),
        mk("proxy.listener_gone", "代理/VPN", "本地代理服务不可达", Severity::Critical, "此前存在的本地代理监听消失"),
        mk("proxy.route_change", "代理/VPN", "VPN 路由变化", Severity::Warning, "默认路由变化（可能 VPN 切换/断开）"),
        mk("quality.latency_spike", "质量", "延迟突然增加", Severity::Warning, "Ping 平均延迟显著高于历史基线"),
        mk("quality.timeout_rate", "质量", "连接超时率升高", Severity::Warning, "窗口内建连失败占比异常"),
        mk("quality.degradation", "质量", "整体链路质量下降", Severity::Info, "重传与建连失败同时升高"),
        mk("dns.result_change", "DNS", "DNS 解析结果变化", Severity::Info, "同一域名连续解析结果不一致（需主动探测数据）"),
        mk("dns.server_unreachable", "DNS", "DNS 服务器不可达", Severity::Critical, "同一 DNS 服务器连续 3 次以上探测失败"),
        mk("iface.flapping", "接口", "网络接口频繁切换", Severity::Warning, "窗口内接口状态变化达到 3 次以上"),
        mk("proxy.connect_failure", "代理/VPN", "代理连接失败", Severity::Critical, "与本地代理端口的连接出现多次关闭"),
        mk("quality.loss_increase", "质量", "丢包率升高", Severity::Warning, "Ping 丢包率超过 10%（需探测数据）"),
        mk("quality.performance_anomaly", "质量", "下载性能异常", Severity::Warning, "同目标下载速度较上次下降超过 50%"),
        mk("tcp.port_unreachable", "TCP", "目标端口不可达", Severity::Warning, "抓包观测到 ICMP type 3 不可达"),
    ]
}

fn evidence(ctx: &DiagnosticContext, kind: &str, max: usize) -> Vec<EvidenceRef> {
    ctx.evidence_of_kind(kind, max)
}

/// 运行全部规则（跳过被禁用的规则 ID）。
pub fn run_rules(ctx: &DiagnosticContext, disabled: &[String]) -> Vec<DiagnosticFinding> {
    evaluate(ctx)
        .into_iter()
        .filter(|f| !disabled.iter().any(|d| d == &f.rule_id))
        .collect()
}

/// 规则求值主入口（每条规则一个 if 块，输出带证据的 Finding）。
pub fn evaluate(ctx: &DiagnosticContext) -> Vec<DiagnosticFinding> {
    let mut findings: Vec<DiagnosticFinding> = Vec::new();

    // ---- DNS ----
    if ctx.dns_probe_failures >= 1 {
        findings.push(DiagnosticFinding {
            rule_id: "dns.probe_failure".into(),
            title: "DNS 主动解析失败".into(),
            severity: Severity::Critical,
            confidence: if ctx.dns_probe_failures >= 3 {
                Confidence::Confirmed
            } else {
                Confidence::Inferred
            },
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "dns_new", 3),
            possible_causes: vec![
                "DNS 服务器不可达或响应异常".into(),
                "网络出口（代理/VPN）对 DNS 流量拦截".into(),
                "本机 DNS 配置错误".into(),
            ],
            verification: vec![
                "用 nslookup 对比不同 DNS 服务器".into(),
                "检查 Proxy Analysis 中的代理/VPN 状态".into(),
            ],
        });
    }
    if let (Some(avg), Some(base)) = (ctx.dns_avg_ms, ctx.dns_baseline_ms) {
        if base > 0.0 && avg > base * 3.0 && avg > 150.0 {
            findings.push(DiagnosticFinding {
                rule_id: "dns.latency_anomaly".into(),
                title: "DNS 延迟异常".into(),
                severity: Severity::Warning,
                confidence: Confidence::Inferred,
                detected_at: ctx.now,
                impact_processes: vec![],
                impact_domains: vec![],
                evidence: vec![EvidenceRef {
                    source: "probe:dns".into(),
                    timestamp: ctx.now,
                    description: format!("DNS 平均延迟 {avg:.0}ms，基线 {base:.0}ms"),
                }],
                possible_causes: vec![
                    "当前使用的 DNS 服务器响应慢".into(),
                    "出口链路抖动".into(),
                ],
                verification: vec!["对多个公共 DNS 分别测速对比".into()],
            });
        }
    }

    // ---- TCP ----
    if ctx.syn_failures_recent >= 1 {
        findings.push(DiagnosticFinding {
            rule_id: "tcp.syn_failure".into(),
            title: "TCP 建连失败".into(),
            severity: Severity::Warning,
            confidence: if ctx.syn_failures_recent >= 3 {
                Confidence::Confirmed
            } else {
                Confidence::Inferred
            },
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "conn_closed", 3),
            possible_causes: vec![
                "目标不可达或端口未开放".into(),
                "本地网络/网关问题".into(),
                "代理链路问题（若目标经代理）".into(),
            ],
            verification: vec![
                "Route Explorer 执行 Traceroute 观察路径".into(),
                "检查对应进程是否走代理链路".into(),
            ],
        });
    }
    if let Some(p95) = ctx.handshake_p95_ms {
        if p95 > 1500.0 {
            findings.push(DiagnosticFinding {
                rule_id: "tcp.handshake_slow".into(),
                title: "连接建立耗时异常".into(),
                severity: Severity::Warning,
                confidence: Confidence::Confirmed,
                detected_at: ctx.now,
                impact_processes: vec![],
                impact_domains: vec![],
                evidence: vec![EvidenceRef {
                    source: "capture:handshake".into(),
                    timestamp: ctx.now,
                    description: format!("SYN→SYN/ACK P95 = {p95:.0}ms"),
                }],
                possible_causes: vec![
                    "目标服务器响应慢".into(),
                    "链路 RTT 增大（绕路/劣化）".into(),
                ],
                verification: vec!["Route Explorer 对目标做 Traceroute 对比".into()],
            });
        }
    }
    if ctx.retrans_recent >= 20 {
        findings.push(DiagnosticFinding {
            rule_id: "tcp.retransmit_increase".into(),
            title: "TCP 重传增加".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "capture:retransmit".into(),
                timestamp: ctx.now,
                description: format!("窗口内重传事件 {} 次", ctx.retrans_recent),
            }],
            possible_causes: vec!["链路丢包/质量劣化".into(), "对端拥塞".into()],
            verification: vec!["持续下载测试观察重传增长趋势".into()],
        });
    }
    if ctx.rst_recent >= 10 {
        findings.push(DiagnosticFinding {
            rule_id: "tcp.rst_increase".into(),
            title: "RST 异常增加".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "capture:rst".into(),
                timestamp: ctx.now,
                description: format!("窗口内 RST 事件 {} 次", ctx.rst_recent),
            }],
            possible_causes: vec![
                "对端主动重置（服务异常/防火墙）".into(),
                "中间设备拦截".into(),
            ],
            verification: vec!["Packet Inspector 过滤 RST 观察方向与端口".into()],
        });
    }
    let (opened, closed) = ctx.conn_open_closed();
    if closed >= 20 && opened > 0 && closed as f64 / opened as f64 > 2.0 {
        findings.push(DiagnosticFinding {
            rule_id: "tcp.frequent_disconnect".into(),
            title: "连接频繁断开".into(),
            severity: Severity::Info,
            confidence: Confidence::Inferred,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "timeline:conn_closed".into(),
                timestamp: ctx.now,
                description: format!("窗口内关闭 {closed} 次 / 打开 {opened} 次"),
            }],
            possible_causes: vec![
                "应用行为（短连接轮询）".into(),
                "网络不稳定导致被动断开".into(),
            ],
            verification: vec!["按进程过滤时间线，观察断开是否集中于单一进程".into()],
        });
    }

    // ---- 接口 ----
    let iface_down = ctx
        .timeline
        .iter()
        .filter(|e| e.kind == "interface_changed" && e.summary.contains("→ down"))
        .count();
    if iface_down > 0 {
        findings.push(DiagnosticFinding {
            rule_id: "iface.link_down".into(),
            title: "网卡断开".into(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "interface_changed", 3),
            possible_causes: vec![
                "物理链路断开（拔线/信号弱）".into(),
                "网卡驱动或电源管理".into(),
            ],
            verification: vec!["检查线缆/Wi-Fi 信号；查看 Overview 网卡状态".into()],
        });
    }
    if ctx.count_kind("ip_changed") > 0 {
        findings.push(DiagnosticFinding {
            rule_id: "iface.ip_change".into(),
            title: "IP 地址变化".into(),
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "ip_changed", 3),
            possible_causes: vec![
                "DHCP 续租/重连".into(),
                "网络切换（Wi-Fi ↔ 有线）".into(),
            ],
            verification: vec!["Overview 查看当前 IP 与网卡".into()],
        });
    }
    if ctx.count_kind("speed_dropped") > 0 {
        findings.push(DiagnosticFinding {
            rule_id: "iface.speed_drop".into(),
            title: "网卡协商速率下降".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "speed_dropped", 3),
            possible_causes: vec![
                "Wi-Fi 信号变弱".into(),
                "交换机/路由器端口协商变化".into(),
            ],
            verification: vec!["查看 Overview 网卡协商速率趋势".into()],
        });
    }
    let route_change = ctx.count_kind("route_changed");
    if route_change > 0 {
        findings.push(DiagnosticFinding {
            rule_id: "iface.gateway_change".into(),
            title: "默认网关变化".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "route_changed", 2),
            possible_causes: vec![
                "网络切换".into(),
                "VPN/代理接管默认路由或释放".into(),
            ],
            verification: vec!["Proxy Analysis 查看 VPN 接口与默认路由归属".into()],
        });
    }

    // ---- 代理 / VPN ----
    if ctx.proxy_listener_gone && !ctx.proxy_servers.is_empty() {
        findings.push(DiagnosticFinding {
            rule_id: "proxy.listener_gone".into(),
            title: "本地代理服务不可达".into(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "proxy_removed", 3),
            possible_causes: vec![
                "代理进程退出".into(),
                "代理服务端口变更".into(),
            ],
            verification: vec!["确认代理软件运行状态与端口".into()],
        });
    }
    if route_change > 0 {
        findings.push(DiagnosticFinding {
            rule_id: "proxy.route_change".into(),
            title: "VPN 路由变化".into(),
            severity: Severity::Warning,
            confidence: Confidence::Inferred,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "route_changed", 2),
            possible_causes: vec![
                "VPN 连接/断开".into(),
                "TUN 接管或释放默认路由".into(),
            ],
            verification: vec!["Proxy Analysis 查看 VPN 接口当前状态".into()],
        });
    }

    // ---- 质量 ----
    if let (Some(avg), Some(base)) = (ctx.ping_avg_ms, ctx.ping_baseline_ms) {
        if base > 0.0 && avg > base * 2.5 && avg - base > 50.0 {
            findings.push(DiagnosticFinding {
                rule_id: "quality.latency_spike".into(),
                title: "延迟突然增加".into(),
                severity: Severity::Warning,
                confidence: Confidence::Inferred,
                detected_at: ctx.now,
                impact_processes: vec![],
                impact_domains: vec![],
                evidence: vec![EvidenceRef {
                    source: "probe:ping".into(),
                    timestamp: ctx.now,
                    description: format!("Ping 平均 {avg:.0}ms，基线 {base:.0}ms"),
                }],
                possible_causes: vec![
                    "链路拥塞".into(),
                    "路由变化/绕路".into(),
                    "VPN 隧道开销增加".into(),
                ],
                verification: vec!["Route Explorer 对比 Traceroute 路径".into()],
            });
        }
    }
    if ctx.syn_failures_recent >= 3 {
        findings.push(DiagnosticFinding {
            rule_id: "quality.timeout_rate".into(),
            title: "连接超时率升高".into(),
            severity: Severity::Warning,
            confidence: Confidence::Inferred,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "timeline:conn_closed".into(),
                timestamp: ctx.now,
                description: format!("窗口内建连失败 {} 次", ctx.syn_failures_recent),
            }],
            possible_causes: vec!["出口网络异常".into(), "目标服务故障".into()],
            verification: vec!["Benchmark 多目标对比，区分单目标还是全局".into()],
        });
    }
    // ---- 补充规则（第三轮验收补齐）----
    if ctx.count_kind("interface_changed") >= 3 {
        findings.push(DiagnosticFinding {
            rule_id: "iface.flapping".into(),
            title: "网络接口频繁切换".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "interface_changed", 4),
            possible_causes: vec![
                "Wi-Fi/有线反复切换".into(),
                "驱动或电源管理重启网卡".into(),
            ],
            verification: vec!["按时间线观察切换的时间模式".into()],
        });
    }
    if ctx.proxy_conn_failures >= 3 {
        findings.push(DiagnosticFinding {
            rule_id: "proxy.connect_failure".into(),
            title: "代理连接失败".into(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "conn_closed", 4),
            possible_causes: vec![
                "本地代理进程退出或端口变更".into(),
                "代理上游节点不可用".into(),
            ],
            verification: vec!["确认代理软件状态；切换节点重试".into()],
        });
    }
    if ctx.dns_result_changes >= 1 {
        findings.push(DiagnosticFinding {
            rule_id: "dns.result_change".into(),
            title: "DNS 解析结果变化".into(),
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "probe:dns".into(),
                timestamp: ctx.now,
                description: format!("连续解析结果不一致 {} 次", ctx.dns_result_changes),
            }],
            possible_causes: vec![
                "CDN 正常轮询".into(),
                "DNS 劫持/污染（结果异常时）".into(),
            ],
            verification: vec!["对比不同 DNS 服务器的解析结果".into()],
        });
    }
    if ctx.ping_loss_rate.is_some_and(|l| l > 0.1) {
        findings.push(DiagnosticFinding {
            rule_id: "quality.loss_increase".into(),
            title: "丢包率升高".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "probe:ping".into(),
                timestamp: ctx.now,
                description: format!("丢包率 {:.0}%", ctx.ping_loss_rate.unwrap() * 100.0),
            }],
            possible_causes: vec![
                "链路拥塞或劣化".into(),
                "目标限流".into(),
            ],
            verification: vec!["多目标 Ping 区分单目标还是全局".into()],
        });
    }
    if ctx.icmp_unreachable >= 3 {
        findings.push(DiagnosticFinding {
            rule_id: "tcp.port_unreachable".into(),
            title: "目标端口不可达".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "capture:icmp".into(),
                timestamp: ctx.now,
                description: format!("抓包观测 ICMP 不可达 {} 次", ctx.icmp_unreachable),
            }],
            possible_causes: vec![
                "目标端口未开放".into(),
                "防火墙拒绝".into(),
            ],
            verification: vec!["Packet Inspector 过滤 ICMP type 3 查看目标".into()],
        });
    }
    if ctx.count_kind("benchmark_anomaly") > 0 {
        findings.push(DiagnosticFinding {
            rule_id: "quality.performance_anomaly".into(),
            title: "下载性能异常".into(),
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: evidence(ctx, "benchmark_anomaly", 3),
            possible_causes: vec![
                "出口节点降速".into(),
                "目标限速".into(),
            ],
            verification: vec!["Benchmark 对比不同出口/节点".into()],
        });
    }
    if ctx.dns_probe_failures >= 3 {
        findings.push(DiagnosticFinding {
            rule_id: "dns.server_unreachable".into(),
            title: "DNS 服务器不可达".into(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![EvidenceRef {
                source: "probe:dns".into(),
                timestamp: ctx.now,
                description: format!("连续 {} 次探测失败", ctx.dns_probe_failures),
            }],
            possible_causes: vec![
                "DNS 服务器宕机".into(),
                "出口对该服务器拦截".into(),
            ],
            verification: vec!["换用其他公共 DNS 验证".into()],
        });
    }
    if ctx.retrans_recent >= 20 && ctx.syn_failures_recent >= 3 {
        findings.push(DiagnosticFinding {
            rule_id: "quality.degradation".into(),
            title: "整体链路质量下降".into(),
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            detected_at: ctx.now,
            impact_processes: vec![],
            impact_domains: vec![],
            evidence: vec![
                EvidenceRef {
                    source: "capture:retransmit".into(),
                    timestamp: ctx.now,
                    description: format!("重传 {} 次", ctx.retrans_recent),
                },
                EvidenceRef {
                    source: "timeline:conn_closed".into(),
                    timestamp: ctx.now,
                    description: format!("建连失败 {} 次", ctx.syn_failures_recent),
                },
            ],
            possible_causes: vec![
                "物理链路劣化".into(),
                "出口（代理/VPN）拥塞".into(),
            ],
            verification: vec!["Benchmark 对多目标测速定位瓶颈范围".into()],
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with(events: Vec<TimelineEvent>) -> DiagnosticContext<'static> {
        let leaked: &'static Vec<TimelineEvent> = Box::leak(Box::new(events));
        DiagnosticContext {
            now: Utc::now(),
            timeline: leaked,
            syn_failures_recent: 0,
            retrans_recent: 0,
            rst_recent: 0,
            handshake_p95_ms: None,
            proxy_servers: Vec::new(),
            proxy_listener_gone: false,
            proxy_conn_failures: 0,
            ping_loss_rate: None,
            dns_result_changes: 0,
            icmp_unreachable: 0,
            dns_probe_failures: 0,
            dns_avg_ms: None,
            dns_baseline_ms: None,
            ping_avg_ms: None,
            ping_baseline_ms: None,
        }
    }

    fn ev(kind: &str, summary: &str) -> TimelineEvent {
        TimelineEvent {
            timestamp: Utc::now(),
            source: "test".into(),
            kind: kind.into(),
            summary: summary.into(),
            payload: json!({}),
        }
    }

    #[test]
    fn iface_down_rule_fires_with_evidence() {
        let ctx = ctx_with(vec![ev("interface_changed", "网卡 以太网 状态: up → down")]);
        let findings = evaluate(&ctx);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "iface.link_down")
            .expect("应触发网卡断开规则");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(!f.evidence.is_empty(), "结论必须带证据");
        assert!(f.evidence[0].description.contains("up → down"));
    }

    #[test]
    fn single_metric_does_not_claim_certainty() {
        // 仅 1 次 SYN 失败 → 推断级，多可能原因 + 验证建议
        let ctx = ctx_with(vec![ev("conn_closed", "chrome.exe 关闭 1.2.3.4:443")]);
        let mut c = ctx_with(vec![]);
        c.timeline = ctx.timeline;
        c.syn_failures_recent = 1;
        let findings = evaluate(&c);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "tcp.syn_failure")
            .unwrap();
        assert_eq!(f.confidence, Confidence::Inferred, "单指标不得判确定性根因");
        assert!(f.possible_causes.len() >= 2, "必须列出多个可能原因");
        assert!(!f.verification.is_empty(), "必须给出后续验证建议");
    }

    #[test]
    fn retransmit_needs_capture_volume() {
        let mut c = ctx_with(vec![]);
        c.retrans_recent = 5;
        assert!(evaluate(&c).iter().all(|f| f.rule_id != "tcp.retransmit_increase"));
        c.retrans_recent = 25;
        assert!(evaluate(&c).iter().any(|f| f.rule_id == "tcp.retransmit_increase"));
    }

    #[test]
    fn dns_latency_needs_baseline_and_absolute() {
        let mut c = ctx_with(vec![]);
        c.dns_avg_ms = Some(400.0);
        c.dns_baseline_ms = Some(20.0);
        assert!(evaluate(&c).iter().any(|f| f.rule_id == "dns.latency_anomaly"));
        c.dns_avg_ms = Some(30.0);
        c.dns_baseline_ms = Some(5.0);
        assert!(evaluate(&c).iter().all(|f| f.rule_id != "dns.latency_anomaly"));
    }

    #[test]
    fn proxy_listener_gone_requires_prior_proxy() {
        let mut c = ctx_with(vec![ev("proxy_removed", "本地代理服务消失")]);
        c.proxy_listener_gone = true;
        c.proxy_servers = vec!["127.0.0.1:7890".into()];
        assert!(evaluate(&c).iter().any(|f| f.rule_id == "proxy.listener_gone"));
        c.proxy_servers = vec![];
        assert!(evaluate(&c).iter().all(|f| f.rule_id != "proxy.listener_gone"));
    }

    #[test]
    fn disabled_rules_skipped() {
        let ctx = ctx_with(vec![ev("interface_changed", "网卡 以太网 状态: up → down")]);
        let findings = run_rules(&ctx, &["iface.link_down".to_string()]);
        assert!(findings.iter().all(|f| f.rule_id != "iface.link_down"));
    }

    #[test]
    fn proxy_connect_failure_rule() {
        let ctx = ctx_with(vec![]);
        let mut c = ctx_with(vec![]);
        c.timeline = ctx.timeline;
        c.proxy_conn_failures = 3;
        let findings = evaluate(&c);
        let f = findings.iter().find(|f| f.rule_id == "proxy.connect_failure").expect("应触发代理连接失败");
        assert_eq!(f.severity, Severity::Critical);
        // 少于 3 次不触发
        c.proxy_conn_failures = 1;
        assert!(evaluate(&c).iter().all(|f| f.rule_id != "proxy.connect_failure"));
    }

    #[test]
    fn iface_flapping_rule() {
        let ctx = ctx_with(vec![
            ev("interface_changed", "网卡 up → down"),
            ev("interface_changed", "网卡 down → up"),
            ev("interface_changed", "网卡 up → down"),
        ]);
        assert!(evaluate(&ctx).iter().any(|f| f.rule_id == "iface.flapping"));
        // 2 次不触发
        let ctx2 = ctx_with(vec![
            ev("interface_changed", "网卡 up → down"),
            ev("interface_changed", "网卡 down → up"),
        ]);
        assert!(evaluate(&ctx2).iter().all(|f| f.rule_id != "iface.flapping"));
    }

    #[test]
    fn loss_rate_rule_needs_probe_data() {
        let mut c = ctx_with(vec![]);
        c.ping_loss_rate = Some(0.5);
        assert!(evaluate(&c).iter().any(|f| f.rule_id == "quality.loss_increase"));
        c.ping_loss_rate = Some(0.02);
        assert!(evaluate(&c).iter().all(|f| f.rule_id != "quality.loss_increase"));
        // 无探测数据（None）不触发 —— 不伪造
        c.ping_loss_rate = None;
        assert!(evaluate(&c).iter().all(|f| f.rule_id != "quality.loss_increase"));
    }

    #[test]
    fn rule_registry_has_all_categories_and_16_rules() {
        let reg = rule_registry();
        let cats: std::collections::HashSet<&str> =
            reg.iter().map(|r| r.category.as_str()).collect();
        for c in ["DNS", "TCP", "接口", "代理/VPN", "质量"] {
            assert!(cats.contains(c), "规则注册表应含类别 {c}");
        }
        assert_eq!(reg.len(), 23, "规则总数（16 基础 + 7 验收补齐）");
    }

    #[test]
    fn combined_evidence_raises_severity_confidence() {
        let mut c = ctx_with(vec![]);
        c.retrans_recent = 30;
        c.syn_failures_recent = 5;
        let findings = evaluate(&c);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "quality.degradation")
            .expect("重传+建连失败同时升高应触发整体劣化规则");
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.evidence.len() >= 2, "多证据汇聚");
    }
}
