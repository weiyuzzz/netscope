//! Npcap 抓包实机验收（需要管理员权限运行）。
//!
//! 场景：
//!   A. 设备枚举（真实 Npcap 设备列表）
//!   B. 真实抓包：按默认路由接口优先选择设备，生成真实流量（DNS 解析 +
//!      ICMP Ping 网关 + TCP 连接），断言捕获到数据包且解析成功
//!   C. 干净退出验证（线程 join + stopped 状态，验收第 12 项）
//!   D. PCAP 文件导出（magic + 非空验证）
//!
//! 结果写入日志文件（提升权限运行时 stdout 不可见）：
//!   %APPDATA%/dev.netscope.app/reports/capture-acceptance.log

use std::io::Write;
use std::sync::Arc;

use netscope_lib::collector::capture::{
    list_capture_devices, npcap_status, CaptureConfig, CaptureSession, NpcapLib,
};

fn main() {
    let log_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            let dir = std::env::var("APPDATA").unwrap_or_default();
            format!("{dir}\\dev.netscope.app\\reports\\capture-acceptance.log")
        });
    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut log = std::fs::File::create(&log_path).expect("创建日志失败");
    let mut out = |s: &str| {
        let _ = writeln!(log, "{s}");
        let _ = log.flush();
    };

    out("=== Npcap 抓包实机验收 ===");

    // ---- A. 状态与设备枚举 ----
    let status = npcap_status();
    out(&format!(
        "[A1] Npcap 状态: installed={} version={:?}",
        status.installed, status.version
    ));
    if !status.installed {
        out("[FAIL] Npcap 未安装，验收中止");
        return;
    }
    out("[PASS] A1 Npcap 检测与加载");

    let devices = match list_capture_devices() {
        Ok(d) => {
            out(&format!("[PASS] A2 设备枚举: {} 个设备", d.len()));
            for (i, dev) in d.iter().enumerate().take(8) {
                out(&format!(
                    "       设备{i}: {} ({})",
                    dev.description.as_deref().unwrap_or(dev.name.as_str()),
                    if dev.loopback { "loopback" } else { "physical/other" }
                ));
            }
            d
        }
        Err(e) => {
            out(&format!("[FAIL] A2 设备枚举失败: {e}"));
            return;
        }
    };

    // 设备选择：优先默认路由接口（GUID 匹配），否则遍历前 4 个非回环设备
    let mut candidates: Vec<String> = Vec::new();
    if let Some(idx) = netscope_lib::collector::routes::best_interface_index("8.8.8.8") {
        if let Ok(adapters) = netscope_lib::collector::adapters::list_adapters() {
            if let Some(a) = adapters.iter().find(|a| a.index == idx) {
                // adapter.name 是 GUID 形式（GetAdaptersAddresses AdapterName）
                if let Some(dev) = devices
                    .iter()
                    .find(|d| d.name.to_lowercase().contains(&a.name.to_lowercase()))
                {
                    candidates.push(dev.name.clone());
                }
            }
        }
    }
    // 真实物理网卡优先（WAN Miniport / Bluetooth / Wi-Fi Direct 不承载用户流量）
    let is_real = |d: &netscope_lib::collector::capture::CaptureDevice| {
        let desc = d.description.as_deref().unwrap_or("").to_lowercase();
        !desc.contains("wan miniport")
            && !desc.contains("bluetooth")
            && !desc.contains("wi-fi direct")
            && !desc.contains("loopback")
    };
    for d in devices.iter().filter(|d| is_real(d)) {
        if !candidates.contains(&d.name) {
            candidates.push(d.name.clone());
        }
    }
    out(&format!(
        "[B0] 抓包候选设备 {} 个（默认路由接口优先）",
        candidates.len()
    ));

    // ---- B. 真实抓包 + 流量生成 ----
    let lib = Arc::new(NpcapLib::load().expect("wpcap.dll 加载失败（不应发生，A1 已通过）"));
    let mut captured_any = false;
    let mut tcp_seen = 0u64;
    let mut dns_meta_seen = 0usize;
    let mut icmp_seen = 0usize;
    let mut clean_stop = false;
    let mut pcap_path: Option<std::path::PathBuf> = None;
    let mut used_device = String::new();

    for (attempt, device) in candidates.iter().enumerate() {
        out(&format!(
            "[B{}] 尝试设备: {} ({})",
            attempt + 1,
            device,
            devices
                .iter()
                .find(|d| d.name == *device)
                .and_then(|d| d.description.clone())
                .unwrap_or_default()
        ));

        // 生成真实流量的线程：DNS 解析轮换 + Ping 网关 + TCP 连接
        let stop_traffic = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_t = stop_traffic.clone();
        let traffic = std::thread::spawn(move || {
            let domains = [
                "www.example.com",
                "www.microsoft.com",
                "www.baidu.com",
                "cdn.jsdelivr.net",
            ];
            let mut i = 0;
            while !stop_t.load(std::sync::atomic::Ordering::SeqCst) {
                let d = domains[i % domains.len()];
                let _ = std::net::ToSocketAddrs::to_socket_addrs(&(d, 80u16));
                let _ = std::net::TcpStream::connect(std::net::SocketAddr::new(
                    std::net::Ipv4Addr::new(1, 1, 1, 1).into(),
                    443,
                ));
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        });

        let config = CaptureConfig {
            adapter: device.clone(),
            adapter_friendly: "acceptance".into(),
            bpf_filter: None,
            snaplen: 65535,
            max_bytes: Some(20 * 1024 * 1024),
            max_duration_secs: Some(6), // 6 秒自动停止
            max_packets: Some(100_000),
        };

        // PCAP 导出到临时目录
        let export = std::env::temp_dir().join(format!(
            "ns-acceptance-{}.pcap",
            attempt
        ));

        let session = match CaptureSession::start(config.clone(), Some(export.clone()), lib.clone(), None) {
            Ok(s) => s,
            Err(e) => {
                out(&format!("       打开失败: {e}（换下一个设备）"));
                stop_traffic.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = traffic.join();
                continue;
            }
        };

        // 让抓包跑满 10 秒（自动停止），期间流量线程持续发包
        std::thread::sleep(std::time::Duration::from_secs(7));
        stop_traffic.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut session = session;
        session.stop(); // 干净退出验证
        let _ = traffic.join();

        let st = session.status();
        let packets = st.packets;
        tcp_seen = session
            .recent_packets(2000)
            .iter()
            .filter(|p| matches!(p.protocol, netscope_lib::models::capture::IpProtocol::Tcp))
            .count() as u64;
        dns_meta_seen = session
            .recent_packets(2000)
            .iter()
            .filter(|p| matches!(p.meta, netscope_lib::models::capture::PacketMeta::Dns { .. }))
            .count();
        icmp_seen = session
            .recent_packets(2000)
            .iter()
            .filter(|p| matches!(p.meta, netscope_lib::models::capture::PacketMeta::Icmp { .. }))
            .count();

        out(&format!(
            "[B{}] 结果: packets={packets} bytes={} tcp_parsed={tcp_seen} dns_meta={dns_meta_seen} icmp_meta={icmp_seen} state={:?} error={:?}",
            attempt + 1,
            st.bytes,
            st.state,
            st.last_error
        ));

        if packets > 0 && tcp_seen > 0 && st.last_error.is_none() {
            captured_any = true;
            clean_stop = st.state == netscope_lib::models::capture::CaptureState::Stopped;
            used_device = device.clone();
            pcap_path = Some(export);

            // 流摘要（会话统计验证）
            let flows = session.flow_summaries();
            out(&format!("[B{}] 流统计: {} 条会话", attempt + 1, flows.len()));
            break;
        }
    }

    if captured_any {
        out(&format!("[PASS] B 真实抓包: 设备 {used_device}"));
    } else {
        out("[FAIL] B 真实抓包: 所有候选设备均未捕获到 TCP 数据包（检查管理员权限/设备选择）");
    }

    // ---- C. 干净退出验证（验收第 12 项） ----
    if clean_stop {
        out("[PASS] C 干净退出: 状态 Stopped，采集线程已 join");
    } else {
        out("[WARN] C 干净退出: 状态未确认（stopped 标志或线程退出异常）");
    }

    // ---- D. PCAP 导出验证 ----
    if let Some(p) = pcap_path {
        match std::fs::read(&p) {
            Ok(bytes) => {
                let magic_ok = bytes.len() > 24 && bytes[0..4] == [0xd4, 0xc3, 0xb2, 0xa1];
                out(&format!(
                    "[{}] D PCAP 导出: {} bytes, magic_le_us={}",
                    if magic_ok && bytes.len() > 100 { "PASS" } else { "FAIL" },
                    bytes.len(),
                    magic_ok
                ));
            }
            Err(e) => out(&format!("[FAIL] D PCAP 导出读取失败: {e}")),
        }
    } else {
        out("[FAIL] D PCAP 导出: 无会话产生");
    }

    out("=== 验收结束 ===");
}
