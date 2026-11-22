//! 诊断工具：读取应用数据库统计（真实落库验证）。
//! 运行：cargo run --example db_stats

use rusqlite::Connection;

fn main() {
    let path = std::env::var("NS_DB").unwrap_or_else(|_| {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        format!("{appdata}/dev.netscope.app/netscope.db")
    });
    let conn = match Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("打开失败 {path}: {e}");
            return;
        }
    };
    for table in [
        "connections",
        "network_events",
        "dns_events",
        "proxy_events",
        "network_quality",
        "event_timeline",
        "topology_history",
        "sessions",
        "session_events",
        "diagnostic_results",
        "benchmark_results",
        "ai_conversations",
    ] {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap_or(-1);
        println!("{table:>20}: {n}");
    }
    // 时间线样例（最近 5 条）
    let mut stmt = conn
        .prepare("SELECT timestamp, kind, summary FROM event_timeline ORDER BY timestamp DESC LIMIT 5")
        .unwrap();
    println!("--- 最近时间线 ---");
    let rows = stmt.query_map([], |r| {
        Ok(format!(
            "{} [{}] {}",
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?
        ))
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            println!("  {row}");
        }
    }
}
