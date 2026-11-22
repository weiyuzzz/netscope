//! 诊断工具：对真实数据库执行 AI 提问（离线模式，验证检索→回答→持久化链路）。
//! 运行：cargo run --example ai_ask -- "最近 DNS 有什么变化？"

fn main() {
    let question = std::env::args().nth(1).unwrap_or_else(|| "最近 DNS 有什么变化？".into());
    let path = std::env::var("NS_DB").unwrap_or_else(|_| {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        format!("{appdata}/dev.netscope.app/netscope.db")
    });
    let conn = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .expect("打开应用数据库失败");

    let cfg = netscope_lib::models::session::AiConfig::default(); // 离线模式
    let conv = netscope_lib::ai::assistant::ask(&conn, &cfg, &question).expect("ask 失败");
    println!("=== Provider: {} ===", conv.provider);
    println!("{}", conv.answer);
}
