//! 统一数据模型：采集、关联、拓扑、存储与前端通信共用的数据契约。
//!
//! 约定：
//! - 所有时间戳统一使用 UTC（`chrono::DateTime<Utc>`），序列化为 RFC3339；
//! - 所有结构体经 serde 序列化后供前端消费，字段命名遵循 camelCase；
//! - 本模块不得依赖 Tauri 或任何 UI 层。

pub mod capture;
pub mod connection;
pub mod interface;
pub mod metrics;
pub mod network_event;
pub mod process;
pub mod session;
pub mod proxy;
pub mod topology;
