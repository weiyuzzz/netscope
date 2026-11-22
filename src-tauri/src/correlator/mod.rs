//! 数据关联层（Phase 2 实现）。
//!
//! 职责：
//! - `connection_correlation` 连接生命周期管理（Opened/Updated/Closed，快照对比，
//!   维护 first_seen/last_seen，禁止不同时间连接错误合并）；
//! - `process_correlation` PID → 进程信息关联（权限不足时如实标注，不猜测）；
//! - `dns_correlation` DNS 事件 ↔ 连接/IP 时间关联（保留时间戳与关联依据，
//!   无法确认来源进程的 DNS 事件标记为未知来源）。
//!
//! 约束：本层不依赖 UI；所有关联结论必须携带依据（evidence）与置信度。

pub mod connection_correlation;
pub mod dns_correlation;
pub mod process_correlation;
