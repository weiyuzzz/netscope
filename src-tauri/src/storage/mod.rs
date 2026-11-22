//! SQLite 持久化层。
//!
//! - `database`    连接管理、批量写入、版本迁移（user_version）、数据保留策略
//! - `repository`  各实体的查询/写入仓库
//!
//! 约束：默认只保存网络元数据，不保存完整数据包内容；带时间索引与保留策略。

pub mod database;
pub mod history_repository;
pub mod repository;

use thiserror::Error;

/// 存储层错误。
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite 错误: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("序列化错误: {0}")]
    Serde(#[from] serde_json::Error),
}
