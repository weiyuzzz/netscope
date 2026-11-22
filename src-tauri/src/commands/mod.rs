//! Tauri 命令层：前后端通信的唯一入口。
//!
//! 只做参数校验与转发，不含业务逻辑；业务逻辑位于各功能模块。

pub mod capture_commands;
pub mod diagnostic_commands;
pub mod history_commands;
pub mod monitor_commands;
pub mod network_commands;
pub mod settings_commands;
