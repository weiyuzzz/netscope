//! 拓扑构建层（纯 Rust，不依赖 React / Tauri）。
//!
//! `graph` 提供 TopologyGraph 容器与 GraphDiff 增量输出；`builder` 由采集
//! 事件流驱动图增量更新（进程/代理/VPN/路由跳点），前端消费增量避免整图重建。

pub mod builder;
pub mod edge;
pub mod graph;
pub mod node;
pub mod replay;
