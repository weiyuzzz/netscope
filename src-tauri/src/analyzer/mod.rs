//! 诊断分析引擎（Phase 4 实现）。
//!
//! - `diagnostics` 诊断会话编排（超时检测、测试开始/结束时间、结果汇总）
//! - `rules`       基础故障判断规则（网关不通、DNS 失败、丢包率阈值等）
//!
//! 约束：本层不依赖任何页面组件；诊断结论必须基于真实探测数据。

pub mod benchmark;
pub mod diagnostics;
pub mod report;
pub mod rules;
