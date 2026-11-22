//! PID → 进程信息关联。
//!
//! Phase 1 中进程名由采集层（OpenProcess + QueryFullProcessImageNameW）直接解析；
//! 本模块维护"进程注册表"（pid → 首见/最近时间），用于:
//! - 进程生命周期统计（活跃进程数）；
//! - PID 复用检测（同 PID 不同 exe_path 视为新进程实例，不合并）。

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::models::process::ProcessInfo;

/// 进程注册表。
#[derive(Debug, Default)]
pub struct ProcessRegistry {
    /// (pid, name) → 信息（同 PID 换名视为新实例，不合并）。
    by_key: HashMap<(u32, String), ProcessInfo>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 观测一次进程（连接表中的 pid+进程名）。
    pub fn observe(&mut self, pid: u32, name: Option<&str>, now: DateTime<Utc>) {
        let Some(name) = name else { return };
        match self.by_key.get_mut(&(pid, name.to_string())) {
            Some(info) => info.last_seen = now,
            None => {
                self.by_key.insert(
                    (pid, name.to_string()),
                    ProcessInfo {
                        pid,
                        name: name.to_string(),
                        exe_path: None,
                        first_seen: now,
                        last_seen: now,
                    },
                );
            }
        }
    }

    /// 当前活跃进程列表（排除标记为不可得的）。
    pub fn active(&self) -> Vec<&ProcessInfo> {
        self.by_key.values().collect()
    }

    pub fn count(&self) -> usize {
        self.by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn same_pid_different_name_is_new_instance() {
        let mut reg = ProcessRegistry::new();
        let t0 = Utc::now();
        reg.observe(42, Some("a.exe"), t0);
        reg.observe(42, Some("b.exe"), t0 + chrono::Duration::seconds(1));
        assert_eq!(reg.count(), 2, "PID 复用不得合并");
    }
}
