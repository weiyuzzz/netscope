//! 进程信息模型（PID → 进程名/路径关联，Phase 1 由采集层填充）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 进程基本信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    /// 可执行文件完整路径（可能因权限不足无法获取）。
    pub exe_path: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_info_serializes_camel_case() {
        let now = Utc::now();
        let p = ProcessInfo {
            pid: 4242,
            name: "chrome.exe".into(),
            exe_path: Some(
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".into(),
            ),
            first_seen: now,
            last_seen: now,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"exePath\""));
        assert!(json.contains("\"firstSeen\""));
        let back: ProcessInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 4242);
        assert_eq!(back.name, "chrome.exe");
    }
}
