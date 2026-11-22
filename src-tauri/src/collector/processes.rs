//! 进程快照采集（Toolhelp32）：进程启动 / 退出差分检测（第三轮会话录制内容）。

use std::collections::HashMap;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};

/// 当前进程表（pid → 进程名）。真实系统调用。
pub fn snapshot_processes() -> Result<HashMap<u32, String>, String> {
    unsafe {
        let handle: HANDLE =
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| format!("快照失败: {e}"))?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut out = HashMap::new();
        if Process32FirstW(handle, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                );
                if !name.is_empty() {
                    out.insert(entry.th32ProcessID, name);
                }
                if Process32NextW(handle, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(handle);
        Ok(out)
    }
}

/// 进程差分结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDiff {
    pub started: Vec<(u32, String)>,
    pub exited: Vec<(u32, String)>,
}

/// 对比两次进程快照（纯函数）。
pub fn diff_processes(
    prev: &HashMap<u32, String>,
    current: &HashMap<u32, String>,
) -> ProcessDiff {
    let started = current
        .iter()
        .filter(|(pid, name)| {
            prev.get(pid).map(|p| p != *name).unwrap_or(true)
        })
        .map(|(pid, name)| (*pid, name.clone()))
        .collect();
    let exited = prev
        .iter()
        .filter(|(pid, name)| current.get(pid).map(|c| c != *name).unwrap_or(true))
        .map(|(pid, name)| (*pid, name.clone()))
        .collect();
    ProcessDiff { started, exited }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_detects_start_and_exit() {
        let mut prev = HashMap::new();
        prev.insert(100, "a.exe".to_string());
        prev.insert(200, "b.exe".to_string());

        let mut current = HashMap::new();
        current.insert(200, "b.exe".to_string());
        current.insert(300, "c.exe".to_string());
        // pid 100 消失（退出），pid 300 新增（启动）

        let diff = diff_processes(&prev, &current);
        assert_eq!(diff.started, vec![(300, "c.exe".to_string())]);
        assert_eq!(diff.exited, vec![(100, "a.exe".to_string())]);
    }

    #[test]
    fn pid_reuse_counts_as_both() {
        // 同 PID 换名：视为旧进程退出 + 新进程启动（不合并）
        let mut prev = HashMap::new();
        prev.insert(100, "old.exe".to_string());
        let mut current = HashMap::new();
        current.insert(100, "new.exe".to_string());
        let diff = diff_processes(&prev, &current);
        assert_eq!(diff.started.len(), 1);
        assert_eq!(diff.exited.len(), 1);
    }

    /// 真实系统集成测试：本机进程表非空，且包含自身。
    #[test]
    fn real_process_snapshot() {
        let procs = snapshot_processes().expect("进程快照应成功");
        assert!(procs.len() > 10, "系统进程应远多于 10");
        let self_name = procs.get(&std::process::id()).cloned();
        assert!(
            self_name.as_deref().map(|n| n.contains("netscope")).unwrap_or(false),
            "应能在进程表中找到自身: {:?}",
            self_name
        );
    }
}
