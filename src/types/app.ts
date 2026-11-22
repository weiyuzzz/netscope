/** 与 Rust 后端 `commands::network_commands::AppInfo` 对应的通信契约。 */
export interface AppInfo {
  name: string
  version: string
  os: string
  arch: string
  hostname: string
  /** 应用启动时间（UTC，RFC3339）。 */
  startedAt: string
}

/** 网络采集器运行状态（Phase 1 起由后端事件驱动更新）。 */
export type CollectorStatus = 'not-initialized' | 'running' | 'error'
