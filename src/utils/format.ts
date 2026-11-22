/** 展示格式化工具。 */

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return '-'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = bytes / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`
}

export function formatBps(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec)) return '-'
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`
  if (bytesPerSec < 1024 * 1024 * 1024)
    return `${(bytesPerSec / 1024 / 1024).toFixed(1)} MB/s`
  return `${(bytesPerSec / 1024 / 1024 / 1024).toFixed(2)} GB/s`
}

export function formatMs(ms: number): string {
  if (!Number.isFinite(ms)) return '-'
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`
  if (ms < 1000) return `${ms.toFixed(1)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  try {
    return new Date(iso).toLocaleTimeString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  try {
    return new Date(iso).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

/** 连接状态显示名。 */
export function stateLabel(state: string): string {
  const map: Record<string, string> = {
    established: '已建立',
    listen: '监听',
    syn_sent: 'SYN 发出',
    syn_received: 'SYN 收到',
    fin_wait1: 'FIN 等待 1',
    fin_wait2: 'FIN 等待 2',
    close_wait: '等待关闭',
    closing: '关闭中',
    last_ack: '最后 ACK',
    time_wait: 'TIME_WAIT',
    delete_tcb: '删除 TCB',
    closed: '已关闭',
    endpoint: '端点 (UDP)',
  }
  return map[state] ?? state
}

/** 置信度显示。 */
export function confidenceLabel(c: string): { label: string; cls: string } {
  switch (c) {
    case 'confirmed':
      return { label: '确认', cls: 'text-ns-ok' }
    case 'inferred':
      return { label: '推断', cls: 'text-ns-warn' }
    case 'speculative':
      return { label: '疑似', cls: 'text-ns-muted' }
    default:
      return { label: c, cls: 'text-ns-muted' }
  }
}
