import type { CollectorStatus } from '../../types/app'

const STATUS_META: Record<CollectorStatus, { label: string; color: string }> = {
  'not-initialized': { label: '采集层已实现 · UI 接入于 Phase 3', color: 'bg-ns-warn' },
  running: { label: '采集中', color: 'bg-ns-ok' },
  error: { label: '采集异常', color: 'bg-ns-error' },
}

/** 采集器状态指示（真实状态，Phase 1 接入后端事件）。 */
export function StatusBadge({ status }: { status: CollectorStatus }) {
  const meta = STATUS_META[status]
  return (
    <span className="inline-flex items-center gap-2 text-xs text-ns-muted">
      <span className={`h-2 w-2 rounded-full ${meta.color}`} />
      {meta.label}
    </span>
  )
}
