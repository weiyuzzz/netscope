import { Search, Settings } from 'lucide-react'
import { useAppStore } from '../../stores/appStore'
import { useClock } from '../../hooks/useClock'
import { StatusBadge } from './StatusBadge'

/** 顶部栏：软件名 / 采集状态 / 当前监控时间 / 搜索入口 / 设置入口。 */
export function TopBar() {
  const collectorStatus = useAppStore((s) => s.collectorStatus)
  const setCurrentPage = useAppStore((s) => s.setCurrentPage)
  const now = useClock()

  return (
    <header className="flex h-12 shrink-0 items-center gap-4 border-b border-ns-border bg-ns-panel px-4">
      <span className="text-sm font-semibold">NetScope</span>
      <StatusBadge status={collectorStatus} />
      <span className="text-xs tabular-nums text-ns-muted">
        {now.toLocaleTimeString('zh-CN', { hour12: false })}
      </span>
      <div className="ml-auto flex items-center gap-3">
        <div className="flex h-7 w-56 items-center gap-2 rounded-md border border-ns-border bg-ns-bg px-2 text-xs text-ns-muted">
          <Search className="h-3.5 w-3.5" />
          <span>搜索（Phase 3 启用）</span>
        </div>
        <button
          className="rounded-md p-1.5 text-ns-muted hover:bg-ns-panel-hover hover:text-ns-text"
          title="Settings"
          onClick={() => setCurrentPage('settings')}
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}
