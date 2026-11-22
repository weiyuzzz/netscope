import {
  Activity,
  Network,
  List,
  Stethoscope,
  Settings,
  CircleDot,
  ShieldCheck,
  Radio,
  Gauge,
  Route,
  Clapperboard,
  History as HistoryIcon,
  Sparkles,
} from 'lucide-react'
import { useAppStore, type PageId } from '../../stores/appStore'

interface NavItem {
  id: PageId | null // null = 预留入口，暂不可用
  label: string
  icon: typeof Activity
  enabled: boolean
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview', label: 'Overview', icon: Activity, enabled: true },
  { id: 'network-map', label: 'Network Map', icon: Network, enabled: true },
  { id: 'connections', label: 'Connections', icon: List, enabled: true },
  { id: 'proxy-analysis', label: 'Proxy Analysis', icon: ShieldCheck, enabled: true },
  { id: 'packet-inspector', label: 'Packet Inspector', icon: Radio, enabled: true },
  { id: 'tcp-analytics', label: 'TCP Analytics', icon: Gauge, enabled: true },
  { id: 'route-explorer', label: 'Route Explorer', icon: Route, enabled: true },
  { id: 'session-recorder', label: 'Session Recorder', icon: Clapperboard, enabled: true },
  { id: 'history', label: 'History', icon: HistoryIcon, enabled: true },
  { id: 'ai-assistant', label: 'AI Assistant', icon: Sparkles, enabled: true },
  { id: 'diagnostics', label: 'Diagnostics', icon: Stethoscope, enabled: true },
  { id: 'benchmark', label: 'Benchmark', icon: Gauge, enabled: true },
  { id: 'settings', label: 'Settings', icon: Settings, enabled: true },
]

/** 左侧导航栏。 */
export function Sidebar() {
  const currentPage = useAppStore((s) => s.currentPage)
  const setCurrentPage = useAppStore((s) => s.setCurrentPage)

  return (
    <nav className="flex h-full w-52 shrink-0 flex-col border-r border-ns-border bg-ns-panel">
      <div className="flex items-center gap-2 px-4 py-4">
        <CircleDot className="h-6 w-6 text-ns-accent" />
        <span className="text-base font-semibold tracking-wide">NetScope</span>
      </div>
      <div className="flex-1 space-y-1 px-2 py-2">
        {NAV_ITEMS.map(({ id, label, icon: Icon, enabled }) => {
          const active = enabled && id !== null && id === currentPage
          const className = [
            'flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm',
            active
              ? 'bg-ns-panel-hover text-ns-accent'
              : enabled
                ? 'text-ns-text hover:bg-ns-panel-hover'
                : 'cursor-not-allowed text-ns-muted',
          ].join(' ')
          return (
            <button
              key={label}
              className={className}
              disabled={!enabled}
              onClick={() => id !== null && setCurrentPage(id)}
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span>{label}</span>
              {!enabled && (
                <span className="ml-auto text-[10px] text-ns-muted">预留</span>
              )}
            </button>
          )
        })}
      </div>
    </nav>
  )
}
