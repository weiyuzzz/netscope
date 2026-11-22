import { useState } from 'react'
import { RotateCcw, Search } from 'lucide-react'
import { TopologyCanvas, type TopologyFilters } from '../components/topology/TopologyCanvas'
import { DetailPanel } from '../components/panels/DetailPanel'

const DEFAULT_FILTERS: TopologyFilters = {
  search: '',
  showProcesses: true,
  showEndpoints: true,
  showProxies: true,
  showVpn: true,
  showHops: true,
  protocol: 'all',
  lowConfidenceOnly: false,
  hideInactive: false,
}

function Chip({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
        active
          ? 'border-ns-accent/60 bg-ns-accent/10 text-ns-accent'
          : 'border-ns-border text-ns-muted hover:text-ns-text'
      }`}
    >
      {children}
    </button>
  )
}

/** Network Map：交互式网络拓扑（过滤 + 搜索 + 详情联动）。 */
export function NetworkMapPage({ initialSearch = '' }: { initialSearch?: string }) {
  const [filters, setFilters] = useState<TopologyFilters>({ ...DEFAULT_FILTERS, search: initialSearch })
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)

  const toggle = (key: keyof TopologyFilters) =>
    setFilters((f) => ({ ...f, [key]: !f[key] }))

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-ns-border px-3 py-2">
        <div className="flex h-7 w-56 items-center gap-2 rounded-md border border-ns-border bg-ns-panel px-2">
          <Search className="h-3.5 w-3.5 text-ns-muted" />
          <input
            value={filters.search}
            onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
            placeholder="搜索进程 / 域名 / IP"
            className="w-full bg-transparent text-xs text-ns-text outline-none placeholder:text-ns-muted"
          />
        </div>
        <Chip active={filters.showProcesses} onClick={() => toggle('showProcesses')}>进程</Chip>
        <Chip active={filters.showEndpoints} onClick={() => toggle('showEndpoints')}>域名/IP</Chip>
        <Chip active={filters.showProxies} onClick={() => toggle('showProxies')}>代理</Chip>
        <Chip active={filters.showVpn} onClick={() => toggle('showVpn')}>VPN/TUN</Chip>
        <Chip active={filters.showHops} onClick={() => toggle('showHops')}>路由跳点</Chip>
        <span className="mx-1 h-4 w-px bg-ns-border" />
        <Chip
          active={filters.protocol === 'tcp'}
          onClick={() => setFilters((f) => ({ ...f, protocol: f.protocol === 'tcp' ? 'all' : 'tcp' }))}
        >
          仅 TCP
        </Chip>
        <Chip
          active={filters.protocol === 'udp'}
          onClick={() => setFilters((f) => ({ ...f, protocol: f.protocol === 'udp' ? 'all' : 'udp' }))}
        >
          仅 UDP
        </Chip>
        <Chip active={filters.lowConfidenceOnly} onClick={() => toggle('lowConfidenceOnly')}>
          仅低置信度
        </Chip>
        <Chip active={filters.hideInactive} onClick={() => toggle('hideInactive')}>
          隐藏历史
        </Chip>
        <button
          className="ml-auto inline-flex items-center gap-1 rounded-md border border-ns-border px-2 py-1 text-xs text-ns-muted hover:text-ns-text"
          onClick={() => setFilters({ ...DEFAULT_FILTERS, search: '' })}
        >
          <RotateCcw className="h-3 w-3" /> 重置
        </button>
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          <TopologyCanvas
            filters={filters}
            onSelect={(id) => {
              setSelectedNodeId(id)
              setSelectedEdgeId(null)
            }}
            onEdgeSelect={(id) => {
              setSelectedEdgeId(id)
              setSelectedNodeId(null)
            }}
          />
        </div>
        <DetailPanel selectedNodeId={selectedNodeId} selectedEdgeId={selectedEdgeId} />
      </div>
    </div>
  )
}
