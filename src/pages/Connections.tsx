import { useMemo, useState } from 'react'
import { ArrowUpDown, Search } from 'lucide-react'
import { useConnectionsStore } from '../stores/liveStores'
import { useAppStore } from '../stores/appStore'
import { formatTime, stateLabel } from '../utils/format'
import type { Connection } from '../types/network'

type SortKey = 'process' | 'pid' | 'protocol' | 'remote' | 'state' | 'lastSeen'

function sortValue(c: Connection, key: SortKey): string | number {
  switch (key) {
    case 'process':
      return c.processName ?? ''
    case 'pid':
      return c.pid
    case 'protocol':
      return c.protocol
    case 'remote':
      return c.remote ? `${c.remote.ip}:${c.remote.port}` : ''
    case 'state':
      return c.state
    case 'lastSeen':
      return c.lastSeen
  }
}

/** Connections：实时连接表（搜索 / 过滤 / 排序 / 跳转拓扑）。 */
export function ConnectionsPage() {
  const connections = useConnectionsStore((s) => s.connections)
  const setCurrentPage = useAppStore((s) => s.setCurrentPage)
  const setFocus = useAppStore((s) => s.setFocusFilter)

  const [search, setSearch] = useState('')
  const [protocolFilter, setProtocolFilter] = useState<'all' | 'tcp' | 'udp'>('all')
  const [hideListen, setHideListen] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('lastSeen')
  const [asc, setAsc] = useState(false)

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase()
    let list = Object.values(connections)
    if (q) {
      list = list.filter(
        (c) =>
          (c.processName ?? '').toLowerCase().includes(q) ||
          c.local.ip.includes(q) ||
          (c.remote?.ip ?? '').includes(q) ||
          String(c.pid).includes(q),
      )
    }
    if (protocolFilter !== 'all') list = list.filter((c) => c.protocol === protocolFilter)
    if (hideListen) list = list.filter((c) => c.state !== 'listen')
    return [...list].sort((a, b) => {
      const va = sortValue(a, sortKey)
      const vb = sortValue(b, sortKey)
      const cmp = typeof va === 'number' && typeof vb === 'number'
        ? va - vb
        : String(va).localeCompare(String(vb))
      return asc ? cmp : -cmp
    })
  }, [connections, search, protocolFilter, hideListen, sortKey, asc])

  const header = (key: SortKey, label: string, className = '') => (
    <th
      className={`cursor-pointer select-none whitespace-nowrap px-2.5 py-2 font-medium hover:text-ns-accent ${className}`}
      onClick={() => {
        if (sortKey === key) setAsc(!asc)
        else {
          setSortKey(key)
          setAsc(true)
        }
      }}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        <ArrowUpDown className={`h-3 w-3 ${sortKey === key ? 'text-ns-accent' : 'opacity-40'}`} />
      </span>
    </th>
  )

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-ns-border px-3 py-2">
        <div className="flex h-7 w-56 items-center gap-2 rounded-md border border-ns-border bg-ns-panel px-2">
          <Search className="h-3.5 w-3.5 text-ns-muted" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索进程 / IP / PID"
            className="w-full bg-transparent text-xs text-ns-text outline-none placeholder:text-ns-muted"
          />
        </div>
        {(['all', 'tcp', 'udp'] as const).map((p) => (
          <button
            key={p}
            onClick={() => setProtocolFilter(p)}
            className={`rounded-full border px-2.5 py-0.5 text-xs ${
              protocolFilter === p
                ? 'border-ns-accent/60 bg-ns-accent/10 text-ns-accent'
                : 'border-ns-border text-ns-muted hover:text-ns-text'
            }`}
          >
            {p === 'all' ? '全部协议' : p.toUpperCase()}
          </button>
        ))}
        <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-ns-muted">
          <input type="checkbox" checked={hideListen} onChange={(e) => setHideListen(e.target.checked)} />
          隐藏监听
        </label>
        <span className="ml-auto text-xs text-ns-muted">共 {rows.length} 条</span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="sticky top-0 z-10 bg-ns-panel text-ns-muted">
            <tr>
              {header('process', '进程')}
              {header('pid', 'PID')}
              {header('protocol', '协议')}
              <th className="px-2.5 py-2 font-medium">本地地址</th>
              {header('remote', '远端地址')}
              {header('state', '状态')}
              <th className="px-2.5 py-2 font-medium">网卡</th>
              <th className="px-2.5 py-2 font-medium">首见</th>
              {header('lastSeen', '最近')}
              <th className="px-2.5 py-2 font-medium">拓扑</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr
                key={c.id}
                className="border-b border-ns-border/60 hover:bg-ns-panel-hover"
              >
                <td className="max-w-[180px] truncate px-2.5 py-1.5 text-ns-text">
                  {c.processName ?? <span className="text-ns-muted">未知 (PID {c.pid})</span>}
                </td>
                <td className="px-2.5 py-1.5 font-mono text-ns-muted">{c.pid}</td>
                <td className="px-2.5 py-1.5">
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] ${
                      c.protocol === 'tcp'
                        ? 'bg-ns-blue/15 text-ns-blue'
                        : 'bg-ns-purple/15 text-ns-purple'
                    }`}
                  >
                    {c.protocol.toUpperCase()}
                  </span>
                </td>
                <td className="px-2.5 py-1.5 font-mono text-ns-muted">
                  {c.local.ip}:{c.local.port}
                </td>
                <td className="px-2.5 py-1.5 font-mono text-ns-text">
                  {c.remote ? `${c.remote.ip}:${c.remote.port}` : <span className="text-ns-muted">—</span>}
                </td>
                <td className="whitespace-nowrap px-2.5 py-1.5 text-ns-muted">{stateLabel(c.state)}</td>
                <td className="px-2.5 py-1.5 text-ns-muted">{c.interfaceIndex ?? '-'}</td>
                <td className="whitespace-nowrap px-2.5 py-1.5 text-ns-muted">{formatTime(c.firstSeen)}</td>
                <td className="whitespace-nowrap px-2.5 py-1.5 text-ns-muted">{formatTime(c.lastSeen)}</td>
                <td className="px-2.5 py-1.5">
                  {c.remote && (
                    <button
                      className="text-ns-accent hover:underline"
                      onClick={() => {
                        setFocus(c.processName ?? c.remote!.ip)
                        setCurrentPage('network-map')
                      }}
                    >
                      查看
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <div className="p-8 text-center text-sm text-ns-muted">
            暂无匹配连接（等待采集循环或调整过滤条件）
          </div>
        )}
      </div>
    </div>
  )
}
