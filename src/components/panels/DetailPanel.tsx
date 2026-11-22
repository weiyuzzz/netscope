import { Globe, List, ShieldCheck } from 'lucide-react'
import { useConnectionsStore, useTopologyStore } from '../../stores/liveStores'
import { confidenceLabel, formatDateTime, formatTime, stateLabel } from '../../utils/format'
import type { Connection, TopologyEdge, TopologyNode } from '../../types/network'

const NODE_KIND_LABEL: Record<string, string> = {
  local_computer: '本机',
  network_adapter: '网卡',
  gateway: '网关',
  dns_server: 'DNS 服务器',
  process: '进程',
  domain: '域名',
  remote_ip: '远端 IP',
  proxy: '代理',
  vpn: 'VPN / 虚拟网卡',
  route_hop: '路由跳点',
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="w-24 shrink-0 text-ns-muted">{k}</span>
      <span className="min-w-0 break-all text-ns-text">{v}</span>
    </div>
  )
}

function ConnectionsList({ title, list }: { title: string; list: Connection[] }) {
  if (list.length === 0) return null
  return (
    <div className="mt-3">
      <div className="mb-1.5 text-xs font-medium text-ns-accent">{title}（{list.length}）</div>
      <div className="max-h-56 space-y-1 overflow-auto pr-1">
        {list.slice(0, 50).map((c) => (
          <div
            key={c.id}
            className="rounded border border-ns-border bg-ns-bg px-2 py-1 font-mono text-[11px] text-ns-muted"
          >
            {c.protocol.toUpperCase()} {c.local.ip}:{c.local.port}
            {' → '}
            {c.remote ? `${c.remote.ip}:${c.remote.port}` : '(无远端)'}
            {' · '}
            {stateLabel(c.state)}
          </div>
        ))}
      </div>
    </div>
  )
}

/** 右侧详情面板：节点 / 边 详情 + 关联数据（与 Network Map 联动）。 */
export function DetailPanel({
  selectedNodeId,
  selectedEdgeId,
}: {
  selectedNodeId: string | null
  selectedEdgeId: string | null
}) {
  const nodes = useTopologyStore((s) => s.nodes)
  const edges = useTopologyStore((s) => s.edges)
  const connections = useConnectionsStore((s) => s.connections)

  if (selectedNodeId) {
    const node: TopologyNode | undefined = nodes[selectedNodeId]
    if (!node) return <aside className="w-72 border-l border-ns-border bg-ns-panel p-3 text-xs text-ns-muted">节点已消失</aside>
    const data = (node.data ?? {}) as Record<string, unknown>

    let related: Connection[] = []
    if (node.kind === 'process') {
      const pid = data.pid as number | undefined
      related = Object.values(connections).filter((c) => pid != null && c.pid === pid)
    } else if (node.kind === 'remote_ip') {
      const ip = node.label
      related = Object.values(connections).filter((c) => c.remote?.ip === ip)
    } else if (node.kind === 'proxy') {
      // 代理进程自身的连接
      const pid = data.pid as number | undefined
      related = Object.values(connections).filter((c) => pid != null && c.pid === pid)
    }

    return (
      <aside className="w-80 shrink-0 overflow-auto border-l border-ns-border bg-ns-panel p-3">
        <div className="mb-2 flex items-center gap-2">
          {node.kind === 'proxy' || node.kind === 'vpn' ? (
            <ShieldCheck className="h-4 w-4 text-ns-purple" />
          ) : node.kind === 'domain' ? (
            <Globe className="h-4 w-4 text-ns-purple" />
          ) : (
            <List className="h-4 w-4 text-ns-accent" />
          )}
          <div className="text-sm font-semibold text-ns-text">{node.label}</div>
        </div>
        <div className="space-y-1.5">
          <KV k="类型" v={NODE_KIND_LABEL[node.kind] ?? node.kind} />
          <KV k="状态" v={node.active ? '活跃' : '历史（不活跃）'} />
          <KV k="首见" v={formatDateTime(node.firstSeen)} />
          <KV k="最近" v={formatDateTime(node.lastSeen)} />
        </div>

        {node.kind === 'proxy' && (
          <div className="mt-3 space-y-1.5 rounded border border-ns-border bg-ns-bg p-2">
            <KV k="机制" v={String(data.mechanism ?? '-')} />
            <KV k="协议" v={String(data.protocol ?? '-')} />
            <KV
              k="置信度"
              v={(() => {
                const c = confidenceLabel(String(data.confidence ?? ''))
                return <span className={c.cls}>{c.label}</span>
              })()}
            />
            <KV k="依据" v={String(data.source ?? '-')} />
          </div>
        )}
        {node.kind === 'vpn' && (
          <div className="mt-3 space-y-1.5 rounded border border-ns-border bg-ns-bg p-2">
            <KV k="类别" v={String(data.kind ?? '-')} />
            <KV k="描述" v={String(data.description ?? '-')} />
            <KV k="默认路由" v={data.isDefaultRouteOwner ? '是（出口经此接口）' : '否'} />
            <KV k="IPv4" v={(data.ipv4 as string[] | undefined)?.join(', ') || '-'} />
          </div>
        )}

        <ConnectionsList title="相关连接" list={related} />
        <p className="mt-3 text-[10px] leading-4 text-ns-muted">
          提示：域名/代理等推断关系以黄色虚线与"推断"标签标注，不代表已验证的物理路径。
        </p>
      </aside>
    )
  }

  if (selectedEdgeId) {
    const edge: TopologyEdge | undefined = edges[selectedEdgeId]
    if (!edge) return <aside className="w-72 border-l border-ns-border bg-ns-panel p-3 text-xs text-ns-muted">连接已消失</aside>
    const src = nodes[edge.source]
    const dst = nodes[edge.target]
    const data = (edge.data ?? {}) as Record<string, unknown>
    const proto = data.protocol as string | undefined

    let related: Connection[] = []
    if (edge.kind === 'process_remote_ip' && src?.kind === 'process' && dst?.kind === 'remote_ip') {
      const pid = (src.data as Record<string, unknown> | null)?.pid as number | undefined
      related = Object.values(connections).filter(
        (c) => pid != null && c.pid === pid && c.remote?.ip === dst.label && (!proto || c.protocol === proto),
      )
    }

    const conf = edge.evidence ? confidenceLabel(edge.evidence === 'time_window' ? 'inferred' : edge.evidence === 'dns_only' ? 'speculative' : 'confirmed') : null

    return (
      <aside className="w-80 shrink-0 overflow-auto border-l border-ns-border bg-ns-panel p-3">
        <div className="mb-2 text-sm font-semibold text-ns-text">连接详情</div>
        <div className="space-y-1.5">
          <KV k="从" v={src?.label ?? edge.source} />
          <KV k="到" v={dst?.label ?? edge.target} />
          <KV k="类型" v={edge.kind} />
          <KV k="协议" v={proto ? proto.toUpperCase() : '-'} />
          <KV k="活跃" v={edge.active ? '是' : '否（历史）'} />
          {edge.evidence && <KV k="依据" v={edge.evidence} />}
          {conf && <KV k="置信度" v={<span className={conf.cls}>{conf.label}</span>} />}
          <KV k="关联时间" v={formatTime(edge.correlatedAt)} />
          <KV k="最近活跃" v={formatTime(edge.lastActive)} />
        </div>
        <ConnectionsList title="该链路上的连接" list={related} />
      </aside>
    )
  }

  return (
    <aside className="w-80 shrink-0 border-l border-ns-border bg-ns-panel p-3">
      <div className="text-sm font-semibold text-ns-text">详情</div>
      <p className="mt-2 text-xs leading-5 text-ns-muted">
        点击拓扑中的节点或连接线查看详情。
        <br />
        拖动节点 / 滚轮缩放 / 平移画布。
      </p>
    </aside>
  )
}
